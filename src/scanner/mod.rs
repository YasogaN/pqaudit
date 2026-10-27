use chrono::Utc;
use futures::StreamExt;

use crate::audit::{
    cert_chain::audit_chain,
    compliance::compliance_pair,
    findings::{Finding, FindingKind},
    hndl::{DefaultHndlModel, HndlConfig, HndlModel},
};
use crate::cli::{Cli, ComplianceMode};
use crate::probe::{
    cipher_enum::enumerate_ciphers,
    downgrade::probe_downgrade,
    pqc_probe::{pqc_probe, ProbeConfig},
    starttls::parse_scheme,
};
use crate::{DowngradeResult, ProbeResults, ScanReport, TargetReport, TlsVersion};

/// Top-level scanner configuration derived from the CLI arguments.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub concurrency: usize,
    pub full_scan: bool,
    pub timeout_ms: u64,
    pub sni_override: Option<String>,
    pub q_day_year: u32,
    pub compliance: ComplianceMode,
    pub insecure: bool,
    pub ca_file: Option<std::path::PathBuf>,
    pub extra_roots: Vec<rustls::pki_types::CertificateDer<'static>>,
}

impl From<&Cli> for ScanConfig {
    fn from(cli: &Cli) -> Self {
        Self {
            // `buffer_unordered(0)` would stall forever; treat zero as one.
            concurrency: cli.concurrency.max(1),
            full_scan: cli.full_scan,
            timeout_ms: cli.timeout,
            sni_override: cli.sni.clone(),
            q_day_year: cli.q_day,
            compliance: cli.compliance.clone(),
            insecure: cli.insecure,
            ca_file: cli.ca_file.clone(),
            extra_roots: vec![],
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            concurrency: 10,
            full_scan: false,
            timeout_ms: 5000,
            sni_override: None,
            q_day_year: 2030,
            compliance: ComplianceMode::Nist,
            insecure: false,
            ca_file: None,
            extra_roots: vec![],
        }
    }
}

/// Run a full audit on a list of targets and return the aggregated report.
pub async fn scan(targets: Vec<String>, config: &ScanConfig) -> ScanReport {
    let mut config = config.clone();
    if let Some(path) = &config.ca_file {
        match load_ca_roots(path) {
            Ok(roots) => config.extra_roots.extend(roots),
            Err(error) => {
                let results = targets
                    .into_iter()
                    .map(|target| failed_target(target, &error, &config))
                    .collect();
                return ScanReport {
                    schema_version: "1.0".into(),
                    scanned_at: Utc::now().to_rfc3339(),
                    compliance_mode: config.compliance.clone(),
                    targets: results,
                    comparison: None,
                };
            }
        }
    }

    let config = std::sync::Arc::new(config);

    let results: Vec<TargetReport> = futures::stream::iter(targets)
        .map(|target| {
            let cfg = std::sync::Arc::clone(&config);
            async move { scan_single(target, &cfg).await }
        })
        // `buffered` keeps the input order while still running up to
        // `concurrency` probes at once. Report order must be stable for
        // comparisons, baselines, and human consumption.
        .buffered(config.concurrency)
        .collect()
        .await;

    ScanReport {
        schema_version: "1.0".into(),
        scanned_at: Utc::now().to_rfc3339(),
        compliance_mode: config.compliance.clone(),
        targets: results,
        comparison: None,
    }
}

/// Load trust anchors from a PEM bundle or a single DER certificate.
fn load_ca_roots(
    path: &std::path::Path,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if data.starts_with(b"-----BEGIN") {
        let mut remaining = data.as_slice();
        let mut roots = Vec::new();
        while !remaining.is_empty() {
            match x509_parser::pem::parse_x509_pem(remaining) {
                Ok((rest, block)) => {
                    if block.contents.is_empty() {
                        return Err(format!("{}: empty certificate block", path.display()));
                    }
                    roots.push(rustls::pki_types::CertificateDer::from(block.contents));
                    remaining = rest;
                }
                Err(e) => return Err(format!("{}: {e}", path.display())),
            }
        }
        Ok(roots)
    } else {
        Ok(vec![rustls::pki_types::CertificateDer::from(data)])
    }
}

/// Build a zero-score report for a target that could not be probed at all.
fn failed_target(target: String, error: &str, config: &ScanConfig) -> TargetReport {
    let parsed = parse_scheme(&target);
    let (table, model) = compliance_pair(config.compliance.clone());
    let empty_probe = ProbeResults {
        target: target.clone(),
        port: parsed.port,
        pqc_handshake: Err(error.to_string()),
        cipher_inventory: None,
        downgrade: DowngradeResult::Rejected,
    };
    let score = model.score(&empty_probe, None, table.as_ref());
    let hndl = DefaultHndlModel.assess(
        &empty_probe,
        &HndlConfig {
            q_day_year: config.q_day_year,
            current_year: Utc::now().year_unsigned(),
            cert_expiry_year: None,
        },
    );
    TargetReport {
        target,
        port: parsed.port,
        score,
        hndl,
        findings: vec![],
        cert_chain: None,
        cipher_inventory: None,
        downgrade: DowngradeResult::Rejected,
        error: Some(error.to_string()),
        negotiated_group: None,
        negotiated_suite: None,
        classical_fallback: false,
        legacy_protocols: vec![],
    }
}

/// Scan a single target end-to-end: probe → audit → score → report.
async fn scan_single(target: String, config: &ScanConfig) -> TargetReport {
    let parsed = parse_scheme(&target);
    let host = parsed.host.clone();
    let port = parsed.port;
    let sni = config.sni_override.as_deref().unwrap_or(&host).to_string();
    let timeout_ms = config.timeout_ms;

    let probe_cfg = ProbeConfig {
        timeout_ms,
        sni_override: config.sni_override.clone(),
        scheme: parsed.scheme.clone(),
        insecure: config.insecure,
        extra_roots: config.extra_roots.clone(),
    };

    // Run PQC probe and downgrade probe concurrently.
    let (pqc_result, downgrade) = tokio::join!(
        pqc_probe(&host, port, Some(&sni), &probe_cfg),
        probe_downgrade(&host, port, &sni, &parsed.scheme, timeout_ms),
    );

    // Cipher enumeration only when --full-scan is requested.
    let cipher_inventory = if config.full_scan {
        Some(enumerate_ciphers(&host, port, &sni, &parsed.scheme, timeout_ms).await)
    } else {
        None
    };

    match pqc_result {
        Err(e) => {
            // Probe failed — return a minimal error report with zero score.
            let (table, model) = compliance_pair(config.compliance.clone());
            let empty_probe = ProbeResults {
                target: target.clone(),
                port,
                pqc_handshake: Err(e.to_string()),
                cipher_inventory: cipher_inventory.clone(),
                downgrade: downgrade.clone(),
            };
            let score = model.score(&empty_probe, None, table.as_ref());
            let hndl = DefaultHndlModel.assess(
                &empty_probe,
                &HndlConfig {
                    q_day_year: config.q_day_year,
                    current_year: Utc::now().year_unsigned(),
                    cert_expiry_year: None,
                },
            );
            TargetReport {
                target,
                port,
                score,
                hndl,
                findings: vec![],
                cert_chain: None,
                cipher_inventory,
                downgrade,
                error: Some(e.to_string()),
                negotiated_group: None,
                negotiated_suite: None,
                classical_fallback: false,
                legacy_protocols: vec![],
            }
        }
        Ok(pqc) => {
            let (table, model) = compliance_pair(config.compliance.clone());
            let current_year = Utc::now().year_unsigned();

            // Audit the certificate chain against the active compliance table.
            let cert_chain = audit_chain(&pqc.cert_chain_der, table.as_ref(), current_year);
            let cert_expiry_year = cert_chain.entries.first().map(|e| e.expiry_year);

            // Assemble ProbeResults for scoring and HNDL.
            let probe_results = ProbeResults {
                target: target.clone(),
                port,
                pqc_handshake: Ok(pqc.clone()),
                cipher_inventory: cipher_inventory.clone(),
                downgrade: downgrade.clone(),
            };

            let score = model.score(&probe_results, Some(&cert_chain), table.as_ref());

            let hndl = DefaultHndlModel.assess(
                &probe_results,
                &HndlConfig {
                    q_day_year: config.q_day_year,
                    current_year: Utc::now().year_unsigned(),
                    cert_expiry_year,
                },
            );

            let findings = generate_findings(&probe_results, &cert_chain, model.as_ref());

            TargetReport {
                target,
                port,
                score,
                hndl,
                findings,
                cert_chain: Some(cert_chain),
                cipher_inventory,
                downgrade,
                error: None,
                negotiated_group: Some(pqc.negotiated_group),
                negotiated_suite: Some(pqc.negotiated_suite),
                classical_fallback: pqc.classical_fallback,
                legacy_protocols: pqc.legacy_protocols.clone(),
            }
        }
    }
}

/// Generate audit findings from probe results using the active scoring model for severities.
///
/// `cert_chain` is the already-audited chain report from the same probe, passed in to avoid
/// a redundant `audit_chain` call.
fn generate_findings(
    probe: &ProbeResults,
    cert_chain: &crate::audit::cert_chain::CertChainReport,
    model: &dyn crate::audit::scoring::model::ScoringModel,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Ok(pqc) = &probe.pqc_handshake {
        let group = &pqc.negotiated_group;

        // Key exchange findings
        if group.code_point == 0x6399 {
            let kind = FindingKind::DeprecatedPqcDraftCodepoint { code_point: 0x6399 };
            findings.push(Finding {
                severity: model.severity(&kind),
                kind,
            });
        } else if !group.is_pqc {
            let kind = FindingKind::ClassicalKeyExchangeOnly {
                group: group.clone(),
            };
            findings.push(Finding {
                severity: model.severity(&kind),
                kind,
            });
        } else if pqc.hrr_required {
            let kind = FindingKind::HybridKeyExchangeHrrRequired {
                group: group.clone(),
            };
            findings.push(Finding {
                severity: model.severity(&kind),
                kind,
            });
        }

        // TLS version
        if pqc.negotiated_version != TlsVersion::Tls13 {
            let kind = FindingKind::TlsVersionInsufficient {
                max_version: pqc.negotiated_version.clone(),
            };
            findings.push(Finding {
                severity: model.severity(&kind),
                kind,
            });
        }

        // Classical fallback: PQC is available but not enforced.
        if pqc.classical_fallback {
            let kind = FindingKind::ClassicalFallbackAccepted;
            findings.push(Finding {
                severity: model.severity(&kind),
                kind,
            });
        }

        // Legacy protocol versions accepted by the server.
        for version in &pqc.legacy_protocols {
            let kind = FindingKind::LegacyTlsProtocol {
                version: version.clone(),
            };
            findings.push(Finding {
                severity: model.severity(&kind),
                kind,
            });
        }

        // Certificate validation was not possible; the chain was captured insecurely.
        if let Some(reason) = &pqc.certificate_validation_error {
            let kind = FindingKind::CertificateValidationFailed {
                reason: reason.clone(),
            };
            findings.push(Finding {
                severity: model.severity(&kind),
                kind,
            });
        }

        // Weak cipher suites from inventory
        if let Some(inv) = &probe.cipher_inventory {
            for suite in inv.tls12_suites.iter().chain(inv.tls13_suites.iter()) {
                if crate::audit::tables::iana_ciphers::is_weak_cipher(suite.id) {
                    let kind = FindingKind::WeakSymmetricCipher {
                        suite: suite.clone(),
                    };
                    findings.push(Finding {
                        severity: model.severity(&kind),
                        kind,
                    });
                }
            }
        }

        // Cert chain findings — re-stamp severity with the active compliance model.
        for f in &cert_chain.findings {
            findings.push(Finding {
                severity: model.severity(&f.kind),
                kind: f.kind.clone(),
            });
        }
    }

    // Downgrade findings
    if matches!(probe.downgrade, DowngradeResult::Accepted { .. }) {
        let kind = FindingKind::DowngradeAccepted;
        findings.push(Finding {
            severity: model.severity(&kind),
            kind,
        });
    }

    findings
}

/// Extension trait for chrono Year from UTC
trait UtcYearExt {
    fn year_unsigned(self) -> u32;
}
impl UtcYearExt for chrono::DateTime<chrono::Utc> {
    fn year_unsigned(self) -> u32 {
        use chrono::Datelike;
        self.year() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::compliance::compliance_pair;
    use crate::{CipherSuite, NamedGroup, PqcHandshakeResult, TlsVersion};

    fn make_probe(group_is_pqc: bool, hrr: bool, downgrade: DowngradeResult) -> ProbeResults {
        ProbeResults {
            target: "example.com".into(),
            port: 443,
            pqc_handshake: Ok(PqcHandshakeResult {
                negotiated_version: TlsVersion::Tls13,
                negotiated_suite: CipherSuite {
                    id: 0x1302,
                    name: "TLS_AES_256_GCM_SHA384".into(),
                },
                negotiated_group: NamedGroup {
                    code_point: if group_is_pqc { 0x11EC } else { 0x001D },
                    name: if group_is_pqc {
                        "X25519MLKEM768"
                    } else {
                        "x25519"
                    }
                    .into(),
                    is_pqc: group_is_pqc,
                },
                hrr_required: hrr,
                cert_chain_der: vec![],
                classical_fallback: false,
                legacy_protocols: vec![],
                certificate_validation_error: None,
            }),
            cipher_inventory: None,
            downgrade,
        }
    }

    #[test]
    fn classical_group_generates_finding() {
        let probe = make_probe(false, false, DowngradeResult::Rejected);
        let (_table, model) = compliance_pair(ComplianceMode::Nist);
        let empty_chain = crate::audit::cert_chain::CertChainReport {
            entries: vec![],
            findings: vec![],
        };
        let findings = generate_findings(&probe, &empty_chain, model.as_ref());
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.kind, FindingKind::ClassicalKeyExchangeOnly { .. })),
            "expected ClassicalKeyExchangeOnly finding"
        );
    }

    #[test]
    fn pqc_group_no_hrr_generates_no_key_exchange_finding() {
        let probe = make_probe(true, false, DowngradeResult::Rejected);
        let (_table, model) = compliance_pair(ComplianceMode::Nist);
        let empty_chain = crate::audit::cert_chain::CertChainReport {
            entries: vec![],
            findings: vec![],
        };
        let findings = generate_findings(&probe, &empty_chain, model.as_ref());
        assert!(
            findings.is_empty(),
            "no findings expected for clean PQC, got {findings:?}"
        );
    }

    #[test]
    fn hrr_generates_finding() {
        let probe = make_probe(true, true, DowngradeResult::Rejected);
        let (_table, model) = compliance_pair(ComplianceMode::Nist);
        let empty_chain = crate::audit::cert_chain::CertChainReport {
            entries: vec![],
            findings: vec![],
        };
        let findings = generate_findings(&probe, &empty_chain, model.as_ref());
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.kind, FindingKind::HybridKeyExchangeHrrRequired { .. })),
            "expected HybridKeyExchangeHrrRequired finding"
        );
    }

    #[test]
    fn downgrade_accepted_generates_finding() {
        let probe = make_probe(
            true,
            false,
            DowngradeResult::Accepted {
                negotiated_version: TlsVersion::Tls12,
            },
        );
        let (_table, model) = compliance_pair(ComplianceMode::Nist);
        let empty_chain = crate::audit::cert_chain::CertChainReport {
            entries: vec![],
            findings: vec![],
        };
        let findings = generate_findings(&probe, &empty_chain, model.as_ref());
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.kind, FindingKind::DowngradeAccepted)),
            "expected DowngradeAccepted finding"
        );
    }

    #[test]
    fn scan_config_default_is_sane() {
        let cfg = ScanConfig::default();
        assert_eq!(cfg.concurrency, 10);
        assert_eq!(cfg.timeout_ms, 5000);
        assert_eq!(cfg.q_day_year, 2030);
        assert!(!cfg.full_scan);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::audit::findings::FindingKind;
    use crate::test_support::{
        classical_provider, smtp_starttls_server, test_ca_and_leaf, tls_server,
        tls_server_with_identity,
    };
    use crate::{CipherSuite, NamedGroup, PqcHandshakeResult, ProbeResults};
    use rustls::crypto::aws_lc_rs;

    fn insecure_config() -> ScanConfig {
        ScanConfig {
            timeout_ms: 2000,
            insecure: true,
            concurrency: 1,
            ..ScanConfig::default()
        }
    }

    fn target(addr: &crate::test_support::TestServer) -> String {
        format!("127.0.0.1:{}", addr.port())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scan_pqc_server_reports_pqc_and_fallback() {
        let server = tls_server(
            aws_lc_rs::default_provider(),
            &[&rustls::version::TLS13, &rustls::version::TLS12],
        )
        .await;
        let report = scan(vec![target(&server)], &insecure_config()).await;
        let t = &report.targets[0];
        assert!(t.error.is_none(), "unexpected error: {:?}", t.error);
        assert!(t.score.total > 0);
        assert!(t.negotiated_group.as_ref().unwrap().is_pqc);
        assert!(t.classical_fallback);
        assert!(!t.cert_chain.as_ref().unwrap().entries.is_empty());
        assert!(t
            .findings
            .iter()
            .any(|f| matches!(f.kind, FindingKind::ClassicalFallbackAccepted)));
        assert!(!t
            .findings
            .iter()
            .any(|f| matches!(f.kind, FindingKind::ClassicalKeyExchangeOnly { .. })));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scan_classical_server_reports_classical_key_exchange() {
        let server = tls_server(
            classical_provider(),
            &[&rustls::version::TLS13, &rustls::version::TLS12],
        )
        .await;
        let report = scan(vec![target(&server)], &insecure_config()).await;
        let t = &report.targets[0];
        assert!(!t.negotiated_group.as_ref().unwrap().is_pqc);
        assert!(t
            .findings
            .iter()
            .any(|f| matches!(f.kind, FindingKind::ClassicalKeyExchangeOnly { .. })));
        assert!(t
            .findings
            .iter()
            .any(|f| matches!(f.kind, FindingKind::ClassicalFallbackAccepted)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scan_probe_failure_produces_error_report() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let report = scan(vec![format!("127.0.0.1:{port}")], &insecure_config()).await;
        let t = &report.targets[0];
        assert!(t.error.is_some());
        assert_eq!(t.score.total, 0);
        assert!(t.cert_chain.is_none());
        assert!(t.negotiated_group.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scan_full_scan_populates_cipher_inventory() {
        let server = tls_server(
            aws_lc_rs::default_provider(),
            &[&rustls::version::TLS13, &rustls::version::TLS12],
        )
        .await;
        let mut cfg = insecure_config();
        cfg.full_scan = true;
        let report = scan(vec![target(&server)], &cfg).await;
        let inv = report.targets[0]
            .cipher_inventory
            .as_ref()
            .expect("inventory");
        assert!(!inv.tls13_suites.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scan_starttls_target_succeeds() {
        let server = smtp_starttls_server(aws_lc_rs::default_provider()).await;
        let report = scan(
            vec![format!("smtp://127.0.0.1:{}", server.port())],
            &insecure_config(),
        )
        .await;
        assert!(report.targets[0].error.is_none());
        assert!(report.targets[0].negotiated_group.as_ref().unwrap().is_pqc);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scan_ca_file_der_is_used_as_trust_anchor() {
        let (chain, key, root) = test_ca_and_leaf();
        let server = tls_server_with_identity(
            aws_lc_rs::default_provider(),
            &[&rustls::version::TLS13],
            chain,
            key,
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.der");
        std::fs::write(&path, root.as_ref()).unwrap();
        let mut cfg = insecure_config();
        cfg.insecure = false;
        cfg.sni_override = Some("localhost".into());
        cfg.ca_file = Some(path);
        let report = scan(vec![target(&server)], &cfg).await;
        let t = &report.targets[0];
        assert!(t.error.is_none(), "unexpected error: {:?}", t.error);
        assert!(!t
            .findings
            .iter()
            .any(|f| matches!(f.kind, FindingKind::CertificateValidationFailed { .. })));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scan_ca_file_pem_bundle_loads_multiple_roots() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/certs/classical-chain.pem"
            ),
            &path,
        )
        .unwrap();
        let roots = load_ca_roots(&path).unwrap();
        assert_eq!(roots.len(), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scan_ca_file_errors_are_reported_per_target() {
        let mut cfg = insecure_config();
        cfg.ca_file = Some("/nonexistent/pqaudit-ca.pem".into());
        let report = scan(vec!["example.com:443".into()], &cfg).await;
        assert!(report.targets[0].error.is_some());
        assert!(report.targets[0].error.as_ref().unwrap().contains("ca.pem"));
    }

    #[test]
    fn load_ca_roots_rejects_empty_and_invalid_pem() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.pem");
        std::fs::write(
            &empty,
            b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(load_ca_roots(&empty).is_err());

        let invalid = dir.path().join("invalid.pem");
        std::fs::write(&invalid, b"-----BEGIN CERTIFICATE-----\nnot base64\n").unwrap();
        assert!(load_ca_roots(&invalid).is_err());

        let missing = dir.path().join("missing.pem");
        assert!(load_ca_roots(&missing).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scan_preserves_input_order_even_when_targets_finish_out_of_order() {
        use crate::test_support::silent_server;
        let slow = silent_server().await;
        let fast = tls_server(aws_lc_rs::default_provider(), &[&rustls::version::TLS13]).await;
        let mut cfg = insecure_config();
        cfg.timeout_ms = 100;
        cfg.concurrency = 2;
        let report = scan(
            vec![
                format!("127.0.0.1:{}", slow.port()),
                format!("127.0.0.1:{}", fast.port()),
            ],
            &cfg,
        )
        .await;
        assert_eq!(report.targets.len(), 2);
        assert_eq!(report.targets[0].port, slow.port());
        assert!(report.targets[0].error.is_some());
        assert_eq!(report.targets[1].port, fast.port());
        assert!(report.targets[1].error.is_none());
    }

    #[test]
    fn scan_config_clamps_zero_concurrency() {
        use crate::cli::Cli;
        use clap::Parser;
        let cli = Cli::try_parse_from(["pqaudit", "--concurrency", "0", "example.com"]).unwrap();
        assert_eq!(ScanConfig::from(&cli).concurrency, 1);
    }

    #[test]
    fn scan_config_from_cli_copies_flags() {
        use crate::cli::Cli;
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "pqaudit",
            "--insecure",
            "--ca-file",
            "ca.pem",
            "--concurrency",
            "3",
            "--full-scan",
            "--timeout",
            "1234",
            "--q-day",
            "2032",
            "--compliance",
            "cnsa2",
            "example.com",
        ])
        .unwrap();
        let cfg = ScanConfig::from(&cli);
        assert!(cfg.insecure);
        assert_eq!(cfg.ca_file.as_deref(), Some(std::path::Path::new("ca.pem")));
        assert_eq!(cfg.concurrency, 3);
        assert!(cfg.full_scan);
        assert_eq!(cfg.timeout_ms, 1234);
        assert_eq!(cfg.q_day_year, 2032);
        assert_eq!(cfg.compliance, ComplianceMode::Cnsa2);
    }

    fn probe_with(
        group: u16,
        hrr: bool,
        fallback: bool,
        legacy: Vec<TlsVersion>,
        cert_error: Option<String>,
        downgrade: DowngradeResult,
    ) -> ProbeResults {
        ProbeResults {
            target: "example.com".into(),
            port: 443,
            pqc_handshake: Ok(PqcHandshakeResult {
                negotiated_version: TlsVersion::Tls13,
                negotiated_suite: CipherSuite {
                    id: 0x1302,
                    name: "TLS_AES_256_GCM_SHA384".into(),
                },
                negotiated_group: NamedGroup {
                    code_point: group,
                    name: format!("group-{group:04x}"),
                    is_pqc: group != 0x001D,
                },
                hrr_required: hrr,
                cert_chain_der: vec![],
                classical_fallback: fallback,
                legacy_protocols: legacy,
                certificate_validation_error: cert_error,
            }),
            cipher_inventory: Some(crate::CipherInventory {
                tls13_suites: vec![],
                tls12_suites: vec![CipherSuite {
                    id: 0x000A,
                    name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA".into(),
                }],
                kyber_draft_accepted: false,
            }),
            downgrade,
        }
    }

    #[test]
    fn generate_findings_handles_failed_handshake() {
        use crate::audit::cert_chain::CertChainReport;
        let (_table, model) = compliance_pair(ComplianceMode::Nist);
        let chain = CertChainReport {
            entries: vec![],
            findings: vec![],
        };
        let probe = ProbeResults {
            target: "example.com".into(),
            port: 443,
            pqc_handshake: Err("connection refused".into()),
            cipher_inventory: None,
            downgrade: DowngradeResult::Rejected,
        };
        assert!(generate_findings(&probe, &chain, model.as_ref()).is_empty());
    }

    #[test]
    fn generate_findings_covers_all_probe_signals() {
        use crate::audit::cert_chain::CertChainReport;
        let (_table, model) = compliance_pair(ComplianceMode::Nist);
        let chain = CertChainReport {
            entries: vec![],
            findings: vec![],
        };

        let probe = probe_with(
            0x6399,
            false,
            true,
            vec![TlsVersion::Tls10],
            Some("untrusted issuer".into()),
            DowngradeResult::Accepted {
                negotiated_version: TlsVersion::Tls12,
            },
        );
        let kinds: Vec<FindingKind> = generate_findings(&probe, &chain, model.as_ref())
            .into_iter()
            .map(|f| f.kind)
            .collect();
        assert!(kinds
            .iter()
            .any(|k| matches!(k, FindingKind::DeprecatedPqcDraftCodepoint { .. })));
        assert!(kinds
            .iter()
            .any(|k| matches!(k, FindingKind::ClassicalFallbackAccepted)));
        assert!(kinds
            .iter()
            .any(|k| matches!(k, FindingKind::LegacyTlsProtocol { .. })));
        assert!(kinds
            .iter()
            .any(|k| matches!(k, FindingKind::CertificateValidationFailed { .. })));
        assert!(kinds
            .iter()
            .any(|k| matches!(k, FindingKind::WeakSymmetricCipher { .. })));
        assert!(kinds
            .iter()
            .any(|k| matches!(k, FindingKind::DowngradeAccepted)));

        let probe = probe_with(0x11EC, true, false, vec![], None, DowngradeResult::Rejected);
        let kinds: Vec<FindingKind> = generate_findings(&probe, &chain, model.as_ref())
            .into_iter()
            .map(|f| f.kind)
            .collect();
        assert!(kinds
            .iter()
            .any(|k| matches!(k, FindingKind::HybridKeyExchangeHrrRequired { .. })));

        let mut probe = probe_with(
            0x001D,
            false,
            false,
            vec![],
            None,
            DowngradeResult::Rejected,
        );
        if let Ok(hs) = &mut probe.pqc_handshake {
            hs.negotiated_version = TlsVersion::Tls12;
        }
        let kinds: Vec<FindingKind> = generate_findings(&probe, &chain, model.as_ref())
            .into_iter()
            .map(|f| f.kind)
            .collect();
        assert!(kinds
            .iter()
            .any(|k| matches!(k, FindingKind::TlsVersionInsufficient { .. })));
    }
}
