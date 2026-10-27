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
            concurrency: cli.concurrency,
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
        .buffer_unordered(config.concurrency)
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
        probe_downgrade(&host, port, &parsed.scheme, timeout_ms),
    );

    // Cipher enumeration only when --full-scan is requested.
    let cipher_inventory = if config.full_scan {
        Some(enumerate_ciphers(&host, port, &parsed.scheme, timeout_ms).await)
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
            !findings.iter().any(|f| matches!(
                f.kind,
                FindingKind::ClassicalKeyExchangeOnly { .. }
                    | FindingKind::HybridKeyExchangeHrrRequired { .. }
            )),
            "no key-exchange finding expected for clean PQC"
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
