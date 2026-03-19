use futures::StreamExt;
use chrono::Utc;

use crate::{
    DowngradeResult, ProbeResults, ScanReport, TargetReport, TlsVersion,
};
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
    pqc_probe::{ProbeConfig, pqc_probe},
    starttls::parse_scheme,
};

/// Top-level scanner configuration derived from the CLI arguments.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub concurrency: usize,
    pub full_scan: bool,
    pub timeout_ms: u64,
    pub sni_override: Option<String>,
    pub q_day_year: u32,
    pub compliance: ComplianceMode,
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
        }
    }
}

/// Run a full audit on a list of targets and return the aggregated report.
pub async fn scan(targets: Vec<String>, config: &ScanConfig) -> ScanReport {
    let config = std::sync::Arc::new(config.clone());

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

/// Scan a single target end-to-end: probe → audit → score → report.
async fn scan_single(target: String, config: &ScanConfig) -> TargetReport {
    let parsed = parse_scheme(&target);
    let host = parsed.host.clone();
    let port = parsed.port;
    let sni = config.sni_override.as_deref().unwrap_or(&host).to_string();
    let timeout_ms = config.timeout_ms;

    let probe_cfg = ProbeConfig { timeout_ms, sni_override: config.sni_override.clone() };

    // Run PQC probe and downgrade probe concurrently.
    let (pqc_result, downgrade) = tokio::join!(
        pqc_probe(&host, port, Some(&sni), &probe_cfg),
        probe_downgrade(&host, port, timeout_ms),
    );

    // Cipher enumeration only when --full-scan is requested.
    let cipher_inventory = if config.full_scan {
        Some(enumerate_ciphers(&host, port, timeout_ms).await)
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
            let score = model.score(&empty_probe, table.as_ref());
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
            }
        }
        Ok(pqc) => {
            // Audit the certificate chain.
            let cert_chain = audit_chain(&pqc.cert_chain_der);
            let cert_expiry_year = cert_chain.entries.first().map(|e| e.expiry_year);

            // Assemble ProbeResults for scoring and HNDL.
            let probe_results = ProbeResults {
                target: target.clone(),
                port,
                pqc_handshake: Ok(pqc.clone()),
                cipher_inventory: cipher_inventory.clone(),
                downgrade: downgrade.clone(),
            };

            let (table, model) = compliance_pair(config.compliance.clone());
            let score = model.score(&probe_results, table.as_ref());

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
            findings.push(Finding { severity: model.severity(&kind), kind });
        } else if !group.is_pqc {
            let kind = FindingKind::ClassicalKeyExchangeOnly { group: group.clone() };
            findings.push(Finding { severity: model.severity(&kind), kind });
        } else if pqc.hrr_required {
            let kind = FindingKind::HybridKeyExchangeHrrRequired { group: group.clone() };
            findings.push(Finding { severity: model.severity(&kind), kind });
        }

        // TLS version
        if pqc.negotiated_version != TlsVersion::Tls13 {
            let kind = FindingKind::TlsVersionInsufficient {
                max_version: pqc.negotiated_version.clone(),
            };
            findings.push(Finding { severity: model.severity(&kind), kind });
        }

        // Weak cipher suites from inventory
        if let Some(inv) = &probe.cipher_inventory {
            for suite in inv.tls12_suites.iter().chain(inv.tls13_suites.iter()) {
                if is_weak_cipher(suite.id) {
                    let kind = FindingKind::WeakSymmetricCipher { suite: suite.clone() };
                    findings.push(Finding { severity: model.severity(&kind), kind });
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
        findings.push(Finding { severity: model.severity(&kind), kind });
    }

    findings
}

/// Returns true for cipher suite IDs considered weak or deprecated.
fn is_weak_cipher(id: u16) -> bool {
    matches!(
        id,
        0x000A        // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        | 0x0000..=0x0003  // NULL / export ciphers
        | 0x0004 | 0x0005  // RC4-MD5 / RC4-SHA
    )
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
    use crate::{NamedGroup, PqcHandshakeResult, TlsVersion, CipherSuite};
    use crate::audit::compliance::compliance_pair;

    fn make_probe(group_is_pqc: bool, hrr: bool, downgrade: DowngradeResult) -> ProbeResults {
        ProbeResults {
            target: "example.com".into(),
            port: 443,
            pqc_handshake: Ok(PqcHandshakeResult {
                negotiated_version: TlsVersion::Tls13,
                negotiated_suite: CipherSuite { id: 0x1302, name: "TLS_AES_256_GCM_SHA384".into() },
                negotiated_group: NamedGroup {
                    code_point: if group_is_pqc { 0x11EC } else { 0x001D },
                    name: if group_is_pqc { "X25519MLKEM768" } else { "x25519" }.into(),
                    is_pqc: group_is_pqc,
                },
                hrr_required: hrr,
                cert_chain_der: vec![],
            }),
            cipher_inventory: None,
            downgrade,
        }
    }

    #[test]
    fn classical_group_generates_finding() {
        let probe = make_probe(false, false, DowngradeResult::Rejected);
        let (_table, model) = compliance_pair(ComplianceMode::Nist);
        let empty_chain = crate::audit::cert_chain::CertChainReport { entries: vec![], findings: vec![] };
        let findings = generate_findings(&probe, &empty_chain, model.as_ref());
        assert!(
            findings.iter().any(|f| matches!(f.kind, FindingKind::ClassicalKeyExchangeOnly { .. })),
            "expected ClassicalKeyExchangeOnly finding"
        );
    }

    #[test]
    fn pqc_group_no_hrr_generates_no_key_exchange_finding() {
        let probe = make_probe(true, false, DowngradeResult::Rejected);
        let (_table, model) = compliance_pair(ComplianceMode::Nist);
        let empty_chain = crate::audit::cert_chain::CertChainReport { entries: vec![], findings: vec![] };
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
        let empty_chain = crate::audit::cert_chain::CertChainReport { entries: vec![], findings: vec![] };
        let findings = generate_findings(&probe, &empty_chain, model.as_ref());
        assert!(
            findings.iter().any(|f| matches!(f.kind, FindingKind::HybridKeyExchangeHrrRequired { .. })),
            "expected HybridKeyExchangeHrrRequired finding"
        );
    }

    #[test]
    fn downgrade_accepted_generates_finding() {
        let probe = make_probe(true, false, DowngradeResult::Accepted {
            negotiated_version: TlsVersion::Tls12,
        });
        let (_table, model) = compliance_pair(ComplianceMode::Nist);
        let empty_chain = crate::audit::cert_chain::CertChainReport { entries: vec![], findings: vec![] };
        let findings = generate_findings(&probe, &empty_chain, model.as_ref());
        assert!(
            findings.iter().any(|f| matches!(f.kind, FindingKind::DowngradeAccepted)),
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
