use crate::audit::findings::{Finding, FindingKind, Severity};
use crate::audit::tables::DeadlineTable;
use crate::{AlgorithmId, ChainPosition, KeyInfo};
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertEntry {
    pub position: ChainPosition,
    pub key: KeyInfo,
    pub expiry_year: u32,
    pub not_after: NaiveDate,
    pub subject: String,
    pub algorithm: AlgorithmId,
    pub signature_algorithm: String,
    pub self_signed: bool,
    pub expired: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertChainReport {
    pub entries: Vec<CertEntry>,
    pub findings: Vec<Finding>,
}

// ── OID helpers ──────────────────────────────────────────────────────────────

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_DSA: &str = "1.2.840.10040.4.1";
const OID_ED25519: &str = "1.3.101.112";
const OID_ED448: &str = "1.3.101.113";

const OID_ML_KEM_512: &str = "2.16.840.1.101.3.4.4.1";
const OID_ML_KEM_768: &str = "2.16.840.1.101.3.4.4.2";
const OID_ML_KEM_1024: &str = "2.16.840.1.101.3.4.4.3";

const OID_ML_DSA_44: &str = "2.16.840.1.101.3.4.3.17";
const OID_ML_DSA_65: &str = "2.16.840.1.101.3.4.3.18";
const OID_ML_DSA_87: &str = "2.16.840.1.101.3.4.3.19";

fn curve_name(oid: &str) -> Option<&'static str> {
    match oid {
        "1.2.840.10045.3.1.7" => Some("P-256"),
        "1.3.132.0.34" => Some("P-384"),
        "1.3.132.0.35" => Some("P-521"),
        "1.3.132.0.10" => Some("secp256k1"),
        "1.3.132.0.33" => Some("P-224"),
        _ => None,
    }
}

fn ec_curve_oid(spki: &SubjectPublicKeyInfo) -> String {
    spki.algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .map(|o| o.to_id_string())
        .unwrap_or_default()
}

fn slh_dsa_level(oid: &str) -> Option<u8> {
    // 2.16.840.1.101.3.4.3.20 .. .31 map to 128/192/256-bit parameter sets.
    let suffix: u8 = oid.rsplit('.').next()?.parse().ok()?;
    match suffix {
        20..=21 | 26..=27 => Some(1),
        22..=23 | 28..=29 => Some(3),
        24..=25 | 30..=31 => Some(5),
        _ => None,
    }
}

/// Parse a `KeyInfo` from x509-parser's `SubjectPublicKeyInfo`.
pub fn parse_key_info(spki: &SubjectPublicKeyInfo) -> KeyInfo {
    let alg_oid = spki.algorithm.algorithm.to_id_string();
    match alg_oid.as_str() {
        OID_RSA => {
            let bits = spki.parsed().ok().map(|k| k.key_size() as u32).unwrap_or(0);
            KeyInfo::Rsa { bits }
        }
        OID_EC => {
            let oid = ec_curve_oid(spki);
            KeyInfo::Ec {
                curve: curve_name(&oid)
                    .map(str::to_string)
                    .unwrap_or_else(|| oid.clone()),
            }
        }
        OID_DSA => KeyInfo::Dsa {
            bits: spki.parsed().ok().map(|k| k.key_size() as u32).unwrap_or(0),
        },
        OID_ED25519 => KeyInfo::Ed25519,
        OID_ED448 => KeyInfo::Ed448,
        OID_ML_KEM_512 => KeyInfo::MlKem { level: 512 },
        OID_ML_KEM_768 => KeyInfo::MlKem { level: 768 },
        OID_ML_KEM_1024 => KeyInfo::MlKem { level: 1024 },
        OID_ML_DSA_44 => KeyInfo::MlDsa { level: 44 },
        OID_ML_DSA_65 => KeyInfo::MlDsa { level: 65 },
        OID_ML_DSA_87 => KeyInfo::MlDsa { level: 87 },
        oid if slh_dsa_level(oid).is_some() => KeyInfo::SlhDsa {
            level: slh_dsa_level(oid).unwrap_or(1),
        },
        _ => KeyInfo::Unknown,
    }
}

/// Returns `None` for unrecognized OIDs so callers never fabricate findings for unknown algorithms.
pub fn parse_algorithm_id(spki: &SubjectPublicKeyInfo) -> Option<AlgorithmId> {
    let oid = spki.algorithm.algorithm.to_id_string();
    match oid.as_str() {
        OID_RSA => {
            let min_bits = spki.parsed().ok().map(|k| k.key_size() as u32).unwrap_or(0);
            Some(AlgorithmId::Rsa { min_bits })
        }
        OID_EC => match curve_name(&ec_curve_oid(spki)) {
            Some("P-256") => Some(AlgorithmId::EcP256),
            Some("P-384") => Some(AlgorithmId::EcP384),
            Some("P-521") => Some(AlgorithmId::EcP521),
            // Unknown curves and explicit-parameter EC keys are still
            // quantum-vulnerable; classify them conservatively.
            _ => Some(AlgorithmId::EcOther),
        },
        OID_DSA => Some(AlgorithmId::Dsa {
            min_bits: spki.parsed().ok().map(|k| k.key_size() as u32).unwrap_or(0),
        }),
        OID_ED25519 => Some(AlgorithmId::Ed25519),
        OID_ED448 => Some(AlgorithmId::Ed448),
        OID_ML_KEM_512 => Some(AlgorithmId::MlKem512),
        OID_ML_KEM_768 => Some(AlgorithmId::MlKem768),
        OID_ML_KEM_1024 => Some(AlgorithmId::MlKem1024),
        OID_ML_DSA_44 => Some(AlgorithmId::MlDsa44),
        OID_ML_DSA_65 => Some(AlgorithmId::MlDsa65),
        OID_ML_DSA_87 => Some(AlgorithmId::MlDsa87),
        oid if slh_dsa_level(oid).is_some() => Some(AlgorithmId::SlhDsa {
            level: slh_dsa_level(oid).unwrap_or(1),
        }),
        _ => None,
    }
}

/// Human-readable X.509 signature algorithm name.
pub fn signature_algorithm_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption".into(),
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption".into(),
        "1.2.840.113549.1.1.10" => "RSASSA-PSS".into(),
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption".into(),
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption".into(),
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption".into(),
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1".into(),
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256".into(),
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384".into(),
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512".into(),
        "1.2.840.10040.4.3" => "dsa-with-SHA1".into(),
        "2.16.840.1.101.3.4.3.1" => "dsa-with-SHA224".into(),
        "2.16.840.1.101.3.4.3.2" => "dsa-with-SHA256".into(),
        "2.16.840.1.101.3.4.3.3" => "dsa-with-SHA384".into(),
        "2.16.840.1.101.3.4.3.4" => "dsa-with-SHA512".into(),
        OID_ED25519 => "Ed25519".into(),
        OID_ED448 => "Ed448".into(),
        OID_ML_DSA_44 => "ML-DSA-44".into(),
        OID_ML_DSA_65 => "ML-DSA-65".into(),
        OID_ML_DSA_87 => "ML-DSA-87".into(),
        oid if slh_dsa_level(oid).is_some() => {
            format!("SLH-DSA (level {})", slh_dsa_level(oid).unwrap_or(1))
        }
        other => format!("Unknown({other})"),
    }
}

/// True for MD5/SHA-1 based signature algorithms, which are deprecated for
/// certificate signing.
pub fn is_weak_signature(oid: &str) -> bool {
    matches!(
        oid,
        "1.2.840.113549.1.1.4" | "1.2.840.113549.1.1.5" | "1.2.840.10045.4.1" | "1.2.840.10040.4.3"
    )
}

fn position_for(depth: usize, total: usize) -> ChainPosition {
    if depth == 0 {
        ChainPosition::Leaf
    } else if depth == total - 1 {
        ChainPosition::Root
    } else {
        ChainPosition::Intermediate { depth: depth as u8 }
    }
}

/// Audit a DER-encoded certificate chain.
/// `chain_der` is a slice of DER blobs, one per certificate.
/// The first entry is the leaf; last is the root (or closest to root).
pub fn audit_chain(
    chain_der: &[Vec<u8>],
    table: &dyn DeadlineTable,
    current_year: u32,
) -> CertChainReport {
    if chain_der.is_empty() {
        return CertChainReport {
            entries: vec![],
            findings: vec![],
        };
    }

    let now = Utc::now().date_naive();
    let mut entries = Vec::new();
    let mut findings = Vec::new();
    let total = chain_der.len();

    for (depth, der) in chain_der.iter().enumerate() {
        let position = position_for(depth, total);

        let cert = match X509Certificate::from_der(der) {
            Ok((_, c)) => c,
            Err(_) => {
                findings.push(Finding {
                    kind: FindingKind::UnparseableCertificate { depth },
                    severity: Severity::Error,
                });
                continue;
            }
        };

        let spki = cert.public_key();
        let key = parse_key_info(spki);
        let alg_id = parse_algorithm_id(spki).unwrap_or(AlgorithmId::Unknown);
        let not_after = cert.validity().not_after.to_datetime();
        let expiry_year = not_after.year().max(0) as u32;
        let expiry_date = NaiveDate::from_ymd_opt(
            not_after.year(),
            not_after.month() as u32,
            not_after.day() as u32,
        )
        .unwrap_or_default();
        let subject = cert.subject().to_string();
        let self_signed = cert.subject().to_string() == cert.issuer().to_string();
        let expired = expiry_date < now;
        let signature_oid = cert.signature_algorithm.algorithm.to_id_string();
        let signature_algorithm = signature_algorithm_name(&signature_oid);

        if key.is_classical() && alg_id.is_classical() {
            if let Some(deadline_info) = table.deadline_for(&alg_id) {
                let deadline = deadline_info.disallowed_year;
                findings.push(Finding {
                    kind: FindingKind::ClassicalCertificate {
                        position: position.clone(),
                        key: key.clone(),
                        deadline,
                    },
                    severity: if deadline <= current_year + 5 {
                        Severity::Warning
                    } else {
                        Severity::Note
                    },
                });

                if expiry_year > deadline {
                    findings.push(Finding {
                        kind: FindingKind::CertExpiresAfterDeadline {
                            expiry: expiry_date,
                            deadline,
                            algorithm: alg_id.clone(),
                        },
                        severity: Severity::Warning,
                    });
                }
            }
        }

        if is_weak_signature(&signature_oid) {
            findings.push(Finding {
                kind: FindingKind::WeakCertificateSignature {
                    position: position.clone(),
                    algorithm: signature_algorithm.clone(),
                },
                severity: Severity::Error,
            });
        }

        if expired {
            findings.push(Finding {
                kind: FindingKind::ExpiredCertificate {
                    position: position.clone(),
                    expiry: expiry_date,
                },
                severity: Severity::Error,
            });
        }

        entries.push(CertEntry {
            position,
            key,
            expiry_year,
            not_after: expiry_date,
            subject,
            algorithm: alg_id,
            signature_algorithm,
            self_signed,
            expired,
        });
    }

    CertChainReport { entries, findings }
}

/// Score the certificate chain out of 15 points.
///
/// The leaf carries most of the weight: replacing a classical leaf with a
/// PQC-signed certificate is the migration action that matters most, while a
/// fully PQC chain is the end state.
pub fn cert_chain_points(report: &CertChainReport) -> u8 {
    if report.entries.is_empty() {
        return 0;
    }
    let all_pqc = report.entries.iter().all(|e| e.key.is_pqc());
    let leaf_pqc = report.entries[0].key.is_pqc();
    let any_pqc = report.entries.iter().any(|e| e.key.is_pqc());

    if all_pqc {
        15
    } else if leaf_pqc {
        10
    } else if any_pqc {
        5
    } else {
        0
    }
}

pub fn cert_chain_notes(report: &CertChainReport) -> Vec<String> {
    if report.entries.is_empty() {
        return vec!["no certificate chain was returned".into()];
    }
    let leaf = &report.entries[0];
    let leaf_kind = if leaf.key.is_pqc() {
        "PQC"
    } else {
        "classical"
    };
    let mut notes = vec![format!(
        "{leaf_kind} leaf certificate signed with {}",
        leaf.signature_algorithm
    )];
    if report.entries.len() > 1 && !report.entries[1..].iter().all(|e| e.key.is_pqc()) {
        notes.push("certificate chain contains classical CA keys".into());
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::tables::nist_ir8547::NistIr8547Table;
    use x509_parser::pem::parse_x509_pem;

    fn pem_certs(pem: &[u8]) -> Vec<Vec<u8>> {
        let mut remaining = pem;
        let mut out = Vec::new();
        while let Ok((rest, block)) = parse_x509_pem(remaining) {
            out.push(block.contents);
            remaining = rest;
        }
        out
    }

    fn audit(pem: &[u8]) -> CertChainReport {
        audit_chain(&pem_certs(pem), &NistIr8547Table, 2026)
    }

    #[test]
    fn empty_chain_returns_empty_report() {
        let report = audit_chain(&[], &NistIr8547Table, 2026);
        assert!(report.entries.is_empty());
        assert!(report.findings.is_empty());
        assert_eq!(cert_chain_points(&report), 0);
        assert_eq!(
            cert_chain_notes(&report),
            vec!["no certificate chain was returned"]
        );
    }

    #[test]
    fn invalid_der_produces_unparseable_finding() {
        let report = audit_chain(&[vec![0xFF, 0xFF, 0xFF]], &NistIr8547Table, 2026);
        assert!(report.entries.is_empty());
        assert_eq!(report.findings.len(), 1);
        assert!(matches!(
            report.findings[0].kind,
            FindingKind::UnparseableCertificate { depth: 0 }
        ));
    }

    #[test]
    fn rsa2048_leaf_is_parsed_accurately() {
        let report = audit(include_bytes!("../../tests/fixtures/certs/rsa2048.pem"));
        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.position, ChainPosition::Leaf);
        assert_eq!(entry.key, KeyInfo::Rsa { bits: 2048 });
        assert_eq!(entry.algorithm, AlgorithmId::Rsa { min_bits: 2048 });
        assert_eq!(entry.signature_algorithm, "sha256WithRSAEncryption");
        assert!(entry.self_signed);
        assert!(!entry.expired);
        // RSA-2048 has a 2035 NIST deadline; the fixture expires in 2036.
        assert!(report.findings.iter().any(|f| matches!(
            f.kind,
            FindingKind::CertExpiresAfterDeadline { deadline: 2035, .. }
        )));
    }

    #[test]
    fn rsa1024_leaf_is_flagged_as_already_disallowed() {
        let report = audit(include_bytes!("../../tests/fixtures/certs/rsa1024.pem"));
        let entry = &report.entries[0];
        assert_eq!(entry.key, KeyInfo::Rsa { bits: 1024 });
        assert_eq!(entry.algorithm, AlgorithmId::Rsa { min_bits: 1024 });
        assert!(report.findings.iter().any(|f| matches!(
            f.kind,
            FindingKind::ClassicalCertificate { deadline: 2000, .. }
        )));
    }

    #[test]
    fn ec_leaf_curve_and_signature_are_parsed() {
        let report = audit(include_bytes!("../../tests/fixtures/certs/ec-p256.pem"));
        let entry = &report.entries[0];
        assert_eq!(
            entry.key,
            KeyInfo::Ec {
                curve: "P-256".into()
            }
        );
        assert_eq!(entry.algorithm, AlgorithmId::EcP256);
        assert_eq!(entry.signature_algorithm, "ecdsa-with-SHA256");
    }

    #[test]
    fn ed25519_leaf_is_parsed() {
        let report = audit(include_bytes!("../../tests/fixtures/certs/ed25519.pem"));
        let entry = &report.entries[0];
        assert_eq!(entry.key, KeyInfo::Ed25519);
        assert_eq!(entry.algorithm, AlgorithmId::Ed25519);
        assert_eq!(entry.signature_algorithm, "Ed25519");
    }

    #[test]
    fn ml_dsa_leaf_is_parsed_as_pqc() {
        let report = audit(include_bytes!("../../tests/fixtures/certs/mldsa65.pem"));
        let entry = &report.entries[0];
        assert_eq!(entry.key, KeyInfo::MlDsa { level: 65 });
        assert_eq!(entry.algorithm, AlgorithmId::MlDsa65);
        assert_eq!(entry.signature_algorithm, "ML-DSA-65");
        assert!(entry.key.is_pqc());
        assert!(!report
            .findings
            .iter()
            .any(|f| matches!(f.kind, FindingKind::ClassicalCertificate { .. })));
        assert_eq!(cert_chain_points(&report), 15);
    }

    #[test]
    fn slh_dsa_leaf_is_parsed_as_pqc() {
        let report = audit(include_bytes!("../../tests/fixtures/certs/slhdsa.pem"));
        let entry = &report.entries[0];
        assert_eq!(entry.key, KeyInfo::SlhDsa { level: 1 });
        assert_eq!(entry.algorithm, AlgorithmId::SlhDsa { level: 1 });
        assert!(entry.signature_algorithm.starts_with("SLH-DSA"));
    }

    #[test]
    fn ml_kem_spki_is_parsed_as_pqc_kem() {
        let report = audit(include_bytes!("../../tests/fixtures/certs/mlkem768.pem"));
        let entry = &report.entries[0];
        assert_eq!(entry.key, KeyInfo::MlKem { level: 768 });
        assert_eq!(entry.algorithm, AlgorithmId::MlKem768);
        assert_eq!(entry.signature_algorithm, "ML-DSA-65");
        assert!(entry.key.is_pqc());
    }

    #[test]
    fn pqc_chain_scores_full_points_and_marks_positions() {
        let report = audit(include_bytes!("../../tests/fixtures/certs/pqc-chain.pem"));
        assert_eq!(report.entries.len(), 3);
        assert_eq!(report.entries[0].position, ChainPosition::Leaf);
        assert_eq!(
            report.entries[1].position,
            ChainPosition::Intermediate { depth: 1 }
        );
        assert_eq!(report.entries[2].position, ChainPosition::Root);
        assert!(report.entries.iter().all(|e| e.key.is_pqc()));
        assert_eq!(cert_chain_points(&report), 15);
        assert_eq!(cert_chain_notes(&report).len(), 1);
    }

    #[test]
    fn mixed_chain_scores_leaf_pqc_only() {
        let report = audit(include_bytes!("../../tests/fixtures/certs/mixed-chain.pem"));
        assert!(report.entries[0].key.is_pqc());
        assert!(!report.entries[1].key.is_pqc());
        assert_eq!(cert_chain_points(&report), 10);
        assert!(cert_chain_notes(&report)
            .iter()
            .any(|n| n.contains("classical CA keys")));
    }

    #[test]
    fn classical_chain_scores_zero() {
        let report = audit(include_bytes!(
            "../../tests/fixtures/certs/classical-chain.pem"
        ));
        assert!(report.entries.iter().all(|e| !e.key.is_pqc()));
        assert_eq!(cert_chain_points(&report), 0);
    }

    #[test]
    fn expired_certificate_is_flagged() {
        let report = audit(include_bytes!("../../tests/fixtures/certs/expired.pem"));
        assert!(report.entries[0].expired);
        assert!(report
            .findings
            .iter()
            .any(|f| matches!(f.kind, FindingKind::ExpiredCertificate { .. })));
    }

    #[test]
    fn weak_signature_is_flagged() {
        let mut der =
            pem_certs(include_bytes!("../../tests/fixtures/certs/rsa2048.pem"))[0].clone();
        // Replace sha256WithRSAEncryption (…1.1.11) with sha1WithRSAEncryption (…1.1.5).
        let sha256_oid = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
        ];
        let sha1_oid = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05,
        ];
        let positions: Vec<usize> = der
            .windows(sha256_oid.len())
            .enumerate()
            .filter_map(|(i, w)| (w == sha256_oid).then_some(i))
            .collect();
        assert!(!positions.is_empty(), "sha256 OID must be present");
        for pos in positions {
            der[pos..pos + sha1_oid.len()].copy_from_slice(&sha1_oid);
        }

        let report = audit_chain(&[der], &NistIr8547Table, 2026);
        assert_eq!(
            report.entries[0].signature_algorithm,
            "sha1WithRSAEncryption"
        );
        assert!(report
            .findings
            .iter()
            .any(|f| matches!(f.kind, FindingKind::WeakCertificateSignature { .. })));
    }

    #[test]
    fn signature_algorithm_names_cover_known_oids() {
        for oid in [
            "1.2.840.113549.1.1.4",
            "1.2.840.113549.1.1.5",
            "1.2.840.113549.1.1.10",
            "1.2.840.113549.1.1.11",
            "1.2.840.113549.1.1.12",
            "1.2.840.113549.1.1.13",
            "1.2.840.10045.4.1",
            "1.2.840.10045.4.3.2",
            "1.2.840.10045.4.3.3",
            "1.2.840.10045.4.3.4",
            "1.2.840.10040.4.3",
            "2.16.840.1.101.3.4.3.1",
            OID_ED25519,
            OID_ED448,
            OID_ML_DSA_44,
            OID_ML_DSA_65,
            OID_ML_DSA_87,
        ] {
            assert!(!signature_algorithm_name(oid).starts_with("Unknown"));
        }
        assert!(signature_algorithm_name("1.2.3.4").starts_with("Unknown"));
    }

    #[test]
    fn weak_signature_predicate_matches_deprecated_hashes() {
        for oid in [
            "1.2.840.113549.1.1.4",
            "1.2.840.113549.1.1.5",
            "1.2.840.10045.4.1",
            "1.2.840.10040.4.3",
        ] {
            assert!(is_weak_signature(oid));
        }
        assert!(!is_weak_signature(OID_ML_DSA_65));
    }

    #[test]
    fn slh_dsa_level_mapping_covers_all_parameter_sets() {
        for (suffix, level) in [
            (20, 1),
            (21, 1),
            (22, 3),
            (23, 3),
            (24, 5),
            (25, 5),
            (26, 1),
            (27, 1),
            (28, 3),
            (29, 3),
            (30, 5),
            (31, 5),
        ] {
            let oid = format!("2.16.840.1.101.3.4.3.{suffix}");
            assert_eq!(slh_dsa_level(&oid), Some(level));
        }
        assert_eq!(slh_dsa_level("2.16.840.1.101.3.4.3.32"), None);
    }

    #[test]
    fn curve_name_mapping_covers_nist_curves() {
        assert_eq!(curve_name("1.2.840.10045.3.1.7"), Some("P-256"));
        assert_eq!(curve_name("1.3.132.0.34"), Some("P-384"));
        assert_eq!(curve_name("1.3.132.0.35"), Some("P-521"));
        assert_eq!(curve_name("1.3.132.0.10"), Some("secp256k1"));
        assert_eq!(curve_name("1.3.132.0.33"), Some("P-224"));
        assert_eq!(curve_name("1.2.3.4"), None);
    }

    #[test]
    fn p521_and_unknown_curve_are_parsed() {
        let report = audit(include_bytes!("../../tests/fixtures/certs/ec-p521.pem"));
        assert_eq!(
            report.entries[0].key,
            KeyInfo::Ec {
                curve: "P-521".into()
            }
        );
        assert_eq!(report.entries[0].algorithm, AlgorithmId::EcP521);

        let report = audit(include_bytes!(
            "../../tests/fixtures/certs/ec-secp256k1.pem"
        ));
        assert_eq!(
            report.entries[0].key,
            KeyInfo::Ec {
                curve: "secp256k1".into()
            }
        );
        assert_eq!(report.entries[0].algorithm, AlgorithmId::EcOther);
        assert!(report
            .findings
            .iter()
            .any(|f| matches!(f.kind, FindingKind::ClassicalCertificate { .. })));
    }

    #[test]
    fn dsa_certificate_is_parsed() {
        let report = audit(include_bytes!("../../tests/fixtures/certs/dsa2048.pem"));
        let entry = &report.entries[0];
        assert!(matches!(entry.key, KeyInfo::Dsa { .. }));
        assert!(matches!(entry.algorithm, AlgorithmId::Dsa { .. }));
        assert_eq!(entry.signature_algorithm, "dsa-with-SHA256");
    }

    #[test]
    fn unknown_spki_oid_is_parsed_as_unknown() {
        let mut der =
            pem_certs(include_bytes!("../../tests/fixtures/certs/rsa2048.pem"))[0].clone();
        // rsaEncryption OID …1.1.1 → md2WithRSAEncryption …1.1.2 (unknown as an SPKI algorithm).
        let rsa_oid = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
        ];
        let unknown_oid = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x02,
        ];
        let pos = der
            .windows(rsa_oid.len())
            .position(|w| w == rsa_oid)
            .expect("rsa OID present");
        der[pos..pos + unknown_oid.len()].copy_from_slice(&unknown_oid);
        let report = audit_chain(&[der], &NistIr8547Table, 2026);
        assert_eq!(report.entries[0].key, KeyInfo::Unknown);
        assert_eq!(report.entries[0].algorithm, AlgorithmId::Unknown);
    }

    #[test]
    fn fips_approved_classical_cert_has_no_classical_finding() {
        use crate::audit::tables::fips::FipsTable;
        let report = audit_chain(
            &pem_certs(include_bytes!("../../tests/fixtures/certs/rsa2048.pem")),
            &FipsTable,
            2026,
        );
        assert!(!report
            .findings
            .iter()
            .any(|f| matches!(f.kind, FindingKind::ClassicalCertificate { .. })));
    }

    #[test]
    fn chain_with_pqc_ca_but_classical_leaf_scores_five() {
        let report = CertChainReport {
            entries: vec![
                CertEntry {
                    position: ChainPosition::Leaf,
                    key: KeyInfo::Ec {
                        curve: "P-256".into(),
                    },
                    expiry_year: 2030,
                    not_after: chrono::NaiveDate::from_ymd_opt(2030, 1, 1).unwrap(),
                    subject: "leaf".into(),
                    algorithm: AlgorithmId::EcP256,
                    signature_algorithm: "ecdsa-with-SHA256".into(),
                    self_signed: false,
                    expired: false,
                },
                CertEntry {
                    position: ChainPosition::Root,
                    key: KeyInfo::MlDsa { level: 65 },
                    expiry_year: 2040,
                    not_after: chrono::NaiveDate::from_ymd_opt(2040, 1, 1).unwrap(),
                    subject: "root".into(),
                    algorithm: AlgorithmId::MlDsa65,
                    signature_algorithm: "ML-DSA-65".into(),
                    self_signed: true,
                    expired: false,
                },
            ],
            findings: vec![],
        };
        assert_eq!(cert_chain_points(&report), 5);
    }
}
