use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;
use crate::{AlgorithmId, ChainPosition, KeyInfo};
use crate::audit::findings::{Finding, FindingKind, Severity};
use crate::audit::tables::{DeadlineTable, nist_ir8547::NistIr8547Table};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertEntry {
    pub position: ChainPosition,
    pub key: KeyInfo,
    pub expiry_year: u32,
    pub subject: String,
    pub algorithm: AlgorithmId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertChainReport {
    pub entries: Vec<CertEntry>,
    pub findings: Vec<Finding>,
}

/// Parse a `KeyInfo` from x509-parser's `SubjectPublicKeyInfo`.
fn parse_key_info(spki: &SubjectPublicKeyInfo) -> KeyInfo {
    let alg_oid = spki.algorithm.algorithm.to_id_string();
    match alg_oid.as_str() {
        // rsaEncryption
        "1.2.840.113549.1.1.1" => {
            // Rough heuristic: RSA-2048 DER public key is ~270 bytes, RSA-4096 ~550 bytes
            let byte_len = spki.subject_public_key.data.len();
            let rsa_bits: u32 = if byte_len > 500 { 4096 } else if byte_len > 380 { 3072 } else { 2048 };
            KeyInfo::Rsa { bits: rsa_bits }
        }
        // ecPublicKey
        "1.2.840.10045.2.1" => {
            let curve_oid = spki.algorithm.parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|o| o.to_id_string())
                .unwrap_or_default();
            match curve_oid.as_str() {
                "1.2.840.10045.3.1.7" => KeyInfo::Ec { curve: "P-256".into() },
                "1.3.132.0.34"        => KeyInfo::Ec { curve: "P-384".into() },
                "1.3.132.0.35"        => KeyInfo::Ec { curve: "P-521".into() },
                _                     => KeyInfo::Ec { curve: curve_oid },
            }
        }
        // id-EdDSA Ed25519
        "1.3.101.112" => KeyInfo::Ed25519,
        // Ed448
        "1.3.101.113" => KeyInfo::Ed448,
        _ => KeyInfo::Unknown,
    }
}

fn parse_algorithm_id(spki: &SubjectPublicKeyInfo) -> AlgorithmId {
    let oid = spki.algorithm.algorithm.to_id_string();
    match oid.as_str() {
        "1.2.840.113549.1.1.1" => {
            let byte_len = spki.subject_public_key.data.len();
            let min_bits: u32 = if byte_len > 500 { 4096 } else if byte_len > 380 { 3072 } else { 2048 };
            AlgorithmId::Rsa { min_bits }
        }
        "1.2.840.10045.2.1" => {
            let curve = spki.algorithm.parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|o| o.to_id_string())
                .unwrap_or_default();
            match curve.as_str() {
                "1.2.840.10045.3.1.7" => AlgorithmId::EcP256,
                "1.3.132.0.34"        => AlgorithmId::EcP384,
                "1.3.132.0.35"        => AlgorithmId::EcP521,
                _                     => AlgorithmId::EcP256,
            }
        }
        "1.3.101.112" => AlgorithmId::Ed25519,
        "1.3.101.113" => AlgorithmId::Ed448,
        _             => AlgorithmId::Ed25519, // fallback
    }
}

/// Audit a DER-encoded certificate chain.
/// `chain_der` is a slice of DER blobs, one per certificate.
/// The first entry is the leaf; last is the root (or closest to root).
pub fn audit_chain(chain_der: &[Vec<u8>]) -> CertChainReport {
    if chain_der.is_empty() {
        return CertChainReport { entries: vec![], findings: vec![] };
    }

    let table = NistIr8547Table;
    let mut entries = Vec::new();
    let mut findings = Vec::new();
    let total = chain_der.len();

    for (depth, der) in chain_der.iter().enumerate() {
        let position = if depth == 0 {
            ChainPosition::Leaf
        } else if depth == total - 1 {
            ChainPosition::Root
        } else {
            ChainPosition::Intermediate { depth: depth as u8 }
        };

        let cert = match X509Certificate::from_der(der) {
            Ok((_, c)) => c,
            Err(_) => continue, // skip unparseable certs
        };

        let spki = cert.public_key();
        let key = parse_key_info(spki);
        let alg_id = parse_algorithm_id(spki);
        let expiry_year = cert.validity().not_after.to_datetime().year() as u32;
        let subject = cert.subject().to_string();

        let is_classical = matches!(key,
            KeyInfo::Rsa { .. } | KeyInfo::Ec { .. } | KeyInfo::Ed25519 | KeyInfo::Ed448
        );

        if is_classical {
            if let Some(deadline_info) = table.deadline_for(&alg_id) {
                let deadline = deadline_info.disallowed_year;
                findings.push(Finding {
                    kind: FindingKind::ClassicalCertificate {
                        position: position.clone(),
                        key: key.clone(),
                        deadline,
                    },
                    severity: if deadline <= 2030 { Severity::Warning } else { Severity::Note },
                });

                if expiry_year > deadline {
                    findings.push(Finding {
                        kind: FindingKind::CertExpiresAfterDeadline {
                            expiry: chrono::NaiveDate::from_ymd_opt(expiry_year as i32, 1, 1)
                                .unwrap_or_default(),
                            deadline,
                            algorithm: alg_id.clone(),
                        },
                        severity: Severity::Warning,
                    });
                }
            }
        }

        entries.push(CertEntry {
            position,
            key,
            expiry_year,
            subject,
            algorithm: alg_id,
        });
    }

    CertChainReport { entries, findings }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_chain_returns_empty_report() {
        let report = audit_chain(&[]);
        assert!(report.entries.is_empty());
        assert!(report.findings.is_empty());
    }

    #[test]
    fn single_invalid_der_returns_empty_entries() {
        // Completely invalid DER — parser should return empty, not panic
        let bad = vec![0xFF, 0xFF, 0xFF];
        let report = audit_chain(&[bad]);
        assert!(report.entries.is_empty());
        assert!(report.findings.is_empty());
    }
}
