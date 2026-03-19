// src/audit/findings.rs — stub, completed in Task 7
use crate::{AlgorithmId, ChainPosition, CipherSuite, KeyInfo, NamedGroup, TlsVersion};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Error,
    Warning,
    Note,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingKind {
    ClassicalKeyExchangeOnly {
        group: NamedGroup,
    },
    HybridKeyExchangeHrrRequired {
        group: NamedGroup,
    },
    DeprecatedPqcDraftCodepoint {
        code_point: u16,
    },
    WeakSymmetricCipher {
        suite: CipherSuite,
    },
    ClassicalCertificate {
        position: ChainPosition,
        key: KeyInfo,
        deadline: u32,
    },
    DowngradeAccepted,
    TlsVersionInsufficient {
        max_version: TlsVersion,
    },
    CertExpiresAfterDeadline {
        expiry: NaiveDate,
        deadline: u32,
        algorithm: AlgorithmId,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
}

impl fmt::Display for FindingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClassicalKeyExchangeOnly { group } => {
                write!(f, "Classical key exchange only (group: {})", group.name)
            }
            Self::HybridKeyExchangeHrrRequired { group } => write!(
                f,
                "Hybrid PQC key exchange requires HelloRetryRequest (group: {})",
                group.name
            ),
            Self::DeprecatedPqcDraftCodepoint { code_point } => write!(
                f,
                "Deprecated PQC draft code point 0x{:04X} (Kyber draft)",
                code_point
            ),
            Self::WeakSymmetricCipher { suite } => {
                write!(f, "Weak or deprecated cipher suite: {}", suite.name)
            }
            Self::ClassicalCertificate {
                position,
                key,
                deadline,
            } => write!(
                f,
                "Classical certificate ({:?}) with {:?} must migrate by {}",
                position, key, deadline
            ),
            Self::DowngradeAccepted => write!(f, "Server accepted TLS downgrade below 1.3"),
            Self::TlsVersionInsufficient { max_version } => {
                write!(f, "Insufficient TLS version: {}", max_version)
            }
            Self::CertExpiresAfterDeadline {
                expiry,
                deadline,
                algorithm,
            } => write!(
                f,
                "Certificate expires {} after {:?} deadline {}",
                expiry, algorithm, deadline
            ),
        }
    }
}

impl Finding {
    pub fn sarif_rule_id(&self) -> &'static str {
        match &self.kind {
            FindingKind::ClassicalKeyExchangeOnly { .. } => "PQA001",
            FindingKind::HybridKeyExchangeHrrRequired { .. } => "PQA002",
            FindingKind::DeprecatedPqcDraftCodepoint { .. } => "PQA003",
            FindingKind::WeakSymmetricCipher { .. } => "PQA004",
            FindingKind::ClassicalCertificate { deadline, .. } => {
                if *deadline <= 2030 {
                    "PQA005"
                } else {
                    "PQA006"
                }
            }
            FindingKind::DowngradeAccepted => "PQA007",
            FindingKind::TlsVersionInsufficient { .. } => "PQA008",
            FindingKind::CertExpiresAfterDeadline { .. } => "PQA009",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChainPosition, CipherSuite, KeyInfo, NamedGroup};

    #[test]
    fn finding_has_stable_sarif_id() {
        let f = Finding {
            kind: FindingKind::ClassicalKeyExchangeOnly {
                group: NamedGroup {
                    code_point: 0x001D,
                    name: "x25519".into(),
                    is_pqc: false,
                },
            },
            severity: Severity::Error,
        };
        assert_eq!(f.sarif_rule_id(), "PQA001");
    }

    #[test]
    fn downgrade_accepted_is_pqa007() {
        let f = Finding {
            kind: FindingKind::DowngradeAccepted,
            severity: Severity::Error,
        };
        assert_eq!(f.sarif_rule_id(), "PQA007");
    }

    #[test]
    fn classical_cert_deadline_pre_2030_is_pqa005() {
        let f = Finding {
            kind: FindingKind::ClassicalCertificate {
                position: ChainPosition::Leaf,
                key: KeyInfo::Rsa { bits: 2048 },
                deadline: 2030,
            },
            severity: Severity::Warning,
        };
        assert_eq!(f.sarif_rule_id(), "PQA005");
    }

    #[test]
    fn classical_cert_deadline_post_2030_is_pqa006() {
        let f = Finding {
            kind: FindingKind::ClassicalCertificate {
                position: ChainPosition::Leaf,
                key: KeyInfo::Rsa { bits: 2048 },
                deadline: 2035,
            },
            severity: Severity::Note,
        };
        assert_eq!(f.sarif_rule_id(), "PQA006");
    }
}
