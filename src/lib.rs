pub mod audit;
pub mod baseline;
pub mod cli;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod output;
pub mod probe;
pub mod scanner;

use serde::{Deserialize, Serialize};
use std::fmt;

// ── TLS primitives ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsVersion {
    Tls13,
    Tls12,
    Tls11,
    Tls10,
    Unknown(u16),
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls13 => write!(f, "TLS 1.3"),
            Self::Tls12 => write!(f, "TLS 1.2"),
            Self::Tls11 => write!(f, "TLS 1.1"),
            Self::Tls10 => write!(f, "TLS 1.0"),
            Self::Unknown(v) => write!(f, "Unknown(0x{v:04x})"),
        }
    }
}

/// TLS NamedGroup code point.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NamedGroup {
    pub code_point: u16,
    pub name: String,
    pub is_pqc: bool,
}

/// TLS cipher suite identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CipherSuite {
    pub id: u16,
    pub name: String,
}

/// Key type and size from a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyInfo {
    Rsa { bits: u32 },
    Ec { curve: String },
    Ed25519,
    Ed448,
    MlDsa { level: u8 },
    Unknown,
}

/// Position of a certificate in the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainPosition {
    Leaf,
    Intermediate { depth: u8 },
    Root,
}

/// Algorithm identifier used in deadline tables.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlgorithmId {
    Rsa { min_bits: u32 },
    EcP256,
    EcP384,
    EcP521,
    X25519,
    X448,
    Ed25519,
    Ed448,
    Dh { min_bits: u32 },
    MlKem768,
    MlKem1024,
    MlDsa65,
    MlDsa87,
    Aes128,
    Aes256,
    Sha256,
    Sha384,
    Sha512,
    ChaCha20Poly1305,
}

// ── Probe results ─────────────────────────────────────────────────────────────

/// Results from the Layer 1 rustls PQC handshake probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcHandshakeResult {
    pub negotiated_version: TlsVersion,
    pub negotiated_suite: CipherSuite,
    pub negotiated_group: NamedGroup,
    pub hrr_required: bool,
    pub cert_chain_der: Vec<Vec<u8>>,
}

/// Results from active cipher enumeration (--full-scan).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CipherInventory {
    pub tls13_suites: Vec<CipherSuite>,
    pub tls12_suites: Vec<CipherSuite>,
    /// True if server accepted the Kyber draft key share (group 0x6399).
    #[serde(default)]
    pub kyber_draft_accepted: bool,
}

/// Result of the downgrade probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DowngradeResult {
    Accepted { negotiated_version: TlsVersion },
    Rejected,
    Timeout,
    Error(String),
}

/// Aggregate probe data fed to the audit engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResults {
    pub target: String,
    pub port: u16,
    pub pqc_handshake: Result<PqcHandshakeResult, String>,
    pub cipher_inventory: Option<CipherInventory>,
    pub downgrade: DowngradeResult,
}

// ── Error types ───────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("connection refused to {host}:{port}")]
    ConnectionRefused { host: String, port: u16 },
    #[error("DNS resolution failed for {host}")]
    DnsResolutionFailed { host: String },
    #[error("TLS handshake failed: {reason}")]
    TlsHandshakeFailed { reason: String },
    #[error("certificate validation failed: {reason}")]
    CertificateValidationFailed { reason: String },
    #[error("SNI mismatch: presented={presented}, expected={expected}")]
    SniMismatch { presented: String, expected: String },
    #[error("timeout after {after_ms}ms")]
    Timeout { after_ms: u64 },
    #[error("STARTTLS upgrade failed for {protocol:?}: {reason}")]
    StarttlsUpgradeFailed {
        protocol: StarttlsProtocol,
        reason: String,
    },
    #[error("certificate parse error: {reason}")]
    CertificateParseError { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StarttlsProtocol {
    Smtp,
    Imap,
    Pop3,
    Ldap,
    Other(String),
}

// ── Scan report ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetReport {
    pub target: String,
    pub port: u16,
    pub score: audit::scoring::model::ScoringResult,
    pub hndl: audit::hndl::HndlAssessment,
    pub findings: Vec<audit::findings::Finding>,
    pub cert_chain: Option<audit::cert_chain::CertChainReport>,
    pub cipher_inventory: Option<CipherInventory>,
    pub downgrade: DowngradeResult,
    pub error: Option<String>,
    /// Negotiated key exchange group from the PQC handshake probe.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub negotiated_group: Option<NamedGroup>,
    /// Negotiated cipher suite from the PQC handshake probe.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub negotiated_suite: Option<CipherSuite>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: String,
    pub scanned_at: String,
    pub compliance_mode: cli::ComplianceMode,
    pub targets: Vec<TargetReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison: Option<output::compare::ComparisonReport>,
}

// ── Test helpers shared across modules ────────────────────────────────────────
#[cfg(test)]
pub mod tests_common {
    use crate::audit::{
        cert_chain::CertChainReport,
        findings::Finding,
        hndl::{HndlAssessment, HndlRating},
        scoring::model::{CategoryScore, ScoringResult},
    };
    use crate::cli::ComplianceMode;
    use crate::{CipherInventory, DowngradeResult, ScanReport, TargetReport, TlsVersion};

    fn zero_category(name: &str) -> CategoryScore {
        CategoryScore {
            name: name.into(),
            points: 0,
            max_points: 0,
            notes: vec![],
        }
    }

    pub fn stub_target_report(score: u8) -> TargetReport {
        use crate::CipherSuite;
        TargetReport {
            target: "example.com".into(),
            port: 443,
            score: ScoringResult {
                total: score,
                key_exchange: zero_category("key_exchange"),
                tls_version: zero_category("tls_version"),
                cipher_suite: zero_category("cipher_suite"),
                cert_chain: zero_category("cert_chain"),
                downgrade_posture: zero_category("downgrade_posture"),
            },
            hndl: HndlAssessment {
                rating: HndlRating::None,
                exposure_window_years: 0.0,
                cert_expires_before_q_day: false,
                notes: vec![],
            },
            findings: vec![],
            cert_chain: Some(CertChainReport {
                entries: vec![],
                findings: vec![],
            }),
            cipher_inventory: Some(CipherInventory {
                tls13_suites: vec![CipherSuite {
                    id: 0x1302,
                    name: "TLS_AES_256_GCM_SHA384".into(),
                }],
                tls12_suites: vec![],
                kyber_draft_accepted: false,
            }),
            downgrade: DowngradeResult::Rejected,
            error: None,
            negotiated_group: Some(crate::NamedGroup {
                code_point: 0x11EC,
                name: "X25519MLKEM768".into(),
                is_pqc: true,
            }),
            negotiated_suite: Some(CipherSuite {
                id: 0x1302,
                name: "TLS_AES_256_GCM_SHA384".into(),
            }),
        }
    }

    pub fn stub_scan_report() -> ScanReport {
        ScanReport {
            schema_version: "1.0".into(),
            scanned_at: "2026-01-01T00:00:00Z".into(),
            compliance_mode: ComplianceMode::Nist,
            targets: vec![stub_target_report(80)],
            comparison: None,
        }
    }

    /// Returns a ScanReport with one target that has a ClassicalKeyExchangeOnly finding.
    pub fn stub_scan_report_with_all_findings() -> ScanReport {
        use crate::audit::findings::{Finding, FindingKind, Severity};
        use crate::NamedGroup;

        let mut target = stub_target_report(30);
        target.findings = vec![
            Finding {
                kind: FindingKind::ClassicalKeyExchangeOnly {
                    group: NamedGroup {
                        code_point: 0x001D,
                        name: "x25519".into(),
                        is_pqc: false,
                    },
                },
                severity: Severity::Error,
            },
            Finding {
                kind: FindingKind::DowngradeAccepted,
                severity: Severity::Warning,
            },
        ];
        ScanReport {
            schema_version: "1.0".into(),
            scanned_at: "2026-01-01T00:00:00Z".into(),
            compliance_mode: ComplianceMode::Nist,
            targets: vec![target],
            comparison: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_version_display() {
        assert_eq!(TlsVersion::Tls13.to_string(), "TLS 1.3");
        assert_eq!(TlsVersion::Tls12.to_string(), "TLS 1.2");
    }

    #[test]
    fn probe_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ProbeError>();
    }
}
