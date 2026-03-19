pub mod audit;
pub mod output;
pub mod probe;
pub mod scanner;
pub mod baseline;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod cli;

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
    StarttlsUpgradeFailed { protocol: StarttlsProtocol, reason: String },
    #[error("certificate parse error: {reason}")]
    CertificateParseError { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StarttlsProtocol {
    Smtp,
    Imap,
    Pop3,
    Ldap,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: String,
    pub scanned_at: String,
    pub compliance_mode: cli::ComplianceMode,
    pub targets: Vec<TargetReport>,
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
