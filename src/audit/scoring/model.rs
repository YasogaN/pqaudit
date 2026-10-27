use crate::audit::cert_chain::CertChainReport;
use crate::audit::findings::{FindingKind, Severity};
use crate::audit::tables::DeadlineTable;
use crate::{DowngradeResult, ProbeResults, TlsVersion};
use serde::{Deserialize, Serialize};

/// Downgrade posture is worth 5 points only when the server rejects TLS 1.2
/// downgrades, does not accept a classical-only TLS 1.3 key exchange, and does
/// not accept legacy TLS 1.0/1.1.
pub fn downgrade_points(
    downgrade: &DowngradeResult,
    classical_fallback: bool,
    legacy_protocols: &[TlsVersion],
) -> u8 {
    if matches!(downgrade, DowngradeResult::Rejected)
        && !classical_fallback
        && legacy_protocols.is_empty()
    {
        5
    } else {
        0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryScore {
    pub name: String,
    pub points: u8,
    pub max_points: u8,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringResult {
    pub total: u8,
    pub key_exchange: CategoryScore,
    pub tls_version: CategoryScore,
    pub cipher_suite: CategoryScore,
    pub cert_chain: CategoryScore,
    pub downgrade_posture: CategoryScore,
}

pub trait ScoringModel: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn score(
        &self,
        probe: &ProbeResults,
        cert_chain: Option<&CertChainReport>,
        table: &dyn DeadlineTable,
    ) -> ScoringResult;
    fn severity(&self, finding: &FindingKind) -> Severity;
}
