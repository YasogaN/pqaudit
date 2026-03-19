use crate::audit::findings::{FindingKind, Severity};
use crate::audit::tables::DeadlineTable;
use crate::ProbeResults;
use serde::{Deserialize, Serialize};

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
    fn score(&self, probe: &ProbeResults, table: &dyn DeadlineTable) -> ScoringResult;
    fn severity(&self, finding: &FindingKind) -> Severity;
}
