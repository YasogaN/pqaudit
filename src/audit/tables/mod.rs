pub mod cnsa2;
pub mod fips;
pub mod iana_ciphers;
pub mod iana_groups;
pub mod iana_sigalgs;
pub mod nist_ir8547;

use crate::AlgorithmId;

pub trait DeadlineTable: Send + Sync {
    fn name(&self) -> &'static str;
    fn deadline_for(&self, alg: &AlgorithmId) -> Option<DeadlineInfo>;

    /// Resolve an algorithm's status at `current_year`.
    ///
    /// The year is injected rather than read from the wall clock so that
    /// compliance behaviour is deterministic in tests and reproducible in CI.
    fn status_for(&self, alg: &AlgorithmId, current_year: u32) -> AlgorithmStatus {
        match self.deadline_for(alg) {
            Some(d) if d.disallowed_year <= current_year => AlgorithmStatus::Disallowed,
            Some(d) if d.deprecated_year <= current_year => AlgorithmStatus::Deprecated,
            Some(_) => AlgorithmStatus::Approved,
            // A PQC algorithm with no table entry is approved for this regime.
            None if alg.is_pqc() => AlgorithmStatus::Approved,
            None => AlgorithmStatus::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeadlineInfo {
    pub deprecated_year: u32,
    pub disallowed_year: u32,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgorithmStatus {
    Approved,
    Deprecated,
    Disallowed,
    Unknown,
}
