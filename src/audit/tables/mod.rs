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
    fn status_for(&self, alg: &AlgorithmId) -> AlgorithmStatus;
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
