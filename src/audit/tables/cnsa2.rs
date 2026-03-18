use crate::AlgorithmId;
use crate::audit::tables::{AlgorithmStatus, DeadlineInfo, DeadlineTable};

pub struct Cnsa2Table;

impl DeadlineTable for Cnsa2Table {
    fn name(&self) -> &'static str { "NSA CNSA 2.0" }

    fn deadline_for(&self, alg: &AlgorithmId) -> Option<DeadlineInfo> {
        Some(match alg {
            // Classical algorithms all deprecated, disallowed 2030
            AlgorithmId::Rsa { .. }
            | AlgorithmId::EcP256
            | AlgorithmId::EcP384
            | AlgorithmId::X25519
            | AlgorithmId::Ed25519
            | AlgorithmId::Dh { .. } =>
                DeadlineInfo { deprecated_year: 2024, disallowed_year: 2030, note: "CNSA 1.0 algorithms" },
            // AES-128 insufficient now
            AlgorithmId::Aes128 =>
                DeadlineInfo { deprecated_year: 2024, disallowed_year: 2024, note: "AES-256 required" },
            // SHA-256 insufficient for NSS (SHA-384+ required)
            AlgorithmId::Sha256 =>
                DeadlineInfo { deprecated_year: 2024, disallowed_year: 2024, note: "SHA-384+ required" },
            _ => return None,
        })
    }

    fn status_for(&self, alg: &AlgorithmId) -> AlgorithmStatus {
        const CURRENT_YEAR: u32 = 2026;
        match self.deadline_for(alg) {
            None => AlgorithmStatus::Unknown,
            Some(d) if d.disallowed_year <= CURRENT_YEAR => AlgorithmStatus::Disallowed,
            Some(d) if d.deprecated_year <= CURRENT_YEAR => AlgorithmStatus::Deprecated,
            Some(_) => AlgorithmStatus::Approved,
        }
    }
}
