use crate::audit::tables::{AlgorithmStatus, DeadlineInfo, DeadlineTable};
use crate::AlgorithmId;

pub struct FipsTable;

impl DeadlineTable for FipsTable {
    fn name(&self) -> &'static str {
        "FIPS 140-3"
    }

    fn deadline_for(&self, alg: &AlgorithmId) -> Option<DeadlineInfo> {
        Some(match alg {
            // Not FIPS approved
            AlgorithmId::ChaCha20Poly1305 => DeadlineInfo {
                deprecated_year: 2000,
                disallowed_year: 2000,
                note: "Not FIPS 140-3 approved",
            },
            // Classical algorithms deprecated under FIPS transition guidance
            AlgorithmId::Rsa { .. }
            | AlgorithmId::EcP256
            | AlgorithmId::EcP384
            | AlgorithmId::X25519
            | AlgorithmId::Ed25519
            | AlgorithmId::Dh { .. } => DeadlineInfo {
                deprecated_year: 2024,
                disallowed_year: 2030,
                note: "Transitioning to PQC",
            },
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
