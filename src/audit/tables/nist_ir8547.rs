// NOTE: NIST IR 8547 is an Initial Public Draft (November 2024).
// Deadline values below are from the IPD and may be revised before finalization.
use crate::audit::tables::{AlgorithmStatus, DeadlineInfo, DeadlineTable};
use crate::AlgorithmId;

pub struct NistIr8547Table;

impl DeadlineTable for NistIr8547Table {
    fn name(&self) -> &'static str {
        "NIST IR 8547 (IPD)"
    }

    fn deadline_for(&self, alg: &AlgorithmId) -> Option<DeadlineInfo> {
        Some(match alg {
            AlgorithmId::Rsa { min_bits } if *min_bits < 2048 => DeadlineInfo {
                deprecated_year: 2000,
                disallowed_year: 2000,
                note: "Already disallowed",
            },
            AlgorithmId::Rsa { min_bits } if *min_bits <= 3072 => DeadlineInfo {
                deprecated_year: 2024,
                disallowed_year: 2030,
                note: "Primary hard wall",
            },
            AlgorithmId::Rsa { .. } => DeadlineInfo {
                deprecated_year: 2024,
                disallowed_year: 2035,
                note: "Extended deadline for RSA-4096",
            },
            AlgorithmId::EcP256 | AlgorithmId::EcP384 => DeadlineInfo {
                deprecated_year: 2024,
                disallowed_year: 2030,
                note: "",
            },
            AlgorithmId::EcP521 => DeadlineInfo {
                deprecated_year: 2024,
                disallowed_year: 2035,
                note: "Extended deadline",
            },
            AlgorithmId::X25519 | AlgorithmId::Ed25519 => DeadlineInfo {
                deprecated_year: 2024,
                disallowed_year: 2030,
                note: "",
            },
            AlgorithmId::X448 | AlgorithmId::Ed448 => DeadlineInfo {
                deprecated_year: 2024,
                disallowed_year: 2035,
                note: "Extended deadline",
            },
            AlgorithmId::Dh { min_bits } if *min_bits < 2048 => DeadlineInfo {
                deprecated_year: 2000,
                disallowed_year: 2000,
                note: "Already disallowed",
            },
            AlgorithmId::Dh { min_bits } if *min_bits <= 2048 => DeadlineInfo {
                deprecated_year: 2024,
                disallowed_year: 2030,
                note: "",
            },
            AlgorithmId::Dh { .. } => DeadlineInfo {
                deprecated_year: 2024,
                disallowed_year: 2035,
                note: "Extended deadline for DH-3072+",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::tables::{AlgorithmStatus, DeadlineTable};
    use crate::AlgorithmId;

    #[test]
    fn rsa2048_disallowed_2030() {
        let table = NistIr8547Table;
        let info = table
            .deadline_for(&AlgorithmId::Rsa { min_bits: 2048 })
            .expect("RSA-2048 must have deadline info");
        assert_eq!(info.disallowed_year, 2030);
    }

    #[test]
    fn p521_disallowed_2035() {
        let table = NistIr8547Table;
        let info = table
            .deadline_for(&AlgorithmId::EcP521)
            .expect("P-521 must have deadline info");
        assert_eq!(info.disallowed_year, 2035);
    }

    #[test]
    fn rsa2048_is_deprecated_not_disallowed_in_2026() {
        let table = NistIr8547Table;
        assert_eq!(
            table.status_for(&AlgorithmId::Rsa { min_bits: 2048 }),
            AlgorithmStatus::Deprecated
        );
    }

    #[test]
    fn ml_kem_768_has_no_deadline_returns_unknown() {
        let table = NistIr8547Table;
        assert_eq!(
            table.status_for(&AlgorithmId::MlKem768),
            AlgorithmStatus::Unknown
        );
    }
}
