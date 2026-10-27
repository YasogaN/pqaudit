//! FIPS 140-3 / SP 800-131A algorithm approvals.
//!
//! FIPS 140-3 validates cryptographic modules; it is not a post-quantum
//! transition schedule. This table therefore only encodes whether an algorithm
//! family is NIST-approved, and deliberately does not impose the NIST IR 8547
//! 2030/2035 deadlines. Use the NIST or CNSA 2.0 mode for migration dates.
use crate::audit::tables::{AlgorithmStatus, DeadlineInfo, DeadlineTable};
use crate::AlgorithmId;

pub struct FipsTable;

impl DeadlineTable for FipsTable {
    fn name(&self) -> &'static str {
        "FIPS 140-3"
    }

    fn deadline_for(&self, alg: &AlgorithmId) -> Option<DeadlineInfo> {
        Some(match alg {
            AlgorithmId::Rsa { min_bits } if *min_bits < 2048 => DeadlineInfo {
                deprecated_year: 2000,
                disallowed_year: 2000,
                note: "RSA below 2048 bits is not FIPS-approved",
            },
            AlgorithmId::Dh { min_bits } if *min_bits < 2048 => DeadlineInfo {
                deprecated_year: 2000,
                disallowed_year: 2000,
                note: "Finite-field DH below 2048 bits is not FIPS-approved",
            },
            AlgorithmId::Dsa { .. } => DeadlineInfo {
                deprecated_year: 2000,
                disallowed_year: 2000,
                note: "DSA is not approved by FIPS 186-5",
            },
            // Non-NIST curves are not approved by FIPS 186-5.
            AlgorithmId::EcOther => DeadlineInfo {
                deprecated_year: 2000,
                disallowed_year: 2000,
                note: "Non-NIST curve is not FIPS-approved",
            },
            // X25519/X448 are not approved by SP 800-56A/56B or FIPS 186-5.
            AlgorithmId::X25519 | AlgorithmId::X448 => DeadlineInfo {
                deprecated_year: 2000,
                disallowed_year: 2000,
                note: "X25519/X448 are not FIPS-approved",
            },
            // ChaCha20-Poly1305 is not a FIPS-approved algorithm.
            AlgorithmId::ChaCha20Poly1305 => DeadlineInfo {
                deprecated_year: 2000,
                disallowed_year: 2000,
                note: "ChaCha20-Poly1305 is not FIPS-approved",
            },
            // Remaining families are approved (subject to module validation).
            AlgorithmId::Rsa { .. }
            | AlgorithmId::EcP256
            | AlgorithmId::EcP384
            | AlgorithmId::EcP521
            | AlgorithmId::Ed25519
            | AlgorithmId::Ed448
            | AlgorithmId::Dh { .. }
            | AlgorithmId::Aes128
            | AlgorithmId::Aes256
            | AlgorithmId::Sha256
            | AlgorithmId::Sha384
            | AlgorithmId::Sha512
            | AlgorithmId::MlKem512
            | AlgorithmId::MlKem768
            | AlgorithmId::MlKem1024
            | AlgorithmId::MlDsa44
            | AlgorithmId::MlDsa65
            | AlgorithmId::MlDsa87
            | AlgorithmId::SlhDsa { .. } => return None,
            AlgorithmId::Unknown => return None,
        })
    }

    fn status_for(&self, alg: &AlgorithmId, _current_year: u32) -> AlgorithmStatus {
        match self.deadline_for(alg) {
            // Every entry in this table is already disallowed.
            Some(_) => AlgorithmStatus::Disallowed,
            // Every known algorithm without an entry here is FIPS-approved.
            None if !matches!(alg, AlgorithmId::Unknown) => AlgorithmStatus::Approved,
            None => AlgorithmStatus::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::tables::{AlgorithmStatus, DeadlineTable};

    #[test]
    fn non_approved_algorithms_are_disallowed() {
        let table = FipsTable;
        for alg in [
            AlgorithmId::Rsa { min_bits: 1024 },
            AlgorithmId::Dh { min_bits: 1024 },
            AlgorithmId::Dsa { min_bits: 2048 },
            AlgorithmId::X25519,
            AlgorithmId::X448,
            AlgorithmId::ChaCha20Poly1305,
        ] {
            assert_eq!(
                table.status_for(&alg, 2026),
                AlgorithmStatus::Disallowed,
                "{alg:?} should not be FIPS-approved"
            );
        }
    }

    #[test]
    fn approved_algorithm_families_have_no_deadline() {
        let table = FipsTable;
        for alg in [
            AlgorithmId::Rsa { min_bits: 2048 },
            AlgorithmId::Rsa { min_bits: 4096 },
            AlgorithmId::EcP256,
            AlgorithmId::EcP384,
            AlgorithmId::EcP521,
            AlgorithmId::Ed25519,
            AlgorithmId::Ed448,
            AlgorithmId::Dh { min_bits: 2048 },
            AlgorithmId::Aes128,
            AlgorithmId::Aes256,
            AlgorithmId::Sha256,
            AlgorithmId::Sha384,
            AlgorithmId::Sha512,
            AlgorithmId::MlKem512,
            AlgorithmId::MlKem768,
            AlgorithmId::MlKem1024,
            AlgorithmId::MlDsa44,
            AlgorithmId::MlDsa65,
            AlgorithmId::MlDsa87,
            AlgorithmId::SlhDsa { level: 3 },
            AlgorithmId::Unknown,
        ] {
            assert!(table.deadline_for(&alg).is_none());
        }
    }

    #[test]
    fn fips_does_not_apply_pqc_transition_deadlines() {
        let table = FipsTable;
        // RSA-2048 is quantum-vulnerable, but it remains FIPS-approved.
        assert_eq!(
            table.status_for(&AlgorithmId::Rsa { min_bits: 2048 }, 2035),
            AlgorithmStatus::Approved
        );
    }

    #[test]
    fn unknown_status_is_unknown() {
        assert_eq!(
            FipsTable.status_for(&AlgorithmId::Unknown, 2026),
            AlgorithmStatus::Unknown
        );
    }

    #[test]
    fn table_name_is_stable() {
        assert_eq!(FipsTable.name(), "FIPS 140-3");
    }
}
