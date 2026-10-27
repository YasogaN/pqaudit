//! NIST IR 8547 (Initial Public Draft, November 2024).
//!
//! Table 2 (signatures) and Table 4 (key establishment) both specify:
//! - 112-bit security strength: deprecated after 2030, disallowed after 2035.
//! - >=128-bit security strength: disallowed after 2035.
//!
//! The draft has not been finalised; keep these values centralised here so a
//! final publication only requires changing this table.
use crate::audit::tables::{DeadlineInfo, DeadlineTable};
use crate::AlgorithmId;

pub struct NistIr8547Table;

const IPD_NOTE: &str = "NIST IR 8547 IPD: deprecated after 2030, disallowed after 2035";

impl DeadlineTable for NistIr8547Table {
    fn name(&self) -> &'static str {
        "NIST IR 8547 (IPD)"
    }

    fn deadline_for(&self, alg: &AlgorithmId) -> Option<DeadlineInfo> {
        Some(match alg {
            // Smaller parameter sets are already outside NIST policy.
            AlgorithmId::Rsa { min_bits } if *min_bits < 2048 => DeadlineInfo {
                deprecated_year: 2000,
                disallowed_year: 2000,
                note: "RSA below 2048 bits is already disallowed",
            },
            AlgorithmId::Dh { min_bits } if *min_bits < 2048 => DeadlineInfo {
                deprecated_year: 2000,
                disallowed_year: 2000,
                note: "Finite-field DH below 2048 bits is already disallowed",
            },
            // FIPS 186-5 removed DSA.
            AlgorithmId::Dsa { .. } => DeadlineInfo {
                deprecated_year: 2000,
                disallowed_year: 2000,
                note: "DSA is disallowed by FIPS 186-5",
            },
            // 112-bit classical algorithms: deprecation starts after 2030.
            AlgorithmId::Rsa { min_bits } if *min_bits <= 2048 => DeadlineInfo {
                deprecated_year: 2031,
                disallowed_year: 2035,
                note: IPD_NOTE,
            },
            AlgorithmId::Dh { min_bits } if *min_bits <= 2048 => DeadlineInfo {
                deprecated_year: 2031,
                disallowed_year: 2035,
                note: IPD_NOTE,
            },
            // >=128-bit classical algorithms: disallowed after 2035, without a
            // separate deprecation milestone in the IPD tables.
            AlgorithmId::Rsa { .. }
            | AlgorithmId::EcP256
            | AlgorithmId::EcP384
            | AlgorithmId::EcP521
            | AlgorithmId::EcOther
            | AlgorithmId::X25519
            | AlgorithmId::X448
            | AlgorithmId::Ed25519
            | AlgorithmId::Ed448
            | AlgorithmId::Dh { .. } => DeadlineInfo {
                deprecated_year: 2035,
                disallowed_year: 2035,
                note: IPD_NOTE,
            },
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::tables::AlgorithmStatus;

    fn info(alg: AlgorithmId) -> DeadlineInfo {
        NistIr8547Table
            .deadline_for(&alg)
            .expect("algorithm must have a deadline")
    }

    #[test]
    fn rsa_112_bit_is_deprecated_after_2030_and_disallowed_after_2035() {
        let d = info(AlgorithmId::Rsa { min_bits: 2048 });
        assert_eq!(d.deprecated_year, 2031);
        assert_eq!(d.disallowed_year, 2035);
    }

    #[test]
    fn rsa_128_bit_has_no_early_deprecation() {
        let d = info(AlgorithmId::Rsa { min_bits: 3072 });
        assert_eq!(d.deprecated_year, 2035);
        assert_eq!(d.disallowed_year, 2035);
    }

    #[test]
    fn dh_112_bit_is_deprecated_after_2030() {
        let d = info(AlgorithmId::Dh { min_bits: 2048 });
        assert_eq!(d.deprecated_year, 2031);
        assert_eq!(d.disallowed_year, 2035);
    }

    #[test]
    fn dh_128_bit_is_disallowed_after_2035() {
        let d = info(AlgorithmId::Dh { min_bits: 3072 });
        assert_eq!(d.disallowed_year, 2035);
    }

    #[test]
    fn small_rsa_and_dh_are_already_disallowed() {
        assert_eq!(
            info(AlgorithmId::Rsa { min_bits: 1024 }).disallowed_year,
            2000
        );
        assert_eq!(
            info(AlgorithmId::Dh { min_bits: 1024 }).disallowed_year,
            2000
        );
    }

    #[test]
    fn dsa_is_disallowed() {
        assert_eq!(
            info(AlgorithmId::Dsa { min_bits: 2048 }).disallowed_year,
            2000
        );
    }

    #[test]
    fn every_classical_family_has_a_deadline() {
        for alg in [
            AlgorithmId::EcP256,
            AlgorithmId::EcP384,
            AlgorithmId::EcP521,
            AlgorithmId::EcOther,
            AlgorithmId::X25519,
            AlgorithmId::X448,
            AlgorithmId::Ed25519,
            AlgorithmId::Ed448,
        ] {
            assert_eq!(info(alg).disallowed_year, 2035);
        }
    }

    #[test]
    fn rsa_2048_is_approved_in_2026_then_deprecated_in_2031() {
        let table = NistIr8547Table;
        assert_eq!(
            table.status_for(&AlgorithmId::Rsa { min_bits: 2048 }, 2026),
            AlgorithmStatus::Approved
        );
        assert_eq!(
            table.status_for(&AlgorithmId::Rsa { min_bits: 2048 }, 2031),
            AlgorithmStatus::Deprecated
        );
        assert_eq!(
            table.status_for(&AlgorithmId::Rsa { min_bits: 2048 }, 2035),
            AlgorithmStatus::Disallowed
        );
    }

    #[test]
    fn p256_is_approved_until_2035() {
        let table = NistIr8547Table;
        assert_eq!(
            table.status_for(&AlgorithmId::EcP256, 2034),
            AlgorithmStatus::Approved
        );
        assert_eq!(
            table.status_for(&AlgorithmId::EcP256, 2035),
            AlgorithmStatus::Disallowed
        );
    }

    #[test]
    fn pqc_algorithms_are_approved_at_any_year() {
        let table = NistIr8547Table;
        for year in [2024, 2030, 2035, 2100] {
            assert_eq!(
                table.status_for(&AlgorithmId::MlKem768, year),
                AlgorithmStatus::Approved
            );
            assert_eq!(
                table.status_for(&AlgorithmId::MlDsa87, year),
                AlgorithmStatus::Approved
            );
            assert_eq!(
                table.status_for(&AlgorithmId::SlhDsa { level: 5 }, year),
                AlgorithmStatus::Approved
            );
        }
    }

    #[test]
    fn unknown_algorithm_has_no_deadline_and_unknown_status() {
        let table = NistIr8547Table;
        assert!(table.deadline_for(&AlgorithmId::Unknown).is_none());
        assert_eq!(
            table.status_for(&AlgorithmId::Unknown, 2026),
            AlgorithmStatus::Unknown
        );
    }

    #[test]
    fn symmetric_algorithms_have_no_pqc_deadline() {
        let table = NistIr8547Table;
        for alg in [
            AlgorithmId::Aes128,
            AlgorithmId::Aes256,
            AlgorithmId::Sha256,
            AlgorithmId::Sha384,
            AlgorithmId::Sha512,
            AlgorithmId::ChaCha20Poly1305,
        ] {
            assert!(table.deadline_for(&alg).is_none());
            assert_eq!(table.status_for(&alg, 2026), AlgorithmStatus::Unknown);
        }
    }

    #[test]
    fn table_name_is_stable() {
        assert_eq!(NistIr8547Table.name(), "NIST IR 8547 (IPD)");
    }
}
