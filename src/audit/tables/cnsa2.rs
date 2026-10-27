//! NSA CNSA 2.0 / CNSSP 15.
//!
//! Timelines (from the CNSA 2.0 FAQ and the 2024 CNSSP 15 update):
//! - 2025: software/firmware signing, web browsers, servers and cloud services
//!   should support and prefer CNSA 2.0.
//! - 2026: traditional networking equipment should support and prefer CNSA 2.0.
//! - 2027-01-01: all new NSS acquisitions must be CNSA 2.0 capable.
//! - 2030-12-31: software/firmware signing and networking equipment must use
//!   CNSA 2.0 exclusively.
//! - 2033-12-31: all other NSS (including web servers/cloud) must use CNSA 2.0
//!   exclusively.
//!
//! This tool scans TLS servers, so the practical exclusive-use deadline encoded
//! here is 2033. Operators of networking equipment should treat 2030 as their
//! deadline instead.
use crate::audit::tables::{DeadlineInfo, DeadlineTable};
use crate::AlgorithmId;

pub struct Cnsa2Table;

const CLASSICAL_NOTE: &str =
    "CNSA 2.0: new NSS acquisitions 2027; exclusive 2030 (networking) / 2033 (servers)";

impl DeadlineTable for Cnsa2Table {
    fn name(&self) -> &'static str {
        "NSA CNSA 2.0"
    }

    fn deadline_for(&self, alg: &AlgorithmId) -> Option<DeadlineInfo> {
        Some(match alg {
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
            AlgorithmId::Dsa { .. } => DeadlineInfo {
                deprecated_year: 2000,
                disallowed_year: 2000,
                note: "DSA is not CNSA 2.0 approved",
            },
            // CNSA 1.0 public-key algorithms. CNSA 2.0 replaces them wholesale.
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
                deprecated_year: 2027,
                disallowed_year: 2033,
                note: CLASSICAL_NOTE,
            },
            // Only AES-256 is approved.
            AlgorithmId::Aes128 => DeadlineInfo {
                deprecated_year: 2024,
                disallowed_year: 2024,
                note: "CNSA 2.0 requires AES-256",
            },
            // Only SHA-384/SHA-512 are approved for general use.
            AlgorithmId::Sha256 => DeadlineInfo {
                deprecated_year: 2024,
                disallowed_year: 2024,
                note: "CNSA 2.0 requires SHA-384 or SHA-512",
            },
            // ML-KEM-1024 is the only approved parameter set.
            AlgorithmId::MlKem512 | AlgorithmId::MlKem768 => DeadlineInfo {
                deprecated_year: 2024,
                disallowed_year: 2024,
                note: "CNSA 2.0 requires ML-KEM-1024",
            },
            // ML-DSA-87 is the only approved parameter set.
            AlgorithmId::MlDsa44 | AlgorithmId::MlDsa65 => DeadlineInfo {
                deprecated_year: 2024,
                disallowed_year: 2024,
                note: "CNSA 2.0 requires ML-DSA-87",
            },
            // CNSA 2.0 uses LMS/XMSS for stateful hash-based signatures.
            AlgorithmId::SlhDsa { .. } => DeadlineInfo {
                deprecated_year: 2024,
                disallowed_year: 2024,
                note: "CNSA 2.0 does not approve SLH-DSA; use LMS/XMSS",
            },
            AlgorithmId::ChaCha20Poly1305 => DeadlineInfo {
                deprecated_year: 2024,
                disallowed_year: 2024,
                note: "CNSA 2.0 requires AES-256",
            },
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::tables::{AlgorithmStatus, DeadlineTable};

    fn info(alg: AlgorithmId) -> DeadlineInfo {
        Cnsa2Table
            .deadline_for(&alg)
            .expect("algorithm must have a CNSA 2.0 deadline")
    }

    #[test]
    fn classical_algorithms_have_2027_and_2033_milestones() {
        for alg in [
            AlgorithmId::Rsa { min_bits: 3072 },
            AlgorithmId::EcP256,
            AlgorithmId::EcP384,
            AlgorithmId::EcP521,
            AlgorithmId::EcOther,
            AlgorithmId::X25519,
            AlgorithmId::X448,
            AlgorithmId::Ed25519,
            AlgorithmId::Ed448,
            AlgorithmId::Dh { min_bits: 3072 },
        ] {
            let d = info(alg);
            assert_eq!(d.deprecated_year, 2027);
            assert_eq!(d.disallowed_year, 2033);
        }
    }

    #[test]
    fn small_rsa_and_dsa_are_already_disallowed() {
        assert_eq!(
            info(AlgorithmId::Rsa { min_bits: 1024 }).disallowed_year,
            2000
        );
        assert_eq!(
            info(AlgorithmId::Dh { min_bits: 1024 }).disallowed_year,
            2000
        );
        assert_eq!(
            info(AlgorithmId::Dsa { min_bits: 2048 }).disallowed_year,
            2000
        );
    }

    #[test]
    fn aes128_and_sha256_are_disallowed() {
        assert_eq!(info(AlgorithmId::Aes128).disallowed_year, 2024);
        assert_eq!(info(AlgorithmId::Sha256).disallowed_year, 2024);
    }

    #[test]
    fn only_top_parameter_sets_are_approved() {
        let table = Cnsa2Table;
        assert_eq!(
            table.status_for(&AlgorithmId::MlKem1024, 2026),
            AlgorithmStatus::Approved
        );
        assert_eq!(
            table.status_for(&AlgorithmId::MlDsa87, 2026),
            AlgorithmStatus::Approved
        );
        assert_eq!(
            table.status_for(&AlgorithmId::MlKem768, 2026),
            AlgorithmStatus::Disallowed
        );
        assert_eq!(
            table.status_for(&AlgorithmId::MlDsa65, 2026),
            AlgorithmStatus::Disallowed
        );
    }

    #[test]
    fn slh_dsa_and_chacha_are_disallowed() {
        assert_eq!(info(AlgorithmId::SlhDsa { level: 5 }).disallowed_year, 2024);
        assert_eq!(info(AlgorithmId::ChaCha20Poly1305).disallowed_year, 2024);
    }

    #[test]
    fn approved_symmetric_algorithms_have_no_deadline() {
        let table = Cnsa2Table;
        for alg in [
            AlgorithmId::Aes256,
            AlgorithmId::Sha384,
            AlgorithmId::Sha512,
        ] {
            assert!(table.deadline_for(&alg).is_none());
            assert_eq!(table.status_for(&alg, 2026), AlgorithmStatus::Unknown);
        }
    }

    #[test]
    fn classical_status_transitions() {
        let table = Cnsa2Table;
        assert_eq!(
            table.status_for(&AlgorithmId::EcP384, 2026),
            AlgorithmStatus::Approved
        );
        assert_eq!(
            table.status_for(&AlgorithmId::EcP384, 2027),
            AlgorithmStatus::Deprecated
        );
        assert_eq!(
            table.status_for(&AlgorithmId::EcP384, 2033),
            AlgorithmStatus::Disallowed
        );
    }

    #[test]
    fn unknown_algorithm_is_unknown() {
        let table = Cnsa2Table;
        assert!(table.deadline_for(&AlgorithmId::Unknown).is_none());
        assert_eq!(
            table.status_for(&AlgorithmId::Unknown, 2026),
            AlgorithmStatus::Unknown
        );
    }

    #[test]
    fn table_name_is_stable() {
        assert_eq!(Cnsa2Table.name(), "NSA CNSA 2.0");
    }
}
