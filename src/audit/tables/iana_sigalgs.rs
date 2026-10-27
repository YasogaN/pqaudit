//! TLS SignatureScheme registry entries (IANA, fetched 2026-10-21).
//!
//! TLS 1.2's separate SignatureAlgorithm/HashAlgorithm registries are not used
//! here; this table is for the unified TLS 1.3 SignatureScheme code points.
#[derive(Debug, Clone)]
pub struct SigAlgEntry {
    pub id: u16,
    pub name: &'static str,
    pub is_pqc: bool,
    pub recommended: bool,
}

pub static SIG_ALGS: &[SigAlgEntry] = &[
    // ── RSA PKCS#1 v1.5 ─────────────────────────────────────────────────────
    SigAlgEntry {
        id: 0x0201,
        name: "rsa_pkcs1_sha1",
        is_pqc: false,
        recommended: false,
    },
    SigAlgEntry {
        id: 0x0401,
        name: "rsa_pkcs1_sha256",
        is_pqc: false,
        recommended: true,
    },
    SigAlgEntry {
        id: 0x0501,
        name: "rsa_pkcs1_sha384",
        is_pqc: false,
        recommended: true,
    },
    SigAlgEntry {
        id: 0x0601,
        name: "rsa_pkcs1_sha512",
        is_pqc: false,
        recommended: true,
    },
    // ── ECDSA ───────────────────────────────────────────────────────────────
    SigAlgEntry {
        id: 0x0203,
        name: "ecdsa_sha1",
        is_pqc: false,
        recommended: false,
    },
    SigAlgEntry {
        id: 0x0403,
        name: "ecdsa_secp256r1_sha256",
        is_pqc: false,
        recommended: true,
    },
    SigAlgEntry {
        id: 0x0503,
        name: "ecdsa_secp384r1_sha384",
        is_pqc: false,
        recommended: true,
    },
    SigAlgEntry {
        id: 0x0603,
        name: "ecdsa_secp521r1_sha512",
        is_pqc: false,
        recommended: true,
    },
    // ── RSA-PSS ─────────────────────────────────────────────────────────────
    SigAlgEntry {
        id: 0x0804,
        name: "rsa_pss_rsae_sha256",
        is_pqc: false,
        recommended: true,
    },
    SigAlgEntry {
        id: 0x0805,
        name: "rsa_pss_rsae_sha384",
        is_pqc: false,
        recommended: true,
    },
    SigAlgEntry {
        id: 0x0806,
        name: "rsa_pss_rsae_sha512",
        is_pqc: false,
        recommended: true,
    },
    SigAlgEntry {
        id: 0x0809,
        name: "rsa_pss_pss_sha256",
        is_pqc: false,
        recommended: true,
    },
    SigAlgEntry {
        id: 0x080A,
        name: "rsa_pss_pss_sha384",
        is_pqc: false,
        recommended: true,
    },
    SigAlgEntry {
        id: 0x080B,
        name: "rsa_pss_pss_sha512",
        is_pqc: false,
        recommended: true,
    },
    // ── EdDSA ───────────────────────────────────────────────────────────────
    SigAlgEntry {
        id: 0x0807,
        name: "ed25519",
        is_pqc: false,
        recommended: true,
    },
    SigAlgEntry {
        id: 0x0808,
        name: "ed448",
        is_pqc: false,
        recommended: true,
    },
    // ── ML-DSA (FIPS 204, draft-ietf-tls-mldsa) ─────────────────────────────
    SigAlgEntry {
        id: 0x0904,
        name: "mldsa44",
        is_pqc: true,
        recommended: false,
    },
    SigAlgEntry {
        id: 0x0905,
        name: "mldsa65",
        is_pqc: true,
        recommended: false,
    },
    SigAlgEntry {
        id: 0x0906,
        name: "mldsa87",
        is_pqc: true,
        recommended: false,
    },
    // ── SLH-DSA (FIPS 205, draft-reddy-tls-slhdsa) ──────────────────────────
    SigAlgEntry {
        id: 0x0911,
        name: "slhdsa_sha2_128s",
        is_pqc: true,
        recommended: false,
    },
    SigAlgEntry {
        id: 0x0912,
        name: "slhdsa_sha2_128f",
        is_pqc: true,
        recommended: false,
    },
    SigAlgEntry {
        id: 0x0913,
        name: "slhdsa_sha2_192s",
        is_pqc: true,
        recommended: false,
    },
    SigAlgEntry {
        id: 0x0914,
        name: "slhdsa_sha2_192f",
        is_pqc: true,
        recommended: false,
    },
    SigAlgEntry {
        id: 0x0915,
        name: "slhdsa_sha2_256s",
        is_pqc: true,
        recommended: false,
    },
    SigAlgEntry {
        id: 0x0916,
        name: "slhdsa_sha2_256f",
        is_pqc: true,
        recommended: false,
    },
    SigAlgEntry {
        id: 0x0917,
        name: "slhdsa_shake_128s",
        is_pqc: true,
        recommended: false,
    },
    SigAlgEntry {
        id: 0x0918,
        name: "slhdsa_shake_128f",
        is_pqc: true,
        recommended: false,
    },
    SigAlgEntry {
        id: 0x0919,
        name: "slhdsa_shake_192s",
        is_pqc: true,
        recommended: false,
    },
    SigAlgEntry {
        id: 0x091A,
        name: "slhdsa_shake_192f",
        is_pqc: true,
        recommended: false,
    },
    SigAlgEntry {
        id: 0x091B,
        name: "slhdsa_shake_256s",
        is_pqc: true,
        recommended: false,
    },
    SigAlgEntry {
        id: 0x091C,
        name: "slhdsa_shake_256f",
        is_pqc: true,
        recommended: false,
    },
];

pub fn sigalg_for_id(id: u16) -> Option<&'static SigAlgEntry> {
    SIG_ALGS.iter().find(|s| s.id == id)
}

pub fn sigalg_name(id: u16) -> String {
    match sigalg_for_id(id) {
        Some(s) => s.name.to_string(),
        None => format!("0x{id:04X}"),
    }
}

pub fn is_pqc_sigalg(id: u16) -> bool {
    sigalg_for_id(id).is_some_and(|s| s.is_pqc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_sigalg_is_unique_and_round_trips() {
        let mut seen = std::collections::HashSet::new();
        for entry in SIG_ALGS {
            assert!(seen.insert(entry.id), "duplicate signature scheme id");
            assert_eq!(sigalg_for_id(entry.id).unwrap().name, entry.name);
            assert_eq!(sigalg_name(entry.id), entry.name);
        }
    }

    #[test]
    fn current_ml_dsa_codepoints_are_correct() {
        assert_eq!(sigalg_name(0x0904), "mldsa44");
        assert_eq!(sigalg_name(0x0905), "mldsa65");
        assert_eq!(sigalg_name(0x0906), "mldsa87");
        assert!(is_pqc_sigalg(0x0904));
        assert!(is_pqc_sigalg(0x0906));
    }

    #[test]
    fn slh_dsa_schemes_are_pqc() {
        for id in 0x0911..=0x091C {
            assert!(is_pqc_sigalg(id), "0x{id:04X} should be PQC");
        }
    }

    #[test]
    fn classical_schemes_are_not_pqc() {
        for id in [0x0401, 0x0403, 0x0804, 0x0807, 0x0809] {
            assert!(!is_pqc_sigalg(id));
        }
    }

    #[test]
    fn unknown_sigalg_falls_back_to_hex() {
        assert_eq!(sigalg_name(0xFEED), "0xFEED");
        assert!(sigalg_for_id(0xFEED).is_none());
        assert!(!is_pqc_sigalg(0xFEED));
    }
}
