#[derive(Debug, Clone)]
pub struct SigAlgEntry {
    pub id: u16,
    pub name: &'static str,
}

pub static SIG_ALGS: &[SigAlgEntry] = &[
    SigAlgEntry {
        id: 0x0401,
        name: "rsa_pkcs1_sha256",
    },
    SigAlgEntry {
        id: 0x0501,
        name: "rsa_pkcs1_sha384",
    },
    SigAlgEntry {
        id: 0x0601,
        name: "rsa_pkcs1_sha512",
    },
    SigAlgEntry {
        id: 0x0403,
        name: "ecdsa_secp256r1_sha256",
    },
    SigAlgEntry {
        id: 0x0503,
        name: "ecdsa_secp384r1_sha384",
    },
    SigAlgEntry {
        id: 0x0603,
        name: "ecdsa_secp521r1_sha512",
    },
    SigAlgEntry {
        id: 0x0807,
        name: "ed25519",
    },
    SigAlgEntry {
        id: 0x0808,
        name: "ed448",
    },
    SigAlgEntry {
        id: 0x0809,
        name: "rsa_pss_pss_sha256",
    },
    SigAlgEntry {
        id: 0x080A,
        name: "rsa_pss_pss_sha384",
    },
    SigAlgEntry {
        id: 0x080B,
        name: "rsa_pss_pss_sha512",
    },
    // ML-DSA signature algorithms (FIPS 204)
    SigAlgEntry {
        id: 0x0905,
        name: "mldsa44",
    },
    SigAlgEntry {
        id: 0x0906,
        name: "mldsa65",
    },
    SigAlgEntry {
        id: 0x0907,
        name: "mldsa87",
    },
];

pub fn sigalg_for_id(id: u16) -> Option<&'static SigAlgEntry> {
    SIG_ALGS.iter().find(|s| s.id == id)
}
