//! TLS cipher suite registry entries used by the prober and reporters.
//!
//! This is intentionally a curated subset: every suite that `cipher_enum`
//! actively offers, plus the legacy suites we want to flag when a server
//! selects them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrengthClass {
    Strong,
    Adequate,
    Weak,
}

#[derive(Debug, Clone)]
pub struct CipherEntry {
    pub id: u16,
    pub name: &'static str,
    pub strength: StrengthClass,
}

pub static CIPHER_SUITES: &[CipherEntry] = &[
    // ── TLS 1.3 ─────────────────────────────────────────────────────────────
    CipherEntry {
        id: 0x1301,
        name: "TLS_AES_128_GCM_SHA256",
        strength: StrengthClass::Adequate,
    },
    CipherEntry {
        id: 0x1302,
        name: "TLS_AES_256_GCM_SHA384",
        strength: StrengthClass::Strong,
    },
    CipherEntry {
        id: 0x1303,
        name: "TLS_CHACHA20_POLY1305_SHA256",
        strength: StrengthClass::Strong,
    },
    CipherEntry {
        id: 0x1304,
        name: "TLS_AES_128_CCM_SHA256",
        strength: StrengthClass::Adequate,
    },
    CipherEntry {
        id: 0x1305,
        name: "TLS_AES_128_CCM_8_SHA256",
        strength: StrengthClass::Adequate,
    },
    // ── TLS 1.2 ECDHE-GCM ───────────────────────────────────────────────────
    CipherEntry {
        id: 0xC02B,
        name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        strength: StrengthClass::Adequate,
    },
    CipherEntry {
        id: 0xC02C,
        name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        strength: StrengthClass::Strong,
    },
    CipherEntry {
        id: 0xC02F,
        name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        strength: StrengthClass::Adequate,
    },
    CipherEntry {
        id: 0xC030,
        name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        strength: StrengthClass::Strong,
    },
    CipherEntry {
        id: 0xCCA8,
        name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        strength: StrengthClass::Strong,
    },
    CipherEntry {
        id: 0xCCA9,
        name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        strength: StrengthClass::Strong,
    },
    // ── TLS 1.2 ECDHE-CBC ───────────────────────────────────────────────────
    CipherEntry {
        id: 0xC009,
        name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        strength: StrengthClass::Weak,
    },
    CipherEntry {
        id: 0xC00A,
        name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        strength: StrengthClass::Weak,
    },
    CipherEntry {
        id: 0xC013,
        name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        strength: StrengthClass::Weak,
    },
    CipherEntry {
        id: 0xC014,
        name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        strength: StrengthClass::Weak,
    },
    CipherEntry {
        id: 0xC023,
        name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        strength: StrengthClass::Weak,
    },
    CipherEntry {
        id: 0xC024,
        name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        strength: StrengthClass::Weak,
    },
    CipherEntry {
        id: 0xC027,
        name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        strength: StrengthClass::Weak,
    },
    CipherEntry {
        id: 0xC028,
        name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        strength: StrengthClass::Weak,
    },
    // ── TLS 1.2 DHE-GCM ─────────────────────────────────────────────────────
    CipherEntry {
        id: 0x009E,
        name: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        strength: StrengthClass::Adequate,
    },
    CipherEntry {
        id: 0x009F,
        name: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        strength: StrengthClass::Strong,
    },
    // ── TLS 1.2 RSA / DHE-CBC ───────────────────────────────────────────────
    CipherEntry {
        id: 0x0033,
        name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        strength: StrengthClass::Weak,
    },
    CipherEntry {
        id: 0x0039,
        name: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        strength: StrengthClass::Weak,
    },
    CipherEntry {
        id: 0x0067,
        name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        strength: StrengthClass::Weak,
    },
    CipherEntry {
        id: 0x006B,
        name: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        strength: StrengthClass::Weak,
    },
    CipherEntry {
        id: 0x009C,
        name: "TLS_RSA_WITH_AES_128_GCM_SHA256",
        strength: StrengthClass::Adequate,
    },
    CipherEntry {
        id: 0x009D,
        name: "TLS_RSA_WITH_AES_256_GCM_SHA384",
        strength: StrengthClass::Strong,
    },
    CipherEntry {
        id: 0x003C,
        name: "TLS_RSA_WITH_AES_128_CBC_SHA256",
        strength: StrengthClass::Weak,
    },
    CipherEntry {
        id: 0x003D,
        name: "TLS_RSA_WITH_AES_256_CBC_SHA256",
        strength: StrengthClass::Weak,
    },
    CipherEntry {
        id: 0x002F,
        name: "TLS_RSA_WITH_AES_128_CBC_SHA",
        strength: StrengthClass::Weak,
    },
    CipherEntry {
        id: 0x0035,
        name: "TLS_RSA_WITH_AES_256_CBC_SHA",
        strength: StrengthClass::Weak,
    },
    // ── Obsolete / broken ───────────────────────────────────────────────────
    CipherEntry {
        id: 0x000A,
        name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        strength: StrengthClass::Weak,
    },
    CipherEntry {
        id: 0x0005,
        name: "TLS_RSA_WITH_RC4_128_SHA",
        strength: StrengthClass::Weak,
    },
    CipherEntry {
        id: 0x0004,
        name: "TLS_RSA_WITH_RC4_128_MD5",
        strength: StrengthClass::Weak,
    },
    CipherEntry {
        id: 0x0000,
        name: "TLS_NULL_WITH_NULL_NULL",
        strength: StrengthClass::Weak,
    },
];

pub fn cipher_for_id(id: u16) -> Option<&'static CipherEntry> {
    CIPHER_SUITES.iter().find(|c| c.id == id)
}

/// IANA name for a cipher suite, falling back to its hex value.
pub fn cipher_name(id: u16) -> String {
    match cipher_for_id(id) {
        Some(c) => c.name.to_string(),
        None => format!("0x{id:04X}"),
    }
}

pub fn strength_for_id(id: u16) -> Option<&'static StrengthClass> {
    cipher_for_id(id).map(|c| &c.strength)
}

pub fn is_weak_cipher(id: u16) -> bool {
    matches!(strength_for_id(id), Some(StrengthClass::Weak))
}

pub fn is_tls13_suite(id: u16) -> bool {
    (0x1301..=0x1305).contains(&id)
}

/// TLS 1.3 cipher suites in the order they should be offered.
pub fn tls13_suites() -> impl Iterator<Item = u16> {
    CIPHER_SUITES
        .iter()
        .filter(|c| is_tls13_suite(c.id))
        .map(|c| c.id)
}

/// TLS 1.2 and older cipher suites in the order they should be offered.
pub fn tls12_suites() -> impl Iterator<Item = u16> {
    CIPHER_SUITES
        .iter()
        .filter(|c| !is_tls13_suite(c.id))
        .map(|c| c.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_cipher_is_unique_and_round_trips() {
        let mut seen = std::collections::HashSet::new();
        for entry in CIPHER_SUITES {
            assert!(seen.insert(entry.id), "duplicate cipher id");
            assert_eq!(cipher_for_id(entry.id).unwrap().name, entry.name);
            assert_eq!(cipher_name(entry.id), entry.name);
        }
    }

    #[test]
    fn known_ids_have_expected_strength() {
        assert_eq!(strength_for_id(0x1302), Some(&StrengthClass::Strong));
        assert_eq!(strength_for_id(0x1301), Some(&StrengthClass::Adequate));
        assert_eq!(strength_for_id(0x000A), Some(&StrengthClass::Weak));
        assert_eq!(strength_for_id(0xFFFF), None);
    }

    #[test]
    fn weak_cipher_predicate_covers_legacy_suites() {
        for id in [0x0000, 0x0004, 0x0005, 0x000A, 0x002F, 0xC013] {
            assert!(is_weak_cipher(id), "0x{id:04X} should be weak");
        }
        assert!(!is_weak_cipher(0x1302));
        assert!(!is_weak_cipher(0xFFFF));
    }

    #[test]
    fn tls13_suite_detection_is_bounded() {
        for id in 0x1301..=0x1305 {
            assert!(is_tls13_suite(id));
        }
        assert!(!is_tls13_suite(0x1300));
        assert!(!is_tls13_suite(0x1306));
        assert!(!is_tls13_suite(0xC02F));
    }

    #[test]
    fn suite_iterators_partition_the_table() {
        let tls13: Vec<u16> = tls13_suites().collect();
        let tls12: Vec<u16> = tls12_suites().collect();
        assert_eq!(tls13.len() + tls12.len(), CIPHER_SUITES.len());
        assert!(tls13.iter().all(|&id| is_tls13_suite(id)));
        assert!(tls12.iter().all(|&id| !is_tls13_suite(id)));
    }

    #[test]
    fn unknown_cipher_name_falls_back_to_hex() {
        assert_eq!(cipher_name(0xBEEF), "0xBEEF");
    }
}
