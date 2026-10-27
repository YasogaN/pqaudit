//! TLS Supported Groups registry (IANA, fetched 2026-10-21).
//!
//! Codepoints are stable, but "recommended" changes over time. Keep the table
//! ordered with PQC groups first so callers can build a preference list.
use crate::NamedGroup;

#[derive(Debug, Clone)]
pub struct GroupEntry {
    pub code_point: u16,
    pub name: &'static str,
    pub is_pqc: bool,
    pub deprecated: bool,
    pub recommended: bool,
}

impl From<&GroupEntry> for NamedGroup {
    fn from(e: &GroupEntry) -> Self {
        NamedGroup {
            code_point: e.code_point,
            name: e.name.to_string(),
            is_pqc: e.is_pqc,
        }
    }
}

pub static NAMED_GROUPS: &[GroupEntry] = &[
    // ── Post-quantum / hybrid ────────────────────────────────────────────────
    GroupEntry {
        code_point: 0x11EC,
        name: "X25519MLKEM768",
        is_pqc: true,
        deprecated: false,
        recommended: true,
    },
    GroupEntry {
        code_point: 0x11EB,
        name: "SecP256r1MLKEM768",
        is_pqc: true,
        deprecated: false,
        recommended: false,
    },
    GroupEntry {
        code_point: 0x11ED,
        name: "SecP384r1MLKEM1024",
        is_pqc: true,
        deprecated: false,
        recommended: false,
    },
    GroupEntry {
        code_point: 0x11E9,
        name: "SecP256r1MLKEM512",
        is_pqc: true,
        deprecated: false,
        recommended: false,
    },
    GroupEntry {
        code_point: 0x11EA,
        name: "MLKEM512X25519",
        is_pqc: true,
        deprecated: false,
        recommended: false,
    },
    GroupEntry {
        code_point: 0x11EE,
        name: "curveSM2MLKEM768",
        is_pqc: true,
        deprecated: false,
        recommended: false,
    },
    // Pure ML-KEM (FIPS 203). Not recommended on their own for TLS because they
    // provide no classical fallback, but they are useful for inventory.
    GroupEntry {
        code_point: 0x0200,
        name: "MLKEM512",
        is_pqc: true,
        deprecated: false,
        recommended: false,
    },
    GroupEntry {
        code_point: 0x0201,
        name: "MLKEM768",
        is_pqc: true,
        deprecated: false,
        recommended: false,
    },
    GroupEntry {
        code_point: 0x0202,
        name: "MLKEM1024",
        is_pqc: true,
        deprecated: false,
        recommended: false,
    },
    // ── Obsolete pre-standard Kyber hybrids ─────────────────────────────────
    GroupEntry {
        code_point: 0x6399,
        name: "X25519Kyber768Draft00",
        is_pqc: true,
        deprecated: true,
        recommended: false,
    },
    GroupEntry {
        code_point: 0x639A,
        name: "SecP256r1Kyber768Draft00",
        is_pqc: true,
        deprecated: true,
        recommended: false,
    },
    // ── Classical ───────────────────────────────────────────────────────────
    GroupEntry {
        code_point: 0x001D,
        name: "x25519",
        is_pqc: false,
        deprecated: false,
        recommended: true,
    },
    GroupEntry {
        code_point: 0x001E,
        name: "x448",
        is_pqc: false,
        deprecated: false,
        recommended: true,
    },
    GroupEntry {
        code_point: 0x0017,
        name: "secp256r1",
        is_pqc: false,
        deprecated: false,
        recommended: true,
    },
    GroupEntry {
        code_point: 0x0018,
        name: "secp384r1",
        is_pqc: false,
        deprecated: false,
        recommended: true,
    },
    GroupEntry {
        code_point: 0x0019,
        name: "secp521r1",
        is_pqc: false,
        deprecated: false,
        recommended: false,
    },
    GroupEntry {
        code_point: 0x0016,
        name: "secp256k1",
        is_pqc: false,
        deprecated: false,
        recommended: false,
    },
    // Finite-field DH groups (RFC 7919).
    GroupEntry {
        code_point: 0x0100,
        name: "ffdhe2048",
        is_pqc: false,
        deprecated: false,
        recommended: false,
    },
    GroupEntry {
        code_point: 0x0101,
        name: "ffdhe3072",
        is_pqc: false,
        deprecated: false,
        recommended: false,
    },
    GroupEntry {
        code_point: 0x0102,
        name: "ffdhe4096",
        is_pqc: false,
        deprecated: false,
        recommended: false,
    },
    GroupEntry {
        code_point: 0x0103,
        name: "ffdhe6144",
        is_pqc: false,
        deprecated: false,
        recommended: false,
    },
    GroupEntry {
        code_point: 0x0104,
        name: "ffdhe8192",
        is_pqc: false,
        deprecated: false,
        recommended: false,
    },
];

pub fn group_for_code_point(code_point: u16) -> Option<&'static GroupEntry> {
    NAMED_GROUPS.iter().find(|g| g.code_point == code_point)
}

pub fn named_group_for_code_point(code_point: u16) -> NamedGroup {
    match group_for_code_point(code_point) {
        Some(e) => e.into(),
        None => NamedGroup {
            code_point,
            name: format!("Unknown(0x{code_point:04x})"),
            is_pqc: false,
        },
    }
}

/// PQC groups that are still standards-track and recommended for negotiation.
pub fn recommended_pqc_groups() -> impl Iterator<Item = &'static GroupEntry> {
    NAMED_GROUPS
        .iter()
        .filter(|g| g.is_pqc && !g.deprecated && g.recommended)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_group_is_unique_and_round_trips() {
        let mut seen = std::collections::HashSet::new();
        for entry in NAMED_GROUPS {
            assert!(seen.insert(entry.code_point), "duplicate group codepoint");
            let found = group_for_code_point(entry.code_point).expect("group must be found");
            assert_eq!(found.code_point, entry.code_point);
            assert_eq!(found.name, entry.name);
            let named = named_group_for_code_point(entry.code_point);
            assert_eq!(named.code_point, entry.code_point);
            assert_eq!(named.name, entry.name);
            assert_eq!(named.is_pqc, entry.is_pqc);
        }
    }

    #[test]
    fn x25519mlkem768_is_the_recommended_pqc_group() {
        let entry = group_for_code_point(0x11EC).expect("X25519MLKEM768 must be in table");
        assert!(entry.is_pqc);
        assert!(!entry.deprecated);
        assert!(entry.recommended);
        assert_eq!(entry.name, "X25519MLKEM768");
    }

    #[test]
    fn all_current_hybrid_mlkem_groups_are_present() {
        for code_point in [0x11E9, 0x11EA, 0x11EB, 0x11EC, 0x11ED, 0x11EE] {
            let entry = group_for_code_point(code_point).expect("hybrid group missing");
            assert!(entry.is_pqc);
        }
    }

    #[test]
    fn pure_mlkem_groups_are_present() {
        for code_point in [0x0200, 0x0201, 0x0202] {
            let entry = group_for_code_point(code_point).expect("ML-KEM group missing");
            assert!(entry.is_pqc);
            assert!(!entry.deprecated);
        }
    }

    #[test]
    fn kyber_draft_groups_are_pqc_but_deprecated() {
        for code_point in [0x6399, 0x639A] {
            let entry = group_for_code_point(code_point).expect("Kyber draft group missing");
            assert!(entry.is_pqc);
            assert!(entry.deprecated);
        }
    }

    #[test]
    fn classical_group_is_not_pqc() {
        let entry = group_for_code_point(0x001D).expect("x25519 must be in table");
        assert!(!entry.is_pqc);
        assert!(entry.recommended);
    }

    #[test]
    fn unknown_group_preserves_codepoint_and_is_not_pqc() {
        let group = named_group_for_code_point(0xFEED);
        assert_eq!(group.code_point, 0xFEED);
        assert_eq!(group.name, "Unknown(0xfeed)");
        assert!(!group.is_pqc);
        assert!(group_for_code_point(0xFEED).is_none());
    }

    #[test]
    fn recommended_pqc_groups_only_returns_current_standards() {
        let names: Vec<&str> = recommended_pqc_groups().map(|g| g.name).collect();
        assert_eq!(names, vec!["X25519MLKEM768"]);
    }
}
