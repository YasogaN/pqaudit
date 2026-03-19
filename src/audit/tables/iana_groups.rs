use crate::NamedGroup;

#[derive(Debug, Clone)]
pub struct GroupEntry {
    pub code_point: u16,
    pub name: &'static str,
    pub is_pqc: bool,
    pub deprecated: bool,
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
    // PQC hybrid groups
    GroupEntry {
        code_point: 0x11EB,
        name: "SecP256r1MLKEM768",
        is_pqc: true,
        deprecated: false,
    },
    GroupEntry {
        code_point: 0x11EC,
        name: "X25519MLKEM768",
        is_pqc: true,
        deprecated: false,
    },
    GroupEntry {
        code_point: 0x11ED,
        name: "SecP384r1MLKEM1024",
        is_pqc: true,
        deprecated: false,
    },
    // Pure ML-KEM groups
    GroupEntry {
        code_point: 0x0200,
        name: "ML-KEM-512",
        is_pqc: true,
        deprecated: false,
    },
    GroupEntry {
        code_point: 0x0201,
        name: "ML-KEM-768",
        is_pqc: true,
        deprecated: false,
    },
    GroupEntry {
        code_point: 0x0202,
        name: "ML-KEM-1024",
        is_pqc: true,
        deprecated: false,
    },
    // Deprecated pre-FIPS draft
    GroupEntry {
        code_point: 0x6399,
        name: "X25519Kyber768Draft00",
        is_pqc: true,
        deprecated: true,
    },
    // Classical groups
    GroupEntry {
        code_point: 0x001D,
        name: "x25519",
        is_pqc: false,
        deprecated: false,
    },
    GroupEntry {
        code_point: 0x001E,
        name: "x448",
        is_pqc: false,
        deprecated: false,
    },
    GroupEntry {
        code_point: 0x0017,
        name: "secp256r1",
        is_pqc: false,
        deprecated: false,
    },
    GroupEntry {
        code_point: 0x0018,
        name: "secp384r1",
        is_pqc: false,
        deprecated: false,
    },
    GroupEntry {
        code_point: 0x0019,
        name: "secp521r1",
        is_pqc: false,
        deprecated: false,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519mlkem768_is_pqc() {
        let entry = group_for_code_point(0x11EC).expect("X25519MLKEM768 must be in table");
        assert!(entry.is_pqc);
        assert_eq!(entry.name, "X25519MLKEM768");
    }

    #[test]
    fn kyber_draft_is_pqc_but_deprecated() {
        let entry = group_for_code_point(0x6399).expect("X25519Kyber768Draft00 must be in table");
        assert!(entry.is_pqc);
        assert!(entry.deprecated);
    }

    #[test]
    fn classical_group_is_not_pqc() {
        let entry = group_for_code_point(0x001D).expect("x25519 must be in table");
        assert!(!entry.is_pqc);
    }
}
