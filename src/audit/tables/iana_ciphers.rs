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
    // TLS 1.3
    CipherEntry { id: 0x1301, name: "TLS_AES_128_GCM_SHA256",                          strength: StrengthClass::Adequate },
    CipherEntry { id: 0x1302, name: "TLS_AES_256_GCM_SHA384",                          strength: StrengthClass::Strong   },
    CipherEntry { id: 0x1303, name: "TLS_CHACHA20_POLY1305_SHA256",                    strength: StrengthClass::Strong   },
    CipherEntry { id: 0x1304, name: "TLS_AES_128_CCM_SHA256",                          strength: StrengthClass::Adequate },
    CipherEntry { id: 0x1305, name: "TLS_AES_128_CCM_8_SHA256",                        strength: StrengthClass::Adequate },
    // TLS 1.2 common
    CipherEntry { id: 0xC02B, name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",        strength: StrengthClass::Adequate },
    CipherEntry { id: 0xC02C, name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",        strength: StrengthClass::Strong   },
    CipherEntry { id: 0xC02F, name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",          strength: StrengthClass::Adequate },
    CipherEntry { id: 0xC030, name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",          strength: StrengthClass::Strong   },
    CipherEntry { id: 0xCCA8, name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",    strength: StrengthClass::Strong   },
    CipherEntry { id: 0xCCA9, name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",  strength: StrengthClass::Strong   },
    // Weak suites
    CipherEntry { id: 0x000A, name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",                  strength: StrengthClass::Weak     },
    CipherEntry { id: 0x0005, name: "TLS_RSA_WITH_RC4_128_SHA",                       strength: StrengthClass::Weak     },
    CipherEntry { id: 0x0004, name: "TLS_RSA_WITH_RC4_128_MD5",                       strength: StrengthClass::Weak     },
];

pub fn cipher_for_id(id: u16) -> Option<&'static CipherEntry> {
    CIPHER_SUITES.iter().find(|c| c.id == id)
}
