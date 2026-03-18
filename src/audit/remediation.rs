use crate::audit::findings::FindingKind;

pub struct Remediation {
    pub text: String,
    pub config_snippets: Vec<(&'static str, String)>, // (platform, snippet)
}

pub fn remediation_for(kind: &FindingKind) -> Remediation {
    match kind {
        FindingKind::ClassicalKeyExchangeOnly { .. } => Remediation {
            text: "Configure the server to support X25519MLKEM768 key exchange. \
                   This requires a TLS library with ML-KEM support (OpenSSL 3.2+, \
                   BoringSSL, or rustls with aws-lc-rs).".into(),
            config_snippets: vec![
                ("nginx", "ssl_ecdh_curve X25519MLKEM768:X25519;".into()),
                ("caddy", "curves x25519mlkem768 x25519".into()),
                ("openssl", "openssl.conf: Groups = X25519MLKEM768:X25519".into()),
                ("go", "tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}".into()),
                ("java", "jdk.tls.namedGroups=x25519_mlkem768, x25519".into()),
            ],
        },

        FindingKind::HybridKeyExchangeHrrRequired { .. } => Remediation {
            text: "The server requires a HelloRetryRequest (HRR) for the hybrid PQC group. \
                   This causes an extra round trip. Prefer X25519MLKEM768 which is supported \
                   without HRR by most modern TLS stacks.".into(),
            config_snippets: vec![
                ("nginx", "ssl_ecdh_curve X25519MLKEM768:X25519;".into()),
            ],
        },

        FindingKind::DeprecatedPqcDraftCodepoint { code_point } => Remediation {
            text: format!(
                "The server negotiated a deprecated draft PQC code point (0x{:04X}). \
                 This is not the NIST-standardized ML-KEM. Upgrade to a TLS library \
                 that supports the final FIPS 203 code points (X25519MLKEM768 = 0x11EC).",
                code_point
            ),
            config_snippets: vec![],
        },

        FindingKind::WeakSymmetricCipher { suite } => Remediation {
            text: format!(
                "The cipher suite '{}' uses weak or deprecated symmetric encryption. \
                 Disable this cipher and prefer TLS_AES_256_GCM_SHA384 or \
                 TLS_AES_128_GCM_SHA256.",
                suite.name
            ),
            config_snippets: vec![
                ("nginx", "ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256;".into()),
                ("openssl", "openssl.conf: CipherString = TLS_AES_256_GCM_SHA384".into()),
            ],
        },

        FindingKind::ClassicalCertificate { deadline, .. } => Remediation {
            text: format!(
                "This certificate uses a classical (pre-quantum) key algorithm that will be \
                 disallowed after {}. Plan to replace with a PQC certificate (ML-DSA / \
                 FIPS 204) before the deadline.",
                deadline
            ),
            config_snippets: vec![],
        },

        FindingKind::DowngradeAccepted => Remediation {
            text: "The server accepted a TLS 1.2 or lower connection when TLS 1.3 is available. \
                   Disable TLS 1.2 or configure a strict minimum version.".into(),
            config_snippets: vec![
                ("nginx", "ssl_protocols TLSv1.3;".into()),
                ("caddy", "protocols tls1.3".into()),
                ("openssl", "openssl.conf: MinProtocol = TLSv1.3".into()),
            ],
        },

        FindingKind::TlsVersionInsufficient { max_version } => Remediation {
            text: format!(
                "The server's maximum TLS version is {:?}, which is insufficient for \
                 PQC key exchange. TLS 1.3 is required for ML-KEM hybrid groups.",
                max_version
            ),
            config_snippets: vec![
                ("nginx", "ssl_protocols TLSv1.3;".into()),
                ("caddy", "protocols tls1.3".into()),
            ],
        },

        FindingKind::CertExpiresAfterDeadline { expiry, deadline, .. } => Remediation {
            text: format!(
                "This certificate expires on {} which is after the algorithm disallowance \
                 deadline of {}. The certificate will need to be replaced with a PQC \
                 certificate before the deadline.",
                expiry, deadline
            ),
            config_snippets: vec![],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NamedGroup, TlsVersion, CipherSuite};
    use crate::audit::findings::FindingKind;

    #[test]
    fn classical_key_exchange_has_nginx_snippet() {
        let r = remediation_for(&FindingKind::ClassicalKeyExchangeOnly {
            group: NamedGroup { code_point: 0x001D, name: "x25519".into(), is_pqc: false },
        });
        assert!(r.config_snippets.iter().any(|(platform, _)| *platform == "nginx"));
        assert!(r.text.contains("X25519MLKEM768"));
    }

    #[test]
    fn all_finding_kinds_return_non_empty_text() {
        use crate::{KeyInfo, ChainPosition, AlgorithmId};
        use chrono::NaiveDate;
        let kinds = vec![
            FindingKind::ClassicalKeyExchangeOnly {
                group: NamedGroup { code_point: 0x001D, name: "x25519".into(), is_pqc: false }
            },
            FindingKind::HybridKeyExchangeHrrRequired {
                group: NamedGroup { code_point: 0x11EC, name: "X25519MLKEM768".into(), is_pqc: true }
            },
            FindingKind::DeprecatedPqcDraftCodepoint { code_point: 0x6399 },
            FindingKind::WeakSymmetricCipher {
                suite: CipherSuite { id: 0x000A, name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA".into() }
            },
            FindingKind::ClassicalCertificate {
                position: ChainPosition::Leaf,
                key: KeyInfo::Rsa { bits: 2048 },
                deadline: 2030,
            },
            FindingKind::DowngradeAccepted,
            FindingKind::TlsVersionInsufficient { max_version: TlsVersion::Tls12 },
            FindingKind::CertExpiresAfterDeadline {
                expiry: NaiveDate::from_ymd_opt(2032, 1, 1).unwrap(),
                deadline: 2030,
                algorithm: AlgorithmId::Rsa { min_bits: 2048 },
            },
        ];
        for kind in &kinds {
            let r = remediation_for(kind);
            assert!(!r.text.is_empty(), "empty text for {:?}", kind);
        }
    }
}
