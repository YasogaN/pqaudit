use crate::audit::cert_chain::{cert_chain_notes, cert_chain_points, CertChainReport};
use crate::audit::findings::{FindingKind, Severity};
use crate::audit::scoring::model::{CategoryScore, ScoringModel, ScoringResult};
use crate::audit::tables::DeadlineTable;
use crate::{ProbeResults, TlsVersion};
use chrono::Datelike;

pub struct NistWeightedModel;

pub fn key_exchange_points(code_point: u16, hrr: bool, current_year: u32) -> u8 {
    match code_point {
        0x11EC => {
            if hrr {
                40
            } else {
                50
            }
        } // X25519MLKEM768
        0x11EB => 45, // SecP256r1MLKEM768
        0x11ED => 50, // SecP384r1MLKEM1024
        0x11EA => 40, // MLKEM512X25519
        0x11E9 => 35, // SecP256r1MLKEM512
        0x11EE => 30, // curveSM2MLKEM768 (not NIST-approved)
        0x0202 => 50, // Pure ML-KEM-1024
        0x0201 => {
            if current_year >= 2033 {
                50
            } else {
                48
            }
        } // Pure ML-KEM-768
        0x0200 => 35, // Pure ML-KEM-512 (below long-term target)
        0x6399 => 20, // Kyber Draft (deprecated)
        0x639A => 20, // SecP256r1 Kyber Draft (deprecated)
        _ => 0,       // Classical only
    }
}

pub fn timeline_multiplier(years_until_disallowance: i64) -> f32 {
    match years_until_disallowance {
        y if y >= 9 => 1.00,
        y if y >= 5 => 0.75,
        y if y >= 2 => 0.40,
        y if y >= 1 => 0.10,
        _ => 0.00, // y <= 0: deadline reached or passed
    }
}

fn tls_version_points(version: &TlsVersion) -> u8 {
    match version {
        TlsVersion::Tls13 => 15,
        TlsVersion::Tls12 => 5,
        _ => 0,
    }
}

fn cipher_suite_points(id: u16) -> u8 {
    match id {
        // AES-256-GCM
        0x1302 | 0xC02C | 0xC030 => 15,
        // ChaCha20-Poly1305
        0x1303 | 0xCCA8 | 0xCCA9 => 15,
        // AES-128-GCM
        0x1301 | 0xC02B | 0xC02F => 8,
        // 3DES, RC4, or unknown
        _ => 0,
    }
}

impl ScoringModel for NistWeightedModel {
    fn name(&self) -> &'static str {
        "nist-weighted"
    }

    fn description(&self) -> &'static str {
        "NIST IR 8547-aligned weighted scoring model for PQC readiness (0-100)"
    }

    fn score(
        &self,
        probe: &ProbeResults,
        cert_chain: Option<&CertChainReport>,
        _table: &dyn DeadlineTable,
    ) -> ScoringResult {
        let current_year = chrono::Utc::now().year() as u32;

        let (ke_points, tls_points, cs_points, downgrade_pts) = match &probe.pqc_handshake {
            Ok(hs) => {
                let ke = key_exchange_points(
                    hs.negotiated_group.code_point,
                    hs.hrr_required,
                    current_year,
                );
                let tls = tls_version_points(&hs.negotiated_version);
                let cs = cipher_suite_points(hs.negotiated_suite.id);
                let dg = crate::audit::scoring::model::downgrade_points(
                    &probe.downgrade,
                    hs.classical_fallback,
                    &hs.legacy_protocols,
                );
                (ke, tls, cs, dg)
            }
            Err(_) => (0, 0, 0, 0),
        };
        let (cert_points, cert_notes) = match cert_chain {
            Some(chain) => (cert_chain_points(chain), cert_chain_notes(chain)),
            None => (0, vec!["no certificate chain was returned".into()]),
        };

        let raw_total = ke_points as u16
            + tls_points as u16
            + cs_points as u16
            + cert_points as u16
            + downgrade_pts as u16;
        let total = raw_total.min(100) as u8;

        ScoringResult {
            total,
            key_exchange: CategoryScore {
                name: "key_exchange".into(),
                points: ke_points,
                max_points: 50,
                notes: vec![],
            },
            tls_version: CategoryScore {
                name: "tls_version".into(),
                points: tls_points,
                max_points: 15,
                notes: vec![],
            },
            cipher_suite: CategoryScore {
                name: "cipher_suite".into(),
                points: cs_points,
                max_points: 15,
                notes: vec![],
            },
            cert_chain: CategoryScore {
                name: "cert_chain".into(),
                points: cert_points,
                max_points: 15,
                notes: cert_notes,
            },
            downgrade_posture: CategoryScore {
                name: "downgrade_posture".into(),
                points: downgrade_pts,
                max_points: 5,
                notes: vec![],
            },
        }
    }

    fn severity(&self, finding: &FindingKind) -> Severity {
        match finding {
            FindingKind::ClassicalKeyExchangeOnly { .. } => Severity::Error,
            FindingKind::HybridKeyExchangeHrrRequired { .. } => Severity::Warning,
            FindingKind::DeprecatedPqcDraftCodepoint { .. } => Severity::Error,
            FindingKind::WeakSymmetricCipher { .. } => Severity::Warning,
            FindingKind::ClassicalCertificate { .. } => Severity::Warning,
            FindingKind::DowngradeAccepted => Severity::Error,
            FindingKind::TlsVersionInsufficient { .. } => Severity::Error,
            FindingKind::CertExpiresAfterDeadline { .. } => Severity::Warning,
            FindingKind::UnparseableCertificate { .. } => Severity::Error,
            FindingKind::WeakCertificateSignature { .. } => Severity::Error,
            FindingKind::ExpiredCertificate { .. } => Severity::Error,
            FindingKind::ClassicalFallbackAccepted => Severity::Warning,
            FindingKind::LegacyTlsProtocol { .. } => Severity::Error,
            FindingKind::CertificateValidationFailed { .. } => Severity::Error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::tables::nist_ir8547::NistIr8547Table;
    use crate::{
        CipherSuite, DowngradeResult, NamedGroup, PqcHandshakeResult, ProbeResults, TlsVersion,
    };

    fn pqc_probe_result(group_code: u16, hrr: bool) -> ProbeResults {
        ProbeResults {
            target: "example.com".into(),
            port: 443,
            pqc_handshake: Ok(PqcHandshakeResult {
                negotiated_version: TlsVersion::Tls13,
                negotiated_suite: CipherSuite {
                    id: 0x1301,
                    name: "TLS_AES_128_GCM_SHA256".into(),
                },
                negotiated_group: NamedGroup {
                    code_point: group_code,
                    name: "X25519MLKEM768".into(),
                    is_pqc: true,
                },
                hrr_required: hrr,
                cert_chain_der: vec![],
                pqc_supported: false,
                pqc_only_group: None,
                classical_fallback: false,
                legacy_protocols: vec![],
                certificate_validation_error: None,
            }),
            cipher_inventory: None,
            downgrade: DowngradeResult::Rejected,
        }
    }

    #[test]
    fn x25519mlkem768_no_hrr_scores_key_exchange_50() {
        let model = NistWeightedModel;
        let table = NistIr8547Table;
        let probe = pqc_probe_result(0x11EC, false);
        let result = model.score(&probe, None, &table);
        assert_eq!(result.key_exchange.points, 50);
    }

    #[test]
    fn hrr_penalty_applied() {
        let model = NistWeightedModel;
        let table = NistIr8547Table;
        let probe = pqc_probe_result(0x11EC, true);
        let result = model.score(&probe, None, &table);
        assert_eq!(result.key_exchange.points, 40);
    }

    #[test]
    fn classical_only_scores_zero_key_exchange() {
        let model = NistWeightedModel;
        let table = NistIr8547Table;
        let probe = pqc_probe_result(0x001D, false);
        let result = model.score(&probe, None, &table);
        assert_eq!(result.key_exchange.points, 0);
    }

    #[test]
    fn timeline_multiplier_boundary_values() {
        assert_eq!(timeline_multiplier(-1), 0.00);
        assert_eq!(timeline_multiplier(0), 0.00);
        assert_eq!(timeline_multiplier(1), 0.10);
        assert_eq!(timeline_multiplier(2), 0.40);
        assert_eq!(timeline_multiplier(5), 0.75);
        assert_eq!(timeline_multiplier(9), 1.00);
    }

    #[test]
    fn total_score_bounded_0_to_100() {
        let model = NistWeightedModel;
        let table = NistIr8547Table;
        let probe = pqc_probe_result(0x11EC, false);
        let result = model.score(&probe, None, &table);
        assert!(result.total <= 100);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use crate::audit::tables::nist_ir8547::NistIr8547Table;
    use crate::{
        CipherSuite, DowngradeResult, NamedGroup, PqcHandshakeResult, ProbeResults, TlsVersion,
    };
    use proptest::prelude::*;

    fn make_probe(group_code: u16, hrr: bool) -> ProbeResults {
        ProbeResults {
            target: "example.com".into(),
            port: 443,
            pqc_handshake: Ok(PqcHandshakeResult {
                negotiated_version: TlsVersion::Tls13,
                negotiated_suite: CipherSuite {
                    id: 0x1301,
                    name: "TLS_AES_128_GCM_SHA256".into(),
                },
                negotiated_group: NamedGroup {
                    code_point: group_code,
                    name: "test".into(),
                    is_pqc: true,
                },
                hrr_required: hrr,
                cert_chain_der: vec![],
                pqc_supported: false,
                pqc_only_group: None,
                classical_fallback: false,
                legacy_protocols: vec![],
                certificate_validation_error: None,
            }),
            cipher_inventory: None,
            downgrade: DowngradeResult::Rejected,
        }
    }

    proptest! {
        #[test]
        fn score_always_0_to_100(group_code in 0u16..=0xFFFFu16, hrr in any::<bool>()) {
            let model = NistWeightedModel;
            let table = NistIr8547Table;
            let probe = make_probe(group_code, hrr);
            let result = model.score(&probe, None, &table);
            prop_assert!(result.total <= 100, "score {} > 100", result.total);
        }
    }

    #[test]
    fn key_exchange_point_table_is_complete() {
        assert_eq!(key_exchange_points(0x11EC, false, 2026), 50);
        assert_eq!(key_exchange_points(0x11EC, true, 2026), 40);
        assert_eq!(key_exchange_points(0x11EB, false, 2026), 45);
        assert_eq!(key_exchange_points(0x11ED, false, 2026), 50);
        assert_eq!(key_exchange_points(0x11EA, false, 2026), 40);
        assert_eq!(key_exchange_points(0x11E9, false, 2026), 35);
        assert_eq!(key_exchange_points(0x11EE, false, 2026), 30);
        assert_eq!(key_exchange_points(0x0202, false, 2026), 50);
        assert_eq!(key_exchange_points(0x0201, false, 2026), 48);
        assert_eq!(key_exchange_points(0x0201, false, 2033), 50);
        assert_eq!(key_exchange_points(0x0200, false, 2026), 35);
        assert_eq!(key_exchange_points(0x6399, false, 2026), 20);
        assert_eq!(key_exchange_points(0x639A, false, 2026), 20);
        assert_eq!(key_exchange_points(0x001D, false, 2026), 0);
    }

    #[test]
    fn version_and_cipher_point_tables_are_complete() {
        assert_eq!(tls_version_points(&TlsVersion::Tls13), 15);
        assert_eq!(tls_version_points(&TlsVersion::Tls12), 5);
        assert_eq!(tls_version_points(&TlsVersion::Tls11), 0);
        assert_eq!(tls_version_points(&TlsVersion::Tls10), 0);
        assert_eq!(tls_version_points(&TlsVersion::Unknown(0)), 0);

        for id in [0x1302, 0xC02C, 0xC030, 0x1303, 0xCCA8, 0xCCA9] {
            assert_eq!(cipher_suite_points(id), 15);
        }
        for id in [0x1301, 0xC02B, 0xC02F] {
            assert_eq!(cipher_suite_points(id), 8);
        }
        for id in [0x000A, 0xFFFF] {
            assert_eq!(cipher_suite_points(id), 0);
        }
    }

    #[test]
    fn model_metadata_and_cert_chain_branch() {
        let model = NistWeightedModel;
        assert_eq!(model.name(), "nist-weighted");
        assert!(!model.description().is_empty());
        let chain = CertChainReport {
            entries: vec![],
            findings: vec![],
        };
        let table = NistIr8547Table;
        let probe = make_probe(0x11EC, false);
        let result = model.score(&probe, Some(&chain), &table);
        assert_eq!(result.cert_chain.points, 0);
        assert!(!result.cert_chain.notes.is_empty());
    }

    #[test]
    fn severity_covers_every_finding_kind() {
        use crate::audit::findings::FindingKind;
        use crate::{AlgorithmId, ChainPosition, KeyInfo};
        use chrono::NaiveDate;
        let model = NistWeightedModel;
        let cases = vec![
            FindingKind::ClassicalKeyExchangeOnly {
                group: crate::NamedGroup {
                    code_point: 0x001D,
                    name: "x25519".into(),
                    is_pqc: false,
                },
            },
            FindingKind::HybridKeyExchangeHrrRequired {
                group: crate::NamedGroup {
                    code_point: 0x11EC,
                    name: "X25519MLKEM768".into(),
                    is_pqc: true,
                },
            },
            FindingKind::DeprecatedPqcDraftCodepoint { code_point: 0x6399 },
            FindingKind::WeakSymmetricCipher {
                suite: CipherSuite {
                    id: 0x000A,
                    name: "3DES".into(),
                },
            },
            FindingKind::ClassicalCertificate {
                position: ChainPosition::Leaf,
                key: KeyInfo::Rsa { bits: 2048 },
                deadline: 2035,
            },
            FindingKind::DowngradeAccepted,
            FindingKind::TlsVersionInsufficient {
                max_version: TlsVersion::Tls12,
            },
            FindingKind::CertExpiresAfterDeadline {
                expiry: NaiveDate::from_ymd_opt(2035, 1, 1).unwrap(),
                deadline: 2030,
                algorithm: AlgorithmId::Rsa { min_bits: 2048 },
            },
            FindingKind::UnparseableCertificate { depth: 0 },
            FindingKind::WeakCertificateSignature {
                position: ChainPosition::Leaf,
                algorithm: "sha1".into(),
            },
            FindingKind::ExpiredCertificate {
                position: ChainPosition::Leaf,
                expiry: NaiveDate::from_ymd_opt(2020, 1, 1).unwrap(),
            },
            FindingKind::ClassicalFallbackAccepted,
            FindingKind::LegacyTlsProtocol {
                version: TlsVersion::Tls10,
            },
            FindingKind::CertificateValidationFailed {
                reason: "bad".into(),
            },
        ];
        for kind in cases {
            let _ = model.severity(&kind);
        }
    }
}
