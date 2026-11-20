use crate::audit::cert_chain::{cert_chain_notes, cert_chain_points, CertChainReport};
use crate::audit::findings::{FindingKind, Severity};
use crate::audit::scoring::model::{CategoryScore, ScoringModel, ScoringResult};
use crate::audit::tables::DeadlineTable;
use crate::{ProbeResults, TlsVersion};

pub struct FipsBinaryGatesModel;

fn fips_key_exchange_points(code_point: u16) -> u8 {
    // FIPS-approved PQC groups only; 0x6399 (Kyber draft) intentionally excluded
    match code_point {
        0x11EC | 0x11EB | 0x11ED | 0x11E9 | 0x11EA | 0x0200 | 0x0201 | 0x0202 => 50,
        _ => 0,
    }
}

fn fips_cipher_suite_points(id: u16) -> u8 {
    match id {
        // AES-256-GCM
        0x1302 | 0xC02C | 0xC030 => 15,
        // AES-128-GCM — FIPS approved but not preferred
        0x1301 | 0xC02B | 0xC02F => 8,
        // ChaCha20-Poly1305 — NOT FIPS approved
        0x1303 | 0xCCA8 | 0xCCA9 => 0,
        _ => 0,
    }
}

fn tls_version_points(version: &TlsVersion) -> u8 {
    match version {
        TlsVersion::Tls13 => 15,
        TlsVersion::Tls12 => 5,
        _ => 0,
    }
}

impl ScoringModel for FipsBinaryGatesModel {
    fn name(&self) -> &'static str {
        "fips-binary-gates"
    }

    fn description(&self) -> &'static str {
        "FIPS binary-gates scoring model — non-FIPS primitives score 0"
    }

    fn score(
        &self,
        probe: &ProbeResults,
        cert_chain: Option<&CertChainReport>,
        _table: &dyn DeadlineTable,
    ) -> ScoringResult {
        let (ke_points, tls_points, cs_points, downgrade_pts) = match &probe.pqc_handshake {
            Ok(hs) => {
                let ke = fips_key_exchange_points(hs.negotiated_group.code_point);
                let tls = tls_version_points(&hs.negotiated_version);
                let cs = fips_cipher_suite_points(hs.negotiated_suite.id);
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
            FindingKind::WeakSymmetricCipher { .. } => Severity::Error,
            FindingKind::ClassicalCertificate { .. } => Severity::Warning,
            FindingKind::DowngradeAccepted => Severity::Error,
            FindingKind::TlsVersionInsufficient { .. } => Severity::Error,
            FindingKind::CertExpiresAfterDeadline { .. } => Severity::Warning,
            FindingKind::UnparseableCertificate { .. } => Severity::Error,
            FindingKind::WeakCertificateSignature { .. } => Severity::Error,
            FindingKind::ExpiredCertificate { .. } => Severity::Error,
            FindingKind::ClassicalFallbackAccepted => Severity::Error,
            FindingKind::LegacyTlsProtocol { .. } => Severity::Error,
            FindingKind::CertificateValidationFailed { .. } => Severity::Error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::tables::fips::FipsTable;
    use crate::{
        CipherSuite, DowngradeResult, NamedGroup, PqcHandshakeResult, ProbeResults, TlsVersion,
    };

    fn pqc_probe_result(code_point: u16) -> ProbeResults {
        ProbeResults {
            target: "example.com".into(),
            port: 443,
            pqc_handshake: Ok(PqcHandshakeResult {
                negotiated_version: TlsVersion::Tls13,
                negotiated_suite: CipherSuite {
                    id: 0x1302,
                    name: "TLS_AES_256_GCM_SHA384".into(),
                },
                negotiated_group: NamedGroup {
                    code_point,
                    name: "test".into(),
                    is_pqc: true,
                },
                hrr_required: false,
                cert_chain_der: vec![],
                classical_fallback: false,
                legacy_protocols: vec![],
                certificate_validation_error: None,
            }),
            cipher_inventory: None,
            downgrade: DowngradeResult::Rejected,
        }
    }

    #[test]
    fn fips_approved_pqc_scores_50() {
        let model = FipsBinaryGatesModel;
        let table = FipsTable;
        let probe = pqc_probe_result(0x11EC); // X25519MLKEM768 — FIPS approved
        let result = model.score(&probe, None, &table);
        assert_eq!(result.key_exchange.points, 50);
    }

    #[test]
    fn chacha20_scores_zero_in_fips() {
        let model = FipsBinaryGatesModel;
        let table = FipsTable;
        let mut probe = pqc_probe_result(0x11EC);
        probe.pqc_handshake.as_mut().unwrap().negotiated_suite = CipherSuite {
            id: 0x1303,
            name: "TLS_CHACHA20_POLY1305_SHA256".into(),
        };
        let result = model.score(&probe, None, &table);
        assert_eq!(result.cipher_suite.points, 0);
    }

    #[test]
    fn point_tables_and_metadata_cover_all_branches() {
        for code in [
            0x11EC, 0x11EB, 0x11ED, 0x11E9, 0x11EA, 0x0200, 0x0201, 0x0202,
        ] {
            assert_eq!(fips_key_exchange_points(code), 50);
        }
        assert_eq!(fips_key_exchange_points(0x001D), 0);
        for id in [0x1302, 0xC02C, 0xC030] {
            assert_eq!(fips_cipher_suite_points(id), 15);
        }
        for id in [0x1301, 0xC02B, 0xC02F] {
            assert_eq!(fips_cipher_suite_points(id), 8);
        }
        for id in [0x1303, 0xCCA8, 0xCCA9, 0x000A] {
            assert_eq!(fips_cipher_suite_points(id), 0);
        }
        assert_eq!(tls_version_points(&TlsVersion::Tls13), 15);
        assert_eq!(tls_version_points(&TlsVersion::Tls12), 5);
        assert_eq!(tls_version_points(&TlsVersion::Tls10), 0);

        let model = FipsBinaryGatesModel;
        assert_eq!(model.name(), "fips-binary-gates");
        assert!(!model.description().is_empty());
        let table = FipsTable;
        let chain = CertChainReport {
            entries: vec![],
            findings: vec![],
        };
        let probe = pqc_probe_result(0x11EC);
        assert_eq!(
            model.score(&probe, Some(&chain), &table).cert_chain.points,
            0
        );
    }

    #[test]
    fn failed_handshake_scores_zero() {
        let model = FipsBinaryGatesModel;
        let table = FipsTable;
        let mut probe = pqc_probe_result(0x11EC);
        probe.pqc_handshake = Err("boom".into());
        let result = model.score(&probe, None, &table);
        assert_eq!(result.total, 0);
    }

    #[test]
    fn severity_covers_every_finding_kind() {
        use crate::audit::findings::FindingKind;
        use crate::{AlgorithmId, ChainPosition, KeyInfo};
        use chrono::NaiveDate;
        let model = FipsBinaryGatesModel;
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
