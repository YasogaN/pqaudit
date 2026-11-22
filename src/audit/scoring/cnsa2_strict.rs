use crate::audit::cert_chain::{cert_chain_notes, cert_chain_points, CertChainReport};
use crate::audit::findings::{FindingKind, Severity};
use crate::audit::scoring::model::{CategoryScore, ScoringModel, ScoringResult};
use crate::audit::tables::DeadlineTable;
use crate::{ProbeResults, TlsVersion};

pub struct Cnsa2StrictModel;

fn cnsa2_key_exchange_points(code_point: u16) -> u8 {
    match code_point {
        0x0202 | 0x11ED => 50, // Pure ML-KEM-1024 or SecP384r1MLKEM1024 (CNSA 2.0 compliant)
        0x0201 => 35,          // ML-KEM-768 (below CNSA 2.0 recommended level)
        0x11EC => 30,          // X25519MLKEM768
        0x11EB => 25,          // SecP256r1MLKEM768
        0x11EA => 20,          // MLKEM512X25519
        0x11E9 => 15,          // SecP256r1MLKEM512
        0x0200 => 15,          // Pure ML-KEM-512
        _ => 0,
    }
}

fn cnsa2_cipher_suite_points(id: u16) -> u8 {
    match id {
        0x1302 | 0xC02C | 0xC030 => 15, // AES-256-GCM only
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

impl ScoringModel for Cnsa2StrictModel {
    fn name(&self) -> &'static str {
        "cnsa2-strict"
    }

    fn description(&self) -> &'static str {
        "CNSA 2.0 strict binary-gates scoring model — ML-KEM-1024 required"
    }

    fn score(
        &self,
        probe: &ProbeResults,
        cert_chain: Option<&CertChainReport>,
        _table: &dyn DeadlineTable,
    ) -> ScoringResult {
        let (ke_points, tls_points, cs_points, downgrade_pts) = match &probe.pqc_handshake {
            Ok(hs) => {
                let ke = cnsa2_key_exchange_points(hs.negotiated_group.code_point);
                let tls = tls_version_points(&hs.negotiated_version);
                let cs = cnsa2_cipher_suite_points(hs.negotiated_suite.id);
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
            FindingKind::PqcSupportedButClassicalNegotiated { .. } => Severity::Error,
            FindingKind::HybridKeyExchangeHrrRequired { .. } => Severity::Warning,
            FindingKind::DeprecatedPqcDraftCodepoint { .. } => Severity::Error,
            FindingKind::WeakSymmetricCipher { .. } => Severity::Error,
            FindingKind::ClassicalCertificate { .. } => Severity::Error,
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
    use crate::audit::tables::cnsa2::Cnsa2Table;
    use crate::{
        CipherSuite, DowngradeResult, NamedGroup, PqcHandshakeResult, ProbeResults, TlsVersion,
    };

    fn pqc_probe_result(code_point: u16, hrr: bool) -> ProbeResults {
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
    fn mlkem1024_scores_50_of_50_in_cnsa2() {
        let model = Cnsa2StrictModel;
        let table = Cnsa2Table;
        let probe = pqc_probe_result(0x0202, false); // pure ML-KEM-1024
        let result = model.score(&probe, None, &table);
        assert_eq!(result.key_exchange.points, 50);
    }

    #[test]
    fn mlkem768_scores_35_of_50_in_cnsa2() {
        let model = Cnsa2StrictModel;
        let table = Cnsa2Table;
        let probe = pqc_probe_result(0x0201, false); // pure ML-KEM-768
        let result = model.score(&probe, None, &table);
        assert_eq!(result.key_exchange.points, 35);
    }

    #[test]
    fn secp384r1mlkem1024_scores_50_in_cnsa2() {
        let model = Cnsa2StrictModel;
        let table = Cnsa2Table;
        let probe = pqc_probe_result(0x11ED, false); // SecP384r1MLKEM1024 — CNSA 2.0 compliant hybrid
        let result = model.score(&probe, None, &table);
        assert_eq!(result.key_exchange.points, 50);
    }

    #[test]
    fn aes128_scores_zero_in_cnsa2() {
        let model = Cnsa2StrictModel;
        let table = Cnsa2Table;
        // Use a probe where the cipher suite is AES-128-GCM
        let mut probe = pqc_probe_result(0x0202, false);
        probe.pqc_handshake.as_mut().unwrap().negotiated_suite = CipherSuite {
            id: 0x1301,
            name: "TLS_AES_128_GCM_SHA256".into(),
        };
        let result = model.score(&probe, None, &table);
        assert_eq!(result.cipher_suite.points, 0);
    }

    #[test]
    fn key_exchange_and_cipher_tables_cover_all_branches() {
        assert_eq!(cnsa2_key_exchange_points(0x0202), 50);
        assert_eq!(cnsa2_key_exchange_points(0x11ED), 50);
        assert_eq!(cnsa2_key_exchange_points(0x0201), 35);
        assert_eq!(cnsa2_key_exchange_points(0x11EC), 30);
        assert_eq!(cnsa2_key_exchange_points(0x11EB), 25);
        assert_eq!(cnsa2_key_exchange_points(0x11EA), 20);
        assert_eq!(cnsa2_key_exchange_points(0x11E9), 15);
        assert_eq!(cnsa2_key_exchange_points(0x0200), 15);
        assert_eq!(cnsa2_key_exchange_points(0x001D), 0);

        assert_eq!(cnsa2_cipher_suite_points(0x1302), 15);
        assert_eq!(cnsa2_cipher_suite_points(0xC02C), 15);
        assert_eq!(cnsa2_cipher_suite_points(0xC030), 15);
        assert_eq!(cnsa2_cipher_suite_points(0x1301), 0);
        assert_eq!(tls_version_points(&TlsVersion::Tls13), 15);
        assert_eq!(tls_version_points(&TlsVersion::Tls12), 5);
        assert_eq!(tls_version_points(&TlsVersion::Tls10), 0);

        let model = Cnsa2StrictModel;
        assert_eq!(model.name(), "cnsa2-strict");
        assert!(!model.description().is_empty());
        let table = Cnsa2Table;
        let chain = CertChainReport {
            entries: vec![],
            findings: vec![],
        };
        let probe = pqc_probe_result(0x0202, false);
        assert_eq!(
            model.score(&probe, Some(&chain), &table).cert_chain.points,
            0
        );
    }

    #[test]
    fn failed_handshake_scores_zero() {
        let model = Cnsa2StrictModel;
        let table = Cnsa2Table;
        let mut probe = pqc_probe_result(0x0202, false);
        probe.pqc_handshake = Err("boom".into());
        let result = model.score(&probe, None, &table);
        assert_eq!(result.total, 0);
    }

    #[test]
    fn severity_covers_every_finding_kind() {
        use crate::audit::findings::FindingKind;
        use crate::{AlgorithmId, ChainPosition, KeyInfo};
        use chrono::NaiveDate;
        let model = Cnsa2StrictModel;
        let cases = vec![
            FindingKind::ClassicalKeyExchangeOnly {
                group: crate::NamedGroup {
                    code_point: 0x001D,
                    name: "x25519".into(),
                    is_pqc: false,
                },
            },
            FindingKind::PqcSupportedButClassicalNegotiated {
                negotiated_group: crate::NamedGroup {
                    code_point: 0x001D,
                    name: "x25519".into(),
                    is_pqc: false,
                },
                pqc_group: crate::NamedGroup {
                    code_point: 0x11EC,
                    name: "X25519MLKEM768".into(),
                    is_pqc: true,
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
