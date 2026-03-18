use chrono::Datelike;
use crate::audit::findings::{FindingKind, Severity};
use crate::audit::scoring::model::{CategoryScore, ScoringModel, ScoringResult};
use crate::audit::tables::DeadlineTable;
use crate::{DowngradeResult, ProbeResults, TlsVersion};

pub struct NistWeightedModel;

pub fn key_exchange_points(code_point: u16, hrr: bool, current_year: u32) -> u8 {
    match code_point {
        0x11EC => if hrr { 40 } else { 50 },  // X25519MLKEM768
        0x11EB => 45,                           // SecP256r1MLKEM768
        0x11ED => 50,                           // SecP384r1MLKEM1024
        0x0202 => 50,                           // Pure ML-KEM-1024
        0x0201 => if current_year >= 2033 { 50 } else { 48 }, // Pure ML-KEM-768
        0x6399 => 20,                           // Kyber Draft (deprecated)
        _      => 0,                            // Classical only
    }
}

pub fn timeline_multiplier(years_until_disallowance: i64) -> f32 {
    match years_until_disallowance {
        y if y >= 9  => 1.00,
        y if y >= 5  => 0.75,
        y if y >= 2  => 0.40,
        y if y >= 1  => 0.10,
        _            => 0.00,  // y <= 0: deadline reached or passed
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

fn downgrade_points(downgrade: &DowngradeResult) -> u8 {
    match downgrade {
        DowngradeResult::Rejected => 5,
        _ => 0,
    }
}

impl ScoringModel for NistWeightedModel {
    fn name(&self) -> &'static str { "nist-weighted" }

    fn description(&self) -> &'static str {
        "NIST IR 8547-aligned weighted scoring model for PQC readiness (0-100)"
    }

    fn score(&self, probe: &ProbeResults, _table: &dyn DeadlineTable) -> ScoringResult {
        // TODO Task 7: _table will be used for cert chain scoring and cipher suite timeline multiplier
        let current_year = chrono::Utc::now().year() as u32;

        let (ke_points, tls_points, cs_points, downgrade_pts) =
            match &probe.pqc_handshake {
                Ok(hs) => {
                    let ke = key_exchange_points(
                        hs.negotiated_group.code_point,
                        hs.hrr_required,
                        current_year,
                    );
                    let tls = tls_version_points(&hs.negotiated_version);
                    let cs = cipher_suite_points(hs.negotiated_suite.id);
                    let dg = downgrade_points(&probe.downgrade);
                    (ke, tls, cs, dg)
                }
                Err(_) => (0, 0, 0, downgrade_points(&probe.downgrade)),
            };

        let raw_total =
            ke_points as u16
            + tls_points as u16
            + cs_points as u16
            + downgrade_pts as u16;
        // cert_chain is 0 until Task 7
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
                points: 0,
                max_points: 15,
                notes: vec!["cert chain not audited yet".into()],
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::tables::nist_ir8547::NistIr8547Table;
    use crate::{CipherSuite, DowngradeResult, NamedGroup, ProbeResults, PqcHandshakeResult, TlsVersion};

    fn pqc_probe_result(group_code: u16, hrr: bool) -> ProbeResults {
        ProbeResults {
            target: "example.com".into(),
            port: 443,
            pqc_handshake: Ok(PqcHandshakeResult {
                negotiated_version: TlsVersion::Tls13,
                negotiated_suite: CipherSuite { id: 0x1301, name: "TLS_AES_128_GCM_SHA256".into() },
                negotiated_group: NamedGroup {
                    code_point: group_code,
                    name: "X25519MLKEM768".into(),
                    is_pqc: true,
                },
                hrr_required: hrr,
                cert_chain_der: vec![],
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
        let result = model.score(&probe, &table);
        assert_eq!(result.key_exchange.points, 50);
    }

    #[test]
    fn hrr_penalty_applied() {
        let model = NistWeightedModel;
        let table = NistIr8547Table;
        let probe = pqc_probe_result(0x11EC, true);
        let result = model.score(&probe, &table);
        assert_eq!(result.key_exchange.points, 40);
    }

    #[test]
    fn classical_only_scores_zero_key_exchange() {
        let model = NistWeightedModel;
        let table = NistIr8547Table;
        let probe = pqc_probe_result(0x001D, false);
        let result = model.score(&probe, &table);
        assert_eq!(result.key_exchange.points, 0);
    }

    #[test]
    fn timeline_multiplier_boundary_values() {
        assert_eq!(timeline_multiplier(-1), 0.00);
        assert_eq!(timeline_multiplier(0),  0.00);
        assert_eq!(timeline_multiplier(1),  0.10);
        assert_eq!(timeline_multiplier(2),  0.40);
        assert_eq!(timeline_multiplier(5),  0.75);
        assert_eq!(timeline_multiplier(9),  1.00);
    }

    #[test]
    fn total_score_bounded_0_to_100() {
        let model = NistWeightedModel;
        let table = NistIr8547Table;
        let probe = pqc_probe_result(0x11EC, false);
        let result = model.score(&probe, &table);
        assert!(result.total <= 100);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use crate::audit::tables::nist_ir8547::NistIr8547Table;
    use crate::{CipherSuite, DowngradeResult, NamedGroup, ProbeResults, PqcHandshakeResult, TlsVersion};
    use proptest::prelude::*;

    fn make_probe(group_code: u16, hrr: bool) -> ProbeResults {
        ProbeResults {
            target: "example.com".into(),
            port: 443,
            pqc_handshake: Ok(PqcHandshakeResult {
                negotiated_version: TlsVersion::Tls13,
                negotiated_suite: CipherSuite { id: 0x1301, name: "TLS_AES_128_GCM_SHA256".into() },
                negotiated_group: NamedGroup { code_point: group_code, name: "test".into(), is_pqc: true },
                hrr_required: hrr,
                cert_chain_der: vec![],
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
            let result = model.score(&probe, &table);
            prop_assert!(result.total <= 100, "score {} > 100", result.total);
        }
    }
}
