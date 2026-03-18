use crate::audit::findings::{FindingKind, Severity};
use crate::audit::scoring::model::{CategoryScore, ScoringModel, ScoringResult};
use crate::audit::tables::DeadlineTable;
use crate::{DowngradeResult, ProbeResults, TlsVersion};

pub struct FipsBinaryGatesModel;

fn fips_key_exchange_points(code_point: u16) -> u8 {
    // All PQC hybrid and pure groups are FIPS-acceptable in binary-gates mode
    match code_point {
        0x11EC | 0x11EB | 0x11ED | 0x0201 | 0x0202 => 50,
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

fn downgrade_points(downgrade: &DowngradeResult) -> u8 {
    match downgrade {
        DowngradeResult::Rejected => 5,
        _ => 0,
    }
}

impl ScoringModel for FipsBinaryGatesModel {
    fn name(&self) -> &'static str { "fips-binary-gates" }

    fn description(&self) -> &'static str {
        "FIPS binary-gates scoring model — non-FIPS primitives score 0"
    }

    fn score(&self, probe: &ProbeResults, _table: &dyn DeadlineTable) -> ScoringResult {
        let (ke_points, tls_points, cs_points, downgrade_pts) =
            match &probe.pqc_handshake {
                Ok(hs) => {
                    let ke = fips_key_exchange_points(hs.negotiated_group.code_point);
                    let tls = tls_version_points(&hs.negotiated_version);
                    let cs = fips_cipher_suite_points(hs.negotiated_suite.id);
                    let dg = downgrade_points(&probe.downgrade);
                    (ke, tls, cs, dg)
                }
                Err(_) => (0, 0, 0, downgrade_points(&probe.downgrade)),
            };

        let raw_total = ke_points as u16 + tls_points as u16 + cs_points as u16 + downgrade_pts as u16;
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
            FindingKind::WeakSymmetricCipher { .. } => Severity::Error,
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
    use crate::audit::tables::fips::FipsTable;
    use crate::{CipherSuite, DowngradeResult, NamedGroup, ProbeResults, PqcHandshakeResult, TlsVersion};

    fn pqc_probe_result(code_point: u16) -> ProbeResults {
        ProbeResults {
            target: "example.com".into(),
            port: 443,
            pqc_handshake: Ok(PqcHandshakeResult {
                negotiated_version: TlsVersion::Tls13,
                negotiated_suite: CipherSuite { id: 0x1302, name: "TLS_AES_256_GCM_SHA384".into() },
                negotiated_group: NamedGroup { code_point, name: "test".into(), is_pqc: true },
                hrr_required: false,
                cert_chain_der: vec![],
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
        let result = model.score(&probe, &table);
        assert_eq!(result.key_exchange.points, 50);
    }

    #[test]
    fn chacha20_scores_zero_in_fips() {
        let model = FipsBinaryGatesModel;
        let table = FipsTable;
        let mut probe = pqc_probe_result(0x11EC);
        if let Ok(ref mut hs) = probe.pqc_handshake {
            hs.negotiated_suite = CipherSuite { id: 0x1303, name: "TLS_CHACHA20_POLY1305_SHA256".into() };
        }
        let result = model.score(&probe, &table);
        assert_eq!(result.cipher_suite.points, 0);
    }
}
