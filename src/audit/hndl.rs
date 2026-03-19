use crate::ProbeResults;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HndlRating {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HndlAssessment {
    pub rating: HndlRating,
    pub exposure_window_years: f32,
    pub cert_expires_before_q_day: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct HndlConfig {
    pub q_day_year: u32,
    pub current_year: u32,
    /// Expiry year of the leaf certificate, if available.
    /// cert expiry before Q-day may reduce the HNDL rating by one level
    /// because it forces a rekeying opportunity.
    pub cert_expiry_year: Option<u32>,
}

pub trait HndlModel: Send + Sync {
    fn name(&self) -> &'static str;
    fn assess(&self, probe: &ProbeResults, config: &HndlConfig) -> HndlAssessment;
}

pub struct DefaultHndlModel;

impl HndlModel for DefaultHndlModel {
    fn name(&self) -> &'static str {
        "default"
    }

    fn assess(&self, probe: &ProbeResults, config: &HndlConfig) -> HndlAssessment {
        let group_code = probe
            .pqc_handshake
            .as_ref()
            .map(|r| r.negotiated_group.code_point)
            .unwrap_or(0);

        let exposure = (config.q_day_year as f32) - (config.current_year as f32);

        let cert_before_q = config
            .cert_expiry_year
            .is_some_and(|y| y < config.q_day_year);

        let is_pure_pqc = matches!(group_code, 0x0200..=0x0202);
        // 0x6399 (Kyber Draft) is excluded — pre-FIPS draft is not considered sufficient HNDL protection
        let is_hybrid_pqc = matches!(group_code, 0x11EB..=0x11ED);

        let rating = if is_pure_pqc {
            HndlRating::None
        } else if is_hybrid_pqc {
            match exposure {
                e if e < 2.0 => HndlRating::Low,
                _ => HndlRating::Medium,
            }
        } else {
            // Classical only — cert_before_q can reduce by one level
            let base_rating = match exposure {
                e if e < 2.0 => HndlRating::Medium,
                e if e < 5.0 => HndlRating::High,
                _ => HndlRating::Critical,
            };
            if cert_before_q {
                match base_rating {
                    HndlRating::Critical => HndlRating::High,
                    HndlRating::High => HndlRating::Medium,
                    other => other,
                }
            } else {
                base_rating
            }
        };

        HndlAssessment {
            rating,
            exposure_window_years: exposure,
            cert_expires_before_q_day: cert_before_q,
            notes: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CipherSuite, DowngradeResult, NamedGroup, PqcHandshakeResult, ProbeResults, TlsVersion,
    };

    fn stub_probe_with_group(code_point: u16) -> ProbeResults {
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
                    is_pqc: code_point != 0x001D,
                },
                hrr_required: false,
                cert_chain_der: vec![],
            }),
            cipher_inventory: None,
            downgrade: DowngradeResult::Rejected,
        }
    }

    fn assess_hndl(
        group_code: u16,
        current_year: u32,
        q_day_year: u32,
        cert_expiry_year: Option<u32>,
    ) -> HndlAssessment {
        let probe = stub_probe_with_group(group_code);
        let config = HndlConfig {
            q_day_year,
            current_year,
            cert_expiry_year,
        };
        DefaultHndlModel.assess(&probe, &config)
    }

    #[test]
    fn pure_pqc_is_hndl_none() {
        let assessment = assess_hndl(0x0202, 2026, 2030, None);
        assert_eq!(assessment.rating, HndlRating::None);
    }

    #[test]
    fn classical_5yr_exposure_is_critical() {
        let assessment = assess_hndl(0x001D, 2026, 2032, None);
        assert_eq!(assessment.rating, HndlRating::Critical);
    }

    #[test]
    fn hybrid_short_exposure_is_low() {
        let assessment = assess_hndl(0x11EC, 2029, 2030, None);
        assert_eq!(assessment.rating, HndlRating::Low);
    }

    #[test]
    fn hybrid_long_exposure_is_medium() {
        let assessment = assess_hndl(0x11EC, 2026, 2030, None); // 4-year exposure
        assert_eq!(assessment.rating, HndlRating::Medium);
    }

    #[test]
    fn classical_cert_before_q_day_reduces_rating() {
        // exposure = 5 years, cert expires 1 year before Q-day → High not Critical
        let assessment = assess_hndl(0x001D, 2025, 2030, Some(2029));
        assert_eq!(assessment.rating, HndlRating::High);
    }
}
