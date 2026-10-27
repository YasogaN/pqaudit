use crate::{ScanReport, TargetReport};
use serde_json::{json, Value};
use std::collections::HashMap;

const CBOM_FORMAT: &str = "CycloneDX";
const CBOM_SPEC_VERSION: &str = "1.6";

/// Aggregated crypto asset: algorithm name, CycloneDX primitive, and all endpoints that use it.
#[derive(Debug)]
struct CryptoAsset {
    algorithm: String,
    /// CycloneDX 1.6 algorithmProperties.primitive value.
    primitive: &'static str,
    occurrences: Vec<String>,
}

/// Render a `ScanReport` as a CycloneDX 1.6 CBOM JSON string.
pub fn render_cbom(report: &ScanReport) -> String {
    let components = build_components(&report.targets);

    let cbom = json!({
        "bomFormat": CBOM_FORMAT,
        "specVersion": CBOM_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": report.scanned_at,
            "tools": [{ "name": "pqaudit", "version": env!("CARGO_PKG_VERSION") }],
            "component": { "type": "application", "name": "scanned-tls-endpoints" }
        },
        "components": components
    });

    serde_json::to_string_pretty(&cbom).expect("CBOM JSON is always serializable")
}

fn build_components(targets: &[TargetReport]) -> Vec<Value> {
    let mut assets: HashMap<String, CryptoAsset> = HashMap::new();

    let mut add = |name: &str, primitive: &'static str, occurrence: String| {
        let entry = assets
            .entry(name.to_string())
            .or_insert_with(|| CryptoAsset {
                algorithm: name.to_string(),
                primitive,
                occurrences: vec![],
            });
        entry.occurrences.push(occurrence);
    };

    for target in targets {
        let endpoint = format!("{}:{}", target.target, target.port);

        // Negotiated key exchange group from the PQC handshake probe.
        // This is the most important asset — it reflects what was actually negotiated
        // with the server, unlike cipher_inventory which requires --full-scan.
        if let Some(group) = &target.negotiated_group {
            if group.code_point != 0 {
                let primitive = if group.is_pqc { "kem" } else { "key-agree" };
                add(
                    &group.name,
                    primitive,
                    format!("{} (negotiated key exchange)", endpoint),
                );
            }
        }

        // Negotiated cipher suite from the PQC handshake probe.
        if let Some(suite) = &target.negotiated_suite {
            add(
                &suite.name,
                "other", // cipher suites are composites; "other" is the correct CycloneDX primitive
                format!("{} (negotiated cipher suite)", endpoint),
            );
        }

        // Additional cipher suites from full-scan inventory (--full-scan only).
        if let Some(inv) = &target.cipher_inventory {
            for suite in inv.tls13_suites.iter().chain(inv.tls12_suites.iter()) {
                add(
                    &suite.name,
                    "other",
                    format!("{} (supported cipher suite)", endpoint),
                );
            }
        }

        // Certificate key algorithms.
        if let Some(chain) = &target.cert_chain {
            for entry in &chain.entries {
                let alg_name = key_info_to_alg_name(&entry.key);
                let primitive = key_info_to_primitive(&entry.key);
                let position = chain_position_label(&entry.position);
                add(
                    &alg_name,
                    primitive,
                    format!("{} (cert {})", endpoint, position),
                );
            }
        }
    }

    // HashMap iteration order is deliberately randomized; sort for stable
    // CBOM diffs across runs.
    let mut assets: Vec<CryptoAsset> = assets.into_values().collect();
    assets.sort_by(|a, b| a.algorithm.cmp(&b.algorithm));

    assets
        .into_iter()
        .map(|asset| {
            json!({
                "type": "cryptographic-asset",
                "name": asset.algorithm,
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": asset.primitive
                    }
                },
                "evidence": {
                    "occurrences": asset.occurrences.iter().map(|o| json!({ "location": o })).collect::<Vec<_>>()
                }
            })
        })
        .collect()
}

fn key_info_to_alg_name(key: &crate::KeyInfo) -> String {
    use crate::KeyInfo;
    match key {
        KeyInfo::Rsa { bits } => format!("RSA-{}", bits),
        KeyInfo::Dsa { bits } => format!("DSA-{}", bits),
        KeyInfo::Ec { curve } => format!("EC-{}", curve),
        KeyInfo::Ed25519 => "Ed25519".into(),
        KeyInfo::Ed448 => "Ed448".into(),
        KeyInfo::MlKem { level } => format!("ML-KEM-{}", level),
        KeyInfo::MlDsa { level } => format!("ML-DSA-{}", level),
        KeyInfo::SlhDsa { level } => format!("SLH-DSA-{}", level),
        KeyInfo::Unknown => "Unknown".into(),
    }
}

/// Map a certificate key type to the CycloneDX 1.6 `algorithmProperties.primitive` value.
fn key_info_to_primitive(key: &crate::KeyInfo) -> &'static str {
    use crate::KeyInfo;
    match key {
        KeyInfo::Rsa { .. } => "signature",
        KeyInfo::Dsa { .. } => "signature",
        KeyInfo::Ec { .. } => "signature",
        KeyInfo::Ed25519 => "signature",
        KeyInfo::Ed448 => "signature",
        KeyInfo::MlKem { .. } => "kem",
        KeyInfo::MlDsa { .. } => "signature",
        KeyInfo::SlhDsa { .. } => "signature",
        KeyInfo::Unknown => "unknown",
    }
}

fn chain_position_label(pos: &crate::ChainPosition) -> String {
    use crate::ChainPosition;
    match pos {
        ChainPosition::Leaf => "leaf".into(),
        ChainPosition::Intermediate { depth } => format!("intermediate-{}", depth),
        ChainPosition::Root => "root".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_common::stub_scan_report;

    #[test]
    fn cbom_spec_version_is_1_6() {
        let report = stub_scan_report();
        let cbom: serde_json::Value = serde_json::from_str(&render_cbom(&report)).unwrap();
        assert_eq!(cbom["bomFormat"], "CycloneDX");
        assert_eq!(cbom["specVersion"], "1.6");
    }

    #[test]
    fn cbom_contains_crypto_asset_components() {
        let report = stub_scan_report();
        let cbom: serde_json::Value = serde_json::from_str(&render_cbom(&report)).unwrap();
        let components = cbom["components"].as_array().unwrap();
        assert!(
            !components.is_empty(),
            "expected at least one crypto component"
        );
    }

    #[test]
    fn cbom_component_type_is_cryptographic_asset() {
        let report = stub_scan_report();
        let cbom: serde_json::Value = serde_json::from_str(&render_cbom(&report)).unwrap();
        let components = cbom["components"].as_array().unwrap();
        for c in components {
            assert_eq!(c["type"], "cryptographic-asset");
        }
    }

    #[test]
    fn cbom_algorithm_properties_have_primitive() {
        let report = stub_scan_report();
        let cbom: serde_json::Value = serde_json::from_str(&render_cbom(&report)).unwrap();
        let components = cbom["components"].as_array().unwrap();
        for c in components {
            let primitive = &c["cryptoProperties"]["algorithmProperties"]["primitive"];
            assert!(
                primitive.is_string(),
                "every component must have algorithmProperties.primitive"
            );
        }
    }

    #[test]
    fn cbom_negotiated_group_is_included() {
        let report = stub_scan_report();
        let cbom_str = render_cbom(&report);
        // stub report has negotiated_group = X25519MLKEM768
        assert!(
            cbom_str.contains("X25519MLKEM768"),
            "negotiated key exchange group must appear in CBOM"
        );
    }

    #[test]
    fn cbom_pqc_group_primitive_is_kem() {
        let report = stub_scan_report();
        let cbom: serde_json::Value = serde_json::from_str(&render_cbom(&report)).unwrap();
        let components = cbom["components"].as_array().unwrap();
        let pqc = components
            .iter()
            .find(|c| c["name"] == "X25519MLKEM768")
            .expect("X25519MLKEM768 component missing");
        assert_eq!(
            pqc["cryptoProperties"]["algorithmProperties"]["primitive"],
            "kem"
        );
    }

    #[test]
    fn cbom_is_valid_json() {
        let report = stub_scan_report();
        assert!(serde_json::from_str::<serde_json::Value>(&render_cbom(&report)).is_ok());
    }

    #[test]
    fn cbom_contains_tls_cipher_suite() {
        let report = stub_scan_report();
        let cbom_str = render_cbom(&report);
        // stub report has negotiated_suite = TLS_AES_256_GCM_SHA384
        assert!(
            cbom_str.contains("TLS_AES_256_GCM_SHA384"),
            "expected cipher suite name in CBOM"
        );
    }

    fn cert_entry(
        position: crate::ChainPosition,
        key: crate::KeyInfo,
        algorithm: crate::AlgorithmId,
    ) -> crate::audit::cert_chain::CertEntry {
        crate::audit::cert_chain::CertEntry {
            position,
            key,
            expiry_year: 2035,
            not_after: chrono::NaiveDate::from_ymd_opt(2035, 1, 1).unwrap(),
            subject: "CN=test".into(),
            algorithm,
            signature_algorithm: "test".into(),
            self_signed: false,
            expired: false,
        }
    }

    #[test]
    fn cbom_covers_all_key_types_and_positions() {
        use crate::audit::cert_chain::CertChainReport;
        use crate::{AlgorithmId, ChainPosition, KeyInfo};

        let mut report = stub_scan_report();
        report.targets[0].negotiated_group = Some(crate::NamedGroup {
            code_point: 0,
            name: "none".into(),
            is_pqc: false,
        });
        report.targets[0].negotiated_suite = None;
        report.targets[0].cipher_inventory = None;
        report.targets[0].cert_chain = Some(CertChainReport {
            entries: vec![
                cert_entry(
                    ChainPosition::Leaf,
                    KeyInfo::Rsa { bits: 2048 },
                    AlgorithmId::Rsa { min_bits: 2048 },
                ),
                cert_entry(
                    ChainPosition::Intermediate { depth: 1 },
                    KeyInfo::Dsa { bits: 2048 },
                    AlgorithmId::Dsa { min_bits: 2048 },
                ),
                cert_entry(
                    ChainPosition::Root,
                    KeyInfo::Ec {
                        curve: "P-256".into(),
                    },
                    AlgorithmId::EcP256,
                ),
                cert_entry(ChainPosition::Leaf, KeyInfo::Ed25519, AlgorithmId::Ed25519),
                cert_entry(ChainPosition::Leaf, KeyInfo::Ed448, AlgorithmId::Ed448),
                cert_entry(
                    ChainPosition::Leaf,
                    KeyInfo::MlKem { level: 768 },
                    AlgorithmId::MlKem768,
                ),
                cert_entry(
                    ChainPosition::Leaf,
                    KeyInfo::MlDsa { level: 65 },
                    AlgorithmId::MlDsa65,
                ),
                cert_entry(
                    ChainPosition::Leaf,
                    KeyInfo::SlhDsa { level: 1 },
                    AlgorithmId::SlhDsa { level: 1 },
                ),
                cert_entry(ChainPosition::Leaf, KeyInfo::Unknown, AlgorithmId::Unknown),
            ],
            findings: vec![],
        });

        let cbom: serde_json::Value = serde_json::from_str(&render_cbom(&report)).unwrap();
        let names: Vec<&str> = cbom["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        for expected in [
            "RSA-2048",
            "DSA-2048",
            "EC-P-256",
            "Ed25519",
            "Ed448",
            "ML-KEM-768",
            "ML-DSA-65",
            "SLH-DSA-1",
            "Unknown",
        ] {
            assert!(names.contains(&expected), "missing {expected} in {names:?}");
        }
    }

    #[test]
    fn cbom_handles_missing_group_and_chain() {
        let mut report = stub_scan_report();
        report.targets[0].negotiated_group = None;
        report.targets[0].cert_chain = None;
        report.targets[0].cipher_inventory = None;
        report.targets[0].negotiated_suite = None;
        let cbom: serde_json::Value = serde_json::from_str(&render_cbom(&report)).unwrap();
        assert!(cbom["components"].is_array());
    }

    #[test]
    fn cbom_components_are_sorted_for_stable_diffs() {
        let report = stub_scan_report();
        let cbom: serde_json::Value = serde_json::from_str(&render_cbom(&report)).unwrap();
        let names: Vec<&str> = cbom["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "CBOM component order must be stable");
    }

    #[test]
    fn cbom_with_no_targets_is_empty() {
        let report = crate::ScanReport {
            schema_version: "1.0".into(),
            scanned_at: "2026-01-01T00:00:00Z".into(),
            compliance_mode: crate::cli::ComplianceMode::Nist,
            targets: vec![],
            comparison: None,
        };
        let cbom: serde_json::Value = serde_json::from_str(&render_cbom(&report)).unwrap();
        assert_eq!(cbom["components"].as_array().unwrap().len(), 0);
    }
}
