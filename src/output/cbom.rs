use serde_json::{json, Value};
use std::collections::HashMap;
use crate::{ScanReport, TargetReport};

const CBOM_FORMAT: &str = "CycloneDX";
const CBOM_SPEC_VERSION: &str = "1.5";

/// Aggregated crypto asset: algorithm name + key size, with all endpoints that use it.
#[derive(Debug)]
struct CryptoAsset {
    algorithm: String,
    occurrences: Vec<String>, // "host:port (chain position or cipher)"
}

/// Render a `ScanReport` as a CycloneDX 1.5 CBOM JSON string.
pub fn render_cbom(report: &ScanReport) -> String {
    let components = build_components(&report.targets);

    let serial = format!(
        "urn:pqaudit:{}",
        report.scanned_at.replace(':', "-").replace('.', "-")
    );

    let cbom = json!({
        "bomFormat": CBOM_FORMAT,
        "specVersion": CBOM_SPEC_VERSION,
        "serialNumber": serial,
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
    // key: algorithm name → CryptoAsset
    let mut assets: HashMap<String, CryptoAsset> = HashMap::new();

    let add = |assets: &mut HashMap<String, CryptoAsset>, alg: &str, occurrence: String| {
        let entry = assets.entry(alg.to_string()).or_insert_with(|| CryptoAsset {
            algorithm: alg.to_string(),
            occurrences: vec![],
        });
        entry.occurrences.push(occurrence);
    };

    for target in targets {
        let endpoint = format!("{}:{}", target.target, target.port);

        // Cipher suites from inventory
        if let Some(inv) = &target.cipher_inventory {
            for suite in inv.tls13_suites.iter().chain(inv.tls12_suites.iter()) {
                add(
                    &mut assets,
                    &suite.name,
                    format!("{} (cipher suite)", endpoint),
                );
            }
        }

        // Certificate key algorithms from chain
        if let Some(chain) = &target.cert_chain {
            for entry in &chain.entries {
                let alg_name = key_info_to_alg_name(&entry.key);
                let position = chain_position_label(&entry.position);
                add(
                    &mut assets,
                    &alg_name,
                    format!("{} (cert {})", endpoint, position),
                );
            }
        }
    }

    assets
        .into_values()
        .map(|asset| {
            json!({
                "type": "cryptographic-asset",
                "name": asset.algorithm,
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "name": asset.algorithm
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
        KeyInfo::Ec { curve } => format!("EC-{}", curve),
        KeyInfo::Ed25519 => "Ed25519".into(),
        KeyInfo::Ed448 => "Ed448".into(),
        KeyInfo::MlDsa { level } => format!("ML-DSA-{}", level),
        KeyInfo::Unknown => "Unknown".into(),
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
    fn cbom_contains_crypto_asset_components() {
        let report = stub_scan_report();
        let cbom_str = render_cbom(&report);
        let cbom: serde_json::Value = serde_json::from_str(&cbom_str).unwrap();
        assert_eq!(cbom["bomFormat"], "CycloneDX");
        assert_eq!(cbom["specVersion"], "1.5");
        let components = cbom["components"].as_array().unwrap();
        assert!(!components.is_empty(), "expected at least one crypto component");
    }

    #[test]
    fn cbom_component_type_is_cryptographic_asset() {
        let report = stub_scan_report();
        let cbom: serde_json::Value =
            serde_json::from_str(&render_cbom(&report)).unwrap();
        let components = cbom["components"].as_array().unwrap();
        for c in components {
            assert_eq!(c["type"], "cryptographic-asset");
        }
    }

    #[test]
    fn cbom_is_valid_json() {
        let report = stub_scan_report();
        assert!(
            serde_json::from_str::<serde_json::Value>(&render_cbom(&report)).is_ok()
        );
    }

    #[test]
    fn cbom_contains_tls_cipher_suite() {
        let report = stub_scan_report();
        let cbom_str = render_cbom(&report);
        // stub report has TLS_AES_256_GCM_SHA384 in tls13_suites
        assert!(
            cbom_str.contains("TLS_AES_256_GCM_SHA384"),
            "expected cipher suite name in CBOM"
        );
    }
}
