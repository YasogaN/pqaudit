use serde_json::{json, Value};
use crate::ScanReport;
use crate::audit::remediation::remediation_for;

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

/// All PQA rule definitions included in every SARIF output regardless of active findings.
fn rule_definitions() -> Value {
    json!([
        {
            "id": "PQA001",
            "name": "ClassicalKeyExchangeOnly",
            "shortDescription": { "text": "Server uses classical (pre-quantum) key exchange only." },
            "helpUri": "https://csrc.nist.gov/pubs/ir/8547/ipd"
        },
        {
            "id": "PQA002",
            "name": "HybridKeyExchangeHrrRequired",
            "shortDescription": { "text": "Hybrid PQC key exchange requires a HelloRetryRequest (extra round-trip)." },
            "helpUri": "https://csrc.nist.gov/pubs/ir/8547/ipd"
        },
        {
            "id": "PQA003",
            "name": "DeprecatedPqcDraftCodepoint",
            "shortDescription": { "text": "Server negotiated a deprecated pre-standard PQC code point." },
            "helpUri": "https://csrc.nist.gov/pubs/ir/8547/ipd"
        },
        {
            "id": "PQA004",
            "name": "WeakSymmetricCipher",
            "shortDescription": { "text": "TLS cipher suite uses weak or deprecated symmetric encryption." },
            "helpUri": "https://csrc.nist.gov/pubs/fips/140-3/final"
        },
        {
            "id": "PQA005",
            "name": "ClassicalCertificateDeadlineSoon",
            "shortDescription": { "text": "Certificate uses a classical algorithm with a disallowance deadline by 2030." },
            "helpUri": "https://csrc.nist.gov/pubs/ir/8547/ipd"
        },
        {
            "id": "PQA006",
            "name": "ClassicalCertificateDeadlineLater",
            "shortDescription": { "text": "Certificate uses a classical algorithm with a later disallowance deadline." },
            "helpUri": "https://csrc.nist.gov/pubs/ir/8547/ipd"
        },
        {
            "id": "PQA007",
            "name": "DowngradeAccepted",
            "shortDescription": { "text": "Server accepts a TLS downgrade to 1.2 or lower." },
            "helpUri": "https://csrc.nist.gov/pubs/sp/800/52/r2/final"
        },
        {
            "id": "PQA008",
            "name": "TlsVersionInsufficient",
            "shortDescription": { "text": "Server maximum TLS version is below 1.3, required for PQC key exchange." },
            "helpUri": "https://csrc.nist.gov/pubs/sp/800/52/r2/final"
        },
        {
            "id": "PQA009",
            "name": "CertExpiresAfterDeadline",
            "shortDescription": { "text": "Certificate expiry date extends past the algorithm disallowance deadline." },
            "helpUri": "https://csrc.nist.gov/pubs/ir/8547/ipd"
        }
    ])
}

/// Render a `ScanReport` as a SARIF 2.1.0 JSON string.
pub fn render_sarif(report: &ScanReport) -> String {
    let mut results: Vec<Value> = Vec::new();

    for target in &report.targets {
        let uri = format!("tls://{}:{}", target.target, target.port);

        for finding in &target.findings {
            let remediation = remediation_for(&finding.kind);

            // Build fixes from config snippets
            let fixes: Vec<Value> = remediation
                .config_snippets
                .iter()
                .map(|(platform, snippet)| {
                    json!({
                        "description": { "text": format!("{} configuration", platform) },
                        "artifactChanges": [{
                            "artifactLocation": { "uri": format!("config/{}", platform) },
                            "replacements": [{
                                "deletedRegion": { "startLine": 1 },
                                "insertedContent": { "text": snippet }
                            }]
                        }]
                    })
                })
                .collect();

            let mut result = json!({
                "ruleId": finding.sarif_rule_id(),
                "level": severity_to_sarif_level(&finding.severity),
                "message": { "text": remediation.text },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri }
                    }
                }]
            });

            if !fixes.is_empty() {
                result["fixes"] = json!(fixes);
            }

            results.push(result);
        }
    }

    let sarif = json!({
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "pqaudit",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/YasogaN/pqaudit",
                    "rules": rule_definitions()
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).expect("SARIF JSON is always serializable")
}

fn severity_to_sarif_level(severity: &crate::audit::findings::Severity) -> &'static str {
    use crate::audit::findings::Severity;
    match severity {
        Severity::Error   => "error",
        Severity::Warning => "warning",
        Severity::Note    => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_common::{stub_scan_report, stub_scan_report_with_all_findings};

    #[test]
    fn sarif_schema_version_is_2_1_0() {
        let report = stub_scan_report();
        let sarif: serde_json::Value = serde_json::from_str(&render_sarif(&report)).unwrap();
        assert_eq!(sarif["version"], "2.1.0");
    }

    #[test]
    fn sarif_rule_ids_are_stable() {
        let report = stub_scan_report_with_all_findings();
        let sarif_str = render_sarif(&report);
        let sarif: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();
        let rules: Vec<&str> = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        assert!(rules.contains(&"PQA001"), "PQA001 missing from rules");
        assert!(rules.contains(&"PQA007"), "PQA007 missing from rules");
        assert_eq!(rules.len(), 9, "expected all 9 PQA rules");
    }

    #[test]
    fn sarif_results_contain_finding_rule_id() {
        let report = stub_scan_report_with_all_findings();
        let sarif: serde_json::Value = serde_json::from_str(&render_sarif(&report)).unwrap();
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert!(!results.is_empty(), "expected at least one SARIF result");
        let rule_ids: Vec<&str> = results
            .iter()
            .map(|r| r["ruleId"].as_str().unwrap())
            .collect();
        assert!(rule_ids.contains(&"PQA001"), "PQA001 result missing");
    }

    #[test]
    fn sarif_location_contains_host() {
        let report = stub_scan_report_with_all_findings();
        let sarif: serde_json::Value = serde_json::from_str(&render_sarif(&report)).unwrap();
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        let uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert!(uri.starts_with("tls://"), "location URI should be tls://");
    }
}
