use crate::ScanReport;

/// Render a `ScanReport` as pretty-printed JSON.
pub fn render_json(report: &ScanReport) -> String {
    serde_json::to_string_pretty(report).expect("ScanReport is always serializable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_common::stub_scan_report;

    #[test]
    fn json_output_contains_schema_version() {
        let report = stub_scan_report();
        let json = render_json(&report);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["schema_version"], "1.0");
    }

    #[test]
    fn json_round_trips_losslessly() {
        let report = stub_scan_report();
        let json = render_json(&report);
        let decoded: ScanReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.schema_version, decoded.schema_version);
        assert_eq!(report.targets.len(), decoded.targets.len());
    }

    #[test]
    fn json_output_is_valid_json() {
        let report = stub_scan_report();
        let json = render_json(&report);
        assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
    }

    #[test]
    fn json_output_contains_compliance_mode() {
        let report = stub_scan_report();
        let json = render_json(&report);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["compliance_mode"].is_string());
    }
}
