use crate::ScanReport;
use serde::{Deserialize, Serialize};

/// A per-category score comparison across all scanned targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonCategory {
    pub name: String,
    /// Score per target in the same order as `ComparisonReport::targets`.
    pub scores: Vec<u8>,
    /// Index into `targets` of the best-scoring target, or `None` if all tied.
    pub winner: Option<usize>,
}

/// Side-by-side comparison of all targets in a scan report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonReport {
    pub targets: Vec<String>,
    pub categories: Vec<ComparisonCategory>,
}

/// Build a comparison report from a scan report's targets.
pub fn build_comparison(report: &ScanReport) -> ComparisonReport {
    let target_names: Vec<String> = report
        .targets
        .iter()
        .map(|t| format!("{}:{}", t.target, t.port))
        .collect();

    // The categories we compare: total score and each sub-category
    let mut categories = Vec::new();

    macro_rules! add_category {
        ($name:expr, $accessor:expr) => {{
            let scores: Vec<u8> = report.targets.iter().map($accessor).collect();
            let winner = best_index(&scores);
            categories.push(ComparisonCategory {
                name: $name.into(),
                scores,
                winner,
            });
        }};
    }

    add_category!("total", |t| t.score.total);
    add_category!("key_exchange", |t| t.score.key_exchange.points);
    add_category!("tls_version", |t| t.score.tls_version.points);
    add_category!("cipher_suite", |t| t.score.cipher_suite.points);
    add_category!("cert_chain", |t| t.score.cert_chain.points);
    add_category!("downgrade_posture", |t| t.score.downgrade_posture.points);

    ComparisonReport {
        targets: target_names,
        categories,
    }
}

/// Returns the index of the highest score, or `None` if all are tied.
fn best_index(scores: &[u8]) -> Option<usize> {
    if scores.is_empty() {
        return None;
    }
    let max = *scores.iter().max().unwrap();
    let all_tied = scores.iter().all(|&s| s == max);
    if all_tied {
        None
    } else {
        scores.iter().position(|&s| s == max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ComplianceMode;
    use crate::tests_common::{stub_scan_report, stub_target_report};

    fn stub_multi_target_report() -> ScanReport {
        let mut t1 = stub_target_report(80);
        t1.target = "a.example.com".into();
        let mut t2 = stub_target_report(60);
        t2.target = "b.example.com".into();
        ScanReport {
            schema_version: "1.0".into(),
            scanned_at: "2026-01-01T00:00:00Z".into(),
            compliance_mode: ComplianceMode::Nist,
            targets: vec![t1, t2],
            comparison: None,
        }
    }

    #[test]
    fn compare_report_has_correct_target_count() {
        let report = stub_multi_target_report();
        let comparison = build_comparison(&report);
        assert_eq!(comparison.targets.len(), 2);
    }

    #[test]
    fn compare_report_winner_points_to_higher_score() {
        let report = stub_multi_target_report();
        let comparison = build_comparison(&report);
        let total = comparison
            .categories
            .iter()
            .find(|c| c.name == "total")
            .unwrap();
        // target[0] has score 80, target[1] has score 60 → winner is index 0
        assert_eq!(total.winner, Some(0));
    }

    #[test]
    fn compare_report_tied_scores_have_no_winner() {
        let mut t1 = stub_target_report(70);
        t1.target = "a.example.com".into();
        let mut t2 = stub_target_report(70);
        t2.target = "b.example.com".into();
        let report = ScanReport {
            schema_version: "1.0".into(),
            scanned_at: "2026-01-01T00:00:00Z".into(),
            compliance_mode: ComplianceMode::Nist,
            targets: vec![t1, t2],
            comparison: None,
        };
        let comparison = build_comparison(&report);
        let total = comparison
            .categories
            .iter()
            .find(|c| c.name == "total")
            .unwrap();
        assert_eq!(total.winner, None, "tied scores should have no winner");
    }

    #[test]
    fn compare_flag_with_json_output_adds_comparison_field() {
        use crate::output::json::render_json;
        let report = stub_multi_target_report();
        let mut report = report;
        report.comparison = Some(build_comparison(&report.clone()));
        let json = render_json(&report);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            v.get("comparison").is_some(),
            "JSON must include 'comparison' key"
        );
        assert!(v["comparison"]["targets"].is_array());
    }

    #[test]
    fn compare_flag_with_sarif_output_has_no_effect() {
        use crate::output::sarif::render_sarif;
        let report = stub_multi_target_report();
        let mut report = report;
        report.comparison = Some(build_comparison(&report.clone()));
        let sarif: serde_json::Value = serde_json::from_str(&render_sarif(&report)).unwrap();
        assert!(
            sarif.get("comparison").is_none(),
            "SARIF must not contain comparison key"
        );
    }
}
