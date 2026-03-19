use std::collections::HashSet;
use crate::{ScanReport, TargetReport};

#[derive(Debug)]
pub enum BaselineDiffError {
    SchemaMismatch { baseline: String, current: String },
    ParseError(serde_json::Error),
    IoError(String),
}

impl From<serde_json::Error> for BaselineDiffError {
    fn from(e: serde_json::Error) -> Self {
        BaselineDiffError::ParseError(e)
    }
}

#[derive(Debug, Clone)]
pub struct TargetDiff {
    pub target: String,
    /// Signed score change (current − baseline). Positive = improvement.
    pub score_delta: i16,
    pub score_improved: bool,
    /// Finding rule IDs present in baseline but resolved in current.
    pub resolved_findings: Vec<String>,
    /// Finding rule IDs present in current but absent from baseline.
    pub new_findings: Vec<String>,
}

/// Compare two scan reports and return per-target diffs.
/// Returns `Err` if the schema versions differ — mixing schemas makes diffs unreliable.
pub fn diff_reports(
    baseline: &ScanReport,
    current: &ScanReport,
) -> Result<Vec<TargetDiff>, BaselineDiffError> {
    if baseline.schema_version != current.schema_version {
        return Err(BaselineDiffError::SchemaMismatch {
            baseline: baseline.schema_version.clone(),
            current: current.schema_version.clone(),
        });
    }

    // Build lookup map from target string → TargetReport for the baseline.
    let baseline_map: std::collections::HashMap<&str, &TargetReport> = baseline
        .targets
        .iter()
        .map(|t| (t.target.as_str(), t))
        .collect();

    let diffs = current
        .targets
        .iter()
        .filter_map(|cur| {
            baseline_map.get(cur.target.as_str()).map(|base| diff_target(base, cur))
        })
        .collect();

    Ok(diffs)
}

/// Compute a diff between a baseline TargetReport and the current one.
pub fn diff_target(baseline: &TargetReport, current: &TargetReport) -> TargetDiff {
    let delta = current.score.total as i16 - baseline.score.total as i16;

    let baseline_ids: HashSet<String> = baseline
        .findings
        .iter()
        .map(|f| f.sarif_rule_id().to_string())
        .collect();

    let current_ids: HashSet<String> = current
        .findings
        .iter()
        .map(|f| f.sarif_rule_id().to_string())
        .collect();

    let resolved_findings: Vec<String> = baseline_ids
        .difference(&current_ids)
        .cloned()
        .collect();

    let new_findings: Vec<String> = current_ids
        .difference(&baseline_ids)
        .cloned()
        .collect();

    TargetDiff {
        target: current.target.clone(),
        score_delta: delta,
        score_improved: delta > 0,
        resolved_findings,
        new_findings,
    }
}

/// Load a ScanReport from a JSON baseline file.
pub fn load_baseline(path: &std::path::Path) -> Result<ScanReport, BaselineDiffError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| BaselineDiffError::IoError(e.to_string()))?;
    Ok(serde_json::from_str(&content)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_common::{stub_scan_report, stub_target_report};

    #[test]
    fn baseline_diff_detects_score_improvement() {
        let old = stub_target_report(40);
        let new = stub_target_report(75);
        let diff = diff_target(&old, &new);
        assert_eq!(diff.score_delta, 35);
        assert!(diff.score_improved);
    }

    #[test]
    fn baseline_diff_detects_regression() {
        let old = stub_target_report(80);
        let new = stub_target_report(60);
        let diff = diff_target(&old, &new);
        assert_eq!(diff.score_delta, -20);
        assert!(!diff.score_improved);
    }

    #[test]
    fn schema_version_mismatch_returns_error() {
        let mut old = stub_scan_report();
        old.schema_version = "0.9".into();
        let result = diff_reports(&old, &stub_scan_report());
        assert!(matches!(result, Err(BaselineDiffError::SchemaMismatch { .. })));
    }

    #[test]
    fn same_reports_produce_zero_delta() {
        let report = stub_scan_report();
        let diffs = diff_reports(&report, &report).unwrap();
        for diff in &diffs {
            assert_eq!(diff.score_delta, 0);
        }
    }
}
