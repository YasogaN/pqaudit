use owo_colors::OwoColorize;
use crate::{ScanReport, TargetReport};
use crate::audit::findings::Severity;
use crate::audit::hndl::HndlRating;
use crate::output::compare::ComparisonReport;

/// Render a `ScanReport` as a human-readable terminal string.
///
/// `compare_mode`: if true and `report.comparison` is set, append a side-by-side
/// comparison table after the per-target sections.
pub fn render_human(report: &ScanReport, compare_mode: bool) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "{} {} — {}\n",
        "pqaudit".bold(),
        env!("CARGO_PKG_VERSION"),
        report.scanned_at
    ));
    out.push_str(&format!("Compliance mode: {}\n\n", report.compliance_mode_name()));

    for target in &report.targets {
        out.push_str(&render_target(target));
        out.push('\n');
    }

    if compare_mode {
        if let Some(cmp) = &report.comparison {
            out.push_str(&render_comparison(cmp, report));
        }
    }

    out
}

fn render_target(target: &TargetReport) -> String {
    let mut out = String::new();

    // Header line: host + score
    let score_str = format!("{}/100", target.score.total);
    let colored_score = colorize_score(target.score.total, &score_str);
    out.push_str(&format!(
        "  {} {}  score: {}\n",
        "●".bold(),
        format!("{}:{}", target.target, target.port).bold(),
        colored_score,
    ));

    // Error if probe failed
    if let Some(err) = &target.error {
        out.push_str(&format!("    {} {}\n", "ERROR".red().bold(), err));
        return out;
    }

    // HNDL rating
    let hndl_str = hndl_label(&target.hndl.rating);
    out.push_str(&format!("    HNDL: {}\n", hndl_str));

    // Findings
    if target.findings.is_empty() {
        out.push_str(&format!("    {} No findings\n", "✓".green()));
    } else {
        for finding in &target.findings {
            let icon = match finding.severity {
                Severity::Error   => "✗".red().to_string(),
                Severity::Warning => "!".yellow().to_string(),
                Severity::Note    => "·".dimmed().to_string(),
            };
            let rule_id = finding.sarif_rule_id();
            out.push_str(&format!(
                "    {} [{}] {:?}\n",
                icon, rule_id, finding.kind
            ));
        }
    }

    out
}

fn render_comparison(cmp: &ComparisonReport, report: &ScanReport) -> String {
    let _ = report; // may be used for additional context in the future
    let mut out = String::new();
    out.push_str(&format!("\n{}\n", "── Comparison ──────────────────────────────".dimmed()));

    // Header row
    let header: Vec<String> = cmp.targets.iter().map(|t| truncate(t, 20)).collect();
    out.push_str(&format!("  {:20}", "Category"));
    for h in &header {
        out.push_str(&format!("  {:>20}", h));
    }
    out.push('\n');

    // Separator
    out.push_str(&format!("  {}\n", "─".repeat(20 + header.len() * 22)));

    // Category rows
    for cat in &cmp.categories {
        out.push_str(&format!("  {:20}", cat.name));
        for (i, &score) in cat.scores.iter().enumerate() {
            let s = score.to_string();
            let cell = if cat.winner == Some(i) {
                s.green().bold().to_string()
            } else {
                s.dimmed().to_string()
            };
            out.push_str(&format!("  {:>20}", cell));
        }
        out.push('\n');
    }

    out
}

fn colorize_score(score: u8, text: &str) -> String {
    if score >= 80 {
        text.green().bold().to_string()
    } else if score >= 60 {
        text.yellow().bold().to_string()
    } else {
        text.red().bold().to_string()
    }
}

fn hndl_label(rating: &HndlRating) -> String {
    match rating {
        HndlRating::None     => "None".green().to_string(),
        HndlRating::Low      => "Low".green().to_string(),
        HndlRating::Medium   => "Medium".yellow().to_string(),
        HndlRating::High     => "High".red().to_string(),
        HndlRating::Critical => "Critical".red().bold().to_string(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

trait ComplianceModeDisplay {
    fn compliance_mode_name(&self) -> &str;
}

impl ComplianceModeDisplay for ScanReport {
    fn compliance_mode_name(&self) -> &str {
        use crate::cli::ComplianceMode;
        match self.compliance_mode {
            ComplianceMode::Nist  => "NIST IR 8547",
            ComplianceMode::Cnsa2 => "CNSA 2.0",
            ComplianceMode::Fips  => "FIPS Binary Gates",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_common::{stub_scan_report, stub_target_report};
    use crate::cli::ComplianceMode;
    use crate::output::compare::build_comparison;

    fn stub_scan_report_with_score(score: u8) -> ScanReport {
        ScanReport {
            schema_version: "1.0".into(),
            scanned_at: "2026-01-01T00:00:00Z".into(),
            compliance_mode: ComplianceMode::Nist,
            targets: vec![stub_target_report(score)],
            comparison: None,
        }
    }

    #[test]
    fn human_output_contains_score() {
        let report = stub_scan_report_with_score(72);
        let out = render_human(&report, false);
        assert!(out.contains("72"), "output should contain score 72, got:\n{out}");
        assert!(out.contains("example.com"), "output should contain hostname");
    }

    #[test]
    fn human_output_high_score_is_green_band() {
        let report = stub_scan_report_with_score(85);
        let out = render_human(&report, false);
        assert!(out.contains("85"), "output should contain score 85");
    }

    #[test]
    fn human_output_low_score_contains_score() {
        let report = stub_scan_report_with_score(40);
        let out = render_human(&report, false);
        assert!(out.contains("40"), "output should contain score 40");
    }

    #[test]
    fn human_output_no_findings_shows_check() {
        let report = stub_scan_report();
        let out = render_human(&report, false);
        assert!(out.contains("No findings"), "expected 'No findings' message");
    }

    #[test]
    fn compare_mode_renders_comparison_table() {
        let mut t1 = stub_target_report(80);
        t1.target = "a.example.com".into();
        let mut t2 = stub_target_report(60);
        t2.target = "b.example.com".into();
        let mut report = ScanReport {
            schema_version: "1.0".into(),
            scanned_at: "2026-01-01T00:00:00Z".into(),
            compliance_mode: ComplianceMode::Nist,
            targets: vec![t1, t2],
            comparison: None,
        };
        report.comparison = Some(build_comparison(&report.clone()));
        let out = render_human(&report, true);
        assert!(out.contains("Comparison"), "expected comparison section");
        assert!(out.contains("total"), "expected 'total' category in comparison");
    }
}
