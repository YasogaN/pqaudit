use clap::Parser;
use pqaudit::{
    ScanReport,
    cli::{Cli, OutputFormat},
    output::{
        cbom::render_cbom,
        compare::build_comparison,
        human::render_human,
        json::render_json,
        sarif::render_sarif,
    },
    scanner::{scan, ScanConfig},
};

#[tokio::main]
async fn main() {
    let cli = Cli::try_parse().unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(3);
    });

    // MCP server mode: serve over stdio and exit when transport closes.
    #[cfg(feature = "mcp")]
    if cli.mcp {
        if let Err(e) = pqaudit::mcp::run_mcp_server().await {
            eprintln!("MCP server error: {e}");
            std::process::exit(3);
        }
        return;
    }

    // Collect targets from positional args and optional targets file
    let mut targets = cli.targets.clone();
    if let Some(path) = &cli.targets_file {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                targets.extend(content.lines().filter(|l| !l.trim().is_empty()).map(str::to_string));
            }
            Err(e) => {
                eprintln!("Error reading targets file {}: {e}", path.display());
                std::process::exit(3);
            }
        }
    }

    if targets.is_empty() {
        eprintln!("No targets specified. Pass at least one host or use --targets-file.");
        std::process::exit(3);
    }

    let config = ScanConfig::from(&cli);
    let mut report = scan(targets, &config).await;

    // Load and diff baseline if requested
    if let Some(baseline_path) = &cli.baseline {
        match pqaudit::baseline::load_baseline(baseline_path) {
            Ok(baseline) => {
                match pqaudit::baseline::diff_reports(&baseline, &report) {
                    Ok(diffs) => {
                        // Print diff summary to stderr
                        for diff in &diffs {
                            let trend = if diff.score_improved { "↑" } else { "↓" };
                            eprintln!(
                                "  {} {} score: {:+} (resolved: {}, new: {})",
                                trend,
                                diff.target,
                                diff.score_delta,
                                diff.resolved_findings.len(),
                                diff.new_findings.len()
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("Baseline diff error: {:?}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Could not load baseline {}: {:?}", baseline_path.display(), e);
            }
        }
    }

    // Build comparison if requested
    if cli.compare {
        report.comparison = Some(build_comparison(&report));
    }

    // Render output
    let output_str = match cli.output {
        OutputFormat::Json   => render_json(&report),
        OutputFormat::Sarif  => render_sarif(&report),
        OutputFormat::Cbom   => render_cbom(&report),
        OutputFormat::Human  => render_human(&report, cli.compare),
    };

    // Write to file or stdout
    if let Some(path) = &cli.output_file {
        if let Err(e) = std::fs::write(path, &output_str) {
            eprintln!("Error writing output to {}: {e}", path.display());
            std::process::exit(3);
        }
    } else {
        print!("{}", output_str);
    }

    let exit_code = determine_exit_code(&report, &cli);
    std::process::exit(exit_code);
}

/// Determine the process exit code per spec §6.
///
/// Exit codes:
/// - 0: all targets scanned successfully and all pass any threshold
/// - 1: at least one target's score is below --fail-below
/// - 2: all targets failed to probe (all have error set)
/// - 3: invalid arguments (handled by clap before this function is called)
pub fn determine_exit_code(report: &ScanReport, cli: &Cli) -> i32 {
    // Exit 2 if all targets errored
    if !report.targets.is_empty() && report.targets.iter().all(|t| t.error.is_some()) {
        return 2;
    }

    // Exit 1 if any target is below --fail-below threshold
    if let Some(threshold) = cli.fail_below {
        let any_below = report
            .targets
            .iter()
            .any(|t| t.error.is_none() && t.score.total < threshold);
        if any_below {
            return 1;
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqaudit::{
        CipherInventory, CipherSuite, DowngradeResult, ScanReport, TargetReport,
        audit::{
            cert_chain::CertChainReport,
            hndl::{HndlAssessment, HndlRating},
            scoring::model::{CategoryScore, ScoringResult},
        },
        cli::ComplianceMode,
    };

    fn stub_cli_with_fail_below(threshold: u8) -> Cli {
        Cli::try_parse_from([
            "pqaudit",
            "--fail-below", &threshold.to_string(),
            "example.com",
        ]).unwrap()
    }

    fn stub_cli_no_threshold() -> Cli {
        Cli::try_parse_from(["pqaudit", "example.com"]).unwrap()
    }

    fn zero_cat(name: &str) -> CategoryScore {
        CategoryScore { name: name.into(), points: 0, max_points: 0, notes: vec![] }
    }

    fn stub_target(score: u8, error: Option<String>) -> TargetReport {
        TargetReport {
            target: "example.com".into(),
            port: 443,
            score: ScoringResult {
                total: score,
                key_exchange: zero_cat("key_exchange"),
                tls_version: zero_cat("tls_version"),
                cipher_suite: zero_cat("cipher_suite"),
                cert_chain: zero_cat("cert_chain"),
                downgrade_posture: zero_cat("downgrade_posture"),
            },
            hndl: HndlAssessment {
                rating: HndlRating::None,
                exposure_window_years: 0.0,
                cert_expires_before_q_day: false,
                notes: vec![],
            },
            findings: vec![],
            cert_chain: Some(CertChainReport { entries: vec![], findings: vec![] }),
            cipher_inventory: Some(CipherInventory {
                tls13_suites: vec![CipherSuite { id: 0x1302, name: "TLS_AES_256_GCM_SHA384".into() }],
                tls12_suites: vec![],
                kyber_draft_accepted: false,
            }),
            downgrade: DowngradeResult::Rejected,
            error,
        }
    }

    fn stub_report_with_score(score: u8) -> ScanReport {
        ScanReport {
            schema_version: "1.0".into(),
            scanned_at: "2026-01-01T00:00:00Z".into(),
            compliance_mode: ComplianceMode::Nist,
            targets: vec![stub_target(score, None)],
            comparison: None,
        }
    }

    fn stub_all_errored_report() -> ScanReport {
        ScanReport {
            schema_version: "1.0".into(),
            scanned_at: "2026-01-01T00:00:00Z".into(),
            compliance_mode: ComplianceMode::Nist,
            targets: vec![stub_target(0, Some("connection refused".into()))],
            comparison: None,
        }
    }

    #[test]
    fn exit_code_1_when_score_below_threshold() {
        let report = stub_report_with_score(50);
        let cli = stub_cli_with_fail_below(60);
        assert_eq!(determine_exit_code(&report, &cli), 1);
    }

    #[test]
    fn exit_code_0_when_all_pass() {
        let report = stub_report_with_score(85);
        let cli = stub_cli_with_fail_below(60);
        assert_eq!(determine_exit_code(&report, &cli), 0);
    }

    #[test]
    fn exit_code_0_when_no_threshold() {
        let report = stub_report_with_score(30);
        let cli = stub_cli_no_threshold();
        assert_eq!(determine_exit_code(&report, &cli), 0);
    }

    #[test]
    fn exit_code_2_when_all_targets_fail() {
        let report = stub_all_errored_report();
        let cli = stub_cli_no_threshold();
        assert_eq!(determine_exit_code(&report, &cli), 2);
    }

    #[test]
    fn exit_code_0_when_at_threshold_exactly() {
        let report = stub_report_with_score(60);
        let cli = stub_cli_with_fail_below(60);
        // score 60 with threshold 60: 60 < 60 is false, so exit 0
        assert_eq!(determine_exit_code(&report, &cli), 0);
    }
}
