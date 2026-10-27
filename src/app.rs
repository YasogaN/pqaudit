use crate::cli::{Cli, OutputFormat};
use crate::output::{
    cbom::render_cbom, compare::build_comparison, human::render_human, json::render_json,
    sarif::render_sarif,
};
use crate::scanner::{scan, ScanConfig};
use crate::ScanReport;
use std::io::{IsTerminal, Write};

/// Run the CLI workflow and return the process exit code.
///
/// This is a library function so every path (MCP, baseline, comparison,
/// file output, exit codes) can be tested without spawning a process.
pub async fn run(cli: Cli) -> i32 {
    #[cfg(feature = "mcp")]
    if cli.mcp {
        let result = crate::mcp::run_mcp_server()
            .await
            .map_err(|e| e.to_string());
        return mcp_exit_code(result);
    }

    let mut targets = cli.targets.clone();
    if let Some(path) = &cli.targets_file {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                targets.extend(
                    content
                        .lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .map(str::to_string),
                );
            }
            Err(e) => {
                eprintln!("Error reading targets file {}: {e}", path.display());
                return 3;
            }
        }
    }

    if targets.is_empty() {
        eprintln!("No targets specified. Pass at least one host or use --targets-file.");
        return 3;
    }

    let config = ScanConfig::from(&cli);
    let mut report = scan(targets, &config).await;

    if let Some(baseline_path) = &cli.baseline {
        match crate::baseline::load_baseline(baseline_path) {
            Ok(baseline) => match crate::baseline::diff_reports(&baseline, &report) {
                Ok(diffs) => {
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
                Err(e) => eprintln!("Baseline diff error: {:?}", e),
            },
            Err(e) => eprintln!(
                "Could not load baseline {}: {:?}",
                baseline_path.display(),
                e
            ),
        }
    }

    if cli.compare {
        report.comparison = Some(build_comparison(&report));
    }

    let color_output = matches!(cli.output, OutputFormat::Human)
        && cli.output_file.is_none()
        && std::io::stdout().is_terminal();
    let mut output_str = match cli.output {
        OutputFormat::Json => render_json(&report),
        OutputFormat::Sarif => render_sarif(&report),
        OutputFormat::Cbom => render_cbom(&report),
        OutputFormat::Human => render_human(&report, cli.compare),
    };
    if matches!(cli.output, OutputFormat::Human) && !color_output {
        output_str = crate::output::human::strip_ansi(&output_str);
    }

    if let Some(path) = &cli.output_file {
        if let Err(e) = std::fs::write(path, &output_str) {
            eprintln!("Error writing output to {}: {e}", path.display());
            return 3;
        }
    } else {
        print!("{}", output_str);
        // `main` exits with process::exit, which skips destructors; flush
        // explicitly so piped output is never truncated.
        let _ = std::io::stdout().flush();
    }

    determine_exit_code(&report, &cli)
}

/// Map an MCP server result to a process exit code.
pub fn mcp_exit_code(result: Result<(), String>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("MCP server error: {e}");
            3
        }
    }
}

/// Determine the process exit code per spec §6.
///
/// Exit codes:
/// - 0: all targets scanned successfully and all pass any threshold
/// - 1: at least one target's score is below --fail-below
/// - 2: all targets failed to probe (all have error set)
/// - 3: invalid arguments (handled by clap before this function is called)
pub fn determine_exit_code(report: &ScanReport, cli: &Cli) -> i32 {
    if !report.targets.is_empty() && report.targets.iter().all(|t| t.error.is_some()) {
        return 2;
    }

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
    use crate::audit::{
        cert_chain::CertChainReport,
        hndl::{HndlAssessment, HndlRating},
        scoring::model::{CategoryScore, ScoringResult},
    };
    use crate::cli::ComplianceMode;
    use crate::test_support::tls_server;
    use crate::{CipherInventory, CipherSuite, DowngradeResult, ScanReport, TargetReport};
    use rustls::crypto::aws_lc_rs;

    fn stub_cli(args: &[&str]) -> Cli {
        use clap::Parser;
        Cli::try_parse_from(args).unwrap()
    }

    fn zero_cat(name: &str) -> CategoryScore {
        CategoryScore {
            name: name.into(),
            points: 0,
            max_points: 0,
            notes: vec![],
        }
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
            cert_chain: Some(CertChainReport {
                entries: vec![],
                findings: vec![],
            }),
            cipher_inventory: Some(CipherInventory {
                tls13_suites: vec![CipherSuite {
                    id: 0x1302,
                    name: "TLS_AES_256_GCM_SHA384".into(),
                }],
                tls12_suites: vec![],
                kyber_draft_accepted: false,
            }),
            downgrade: DowngradeResult::Rejected,
            error,
            negotiated_group: None,
            negotiated_suite: None,
            classical_fallback: false,
            legacy_protocols: vec![],
        }
    }

    fn stub_report(score: u8, error: Option<String>) -> ScanReport {
        ScanReport {
            schema_version: "1.0".into(),
            scanned_at: "2026-01-01T00:00:00Z".into(),
            compliance_mode: ComplianceMode::Nist,
            targets: vec![stub_target(score, error)],
            comparison: None,
        }
    }

    #[test]
    fn mcp_exit_code_maps_success_and_error() {
        assert_eq!(mcp_exit_code(Ok(())), 0);
        assert_eq!(mcp_exit_code(Err("boom".into())), 3);
    }

    #[test]
    fn exit_code_1_when_score_below_threshold() {
        let cli = stub_cli(&["pqaudit", "--fail-below", "60", "example.com"]);
        assert_eq!(determine_exit_code(&stub_report(50, None), &cli), 1);
    }

    #[test]
    fn exit_code_0_when_all_pass_or_no_threshold() {
        let cli = stub_cli(&["pqaudit", "--fail-below", "60", "example.com"]);
        assert_eq!(determine_exit_code(&stub_report(85, None), &cli), 0);
        let cli = stub_cli(&["pqaudit", "example.com"]);
        assert_eq!(determine_exit_code(&stub_report(30, None), &cli), 0);
    }

    #[test]
    fn exit_code_2_when_all_targets_fail() {
        let cli = stub_cli(&["pqaudit", "example.com"]);
        assert_eq!(
            determine_exit_code(&stub_report(0, Some("refused".into())), &cli),
            2
        );
    }

    #[test]
    fn exit_code_0_at_threshold_exactly() {
        let cli = stub_cli(&["pqaudit", "--fail-below", "60", "example.com"]);
        assert_eq!(determine_exit_code(&stub_report(60, None), &cli), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_writes_output_and_returns_zero() {
        let server = tls_server(aws_lc_rs::default_provider(), &[&rustls::version::TLS13]).await;
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("out.json");
        let cli = stub_cli(&[
            "pqaudit",
            "--insecure",
            "--output",
            "json",
            "--output-file",
            output.to_str().unwrap(),
            &format!("127.0.0.1:{}", server.port()),
        ]);
        assert_eq!(run(cli).await, 0);
        let json = std::fs::read_to_string(output).unwrap();
        assert!(json.contains("targets"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_renders_sarif_cbom_and_human_formats() {
        let server = tls_server(aws_lc_rs::default_provider(), &[&rustls::version::TLS13]).await;
        let dir = tempfile::tempdir().unwrap();
        for format in ["sarif", "cbom", "human"] {
            let output = dir.path().join(format!("out.{format}"));
            let cli = stub_cli(&[
                "pqaudit",
                "--insecure",
                "--output",
                format,
                "--output-file",
                output.to_str().unwrap(),
                &format!("127.0.0.1:{}", server.port()),
            ]);
            assert_eq!(run(cli).await, 0);
            let rendered = std::fs::read_to_string(output).unwrap();
            assert!(!rendered.is_empty());
            if format == "human" {
                assert!(
                    !rendered.contains('\u{1b}'),
                    "human file output has ANSI escapes"
                );
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_handles_targets_file_compare_and_human_output() {
        let server = tls_server(aws_lc_rs::default_provider(), &[&rustls::version::TLS13]).await;
        let dir = tempfile::tempdir().unwrap();
        let targets = dir.path().join("targets.txt");
        std::fs::write(
            &targets,
            format!(
                "  127.0.0.1:{}  \n\n127.0.0.1:{}\n",
                server.port(),
                server.port()
            ),
        )
        .unwrap();
        let cli = stub_cli(&[
            "pqaudit",
            "--insecure",
            "--targets-file",
            targets.to_str().unwrap(),
            "--compare",
            "--output",
            "human",
        ]);
        assert_eq!(run(cli).await, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_reports_targets_file_and_output_errors() {
        let cli = stub_cli(&[
            "pqaudit",
            "example.com",
            "--targets-file",
            "/nonexistent/targets.txt",
        ]);
        assert_eq!(run(cli).await, 3);

        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("missing-dir/out.json");
        let cli = stub_cli(&[
            "pqaudit",
            "127.0.0.1:1",
            "--insecure",
            "--output",
            "json",
            "--output-file",
            output.to_str().unwrap(),
        ]);
        assert_eq!(run(cli).await, 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_returns_three_when_no_targets() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("targets.txt");
        std::fs::write(&empty, "").unwrap();
        let cli = stub_cli(&["pqaudit", "--targets-file", empty.to_str().unwrap()]);
        assert_eq!(run(cli).await, 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_reads_baseline_and_prints_diff() {
        let server = tls_server(aws_lc_rs::default_provider(), &[&rustls::version::TLS13]).await;
        let dir = tempfile::tempdir().unwrap();
        let baseline = dir.path().join("baseline.json");
        let cli = stub_cli(&[
            "pqaudit",
            "--insecure",
            "--output",
            "json",
            "--output-file",
            baseline.to_str().unwrap(),
            &format!("127.0.0.1:{}", server.port()),
        ]);
        assert_eq!(run(cli).await, 0);

        let cli = stub_cli(&[
            "pqaudit",
            "--insecure",
            "--baseline",
            baseline.to_str().unwrap(),
            "--output",
            "json",
            &format!("127.0.0.1:{}", server.port()),
        ]);
        assert_eq!(run(cli).await, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_survives_baseline_errors() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.json");
        let cli = stub_cli(&[
            "pqaudit",
            "127.0.0.1:1",
            "--insecure",
            "--baseline",
            missing.to_str().unwrap(),
        ]);
        assert_eq!(run(cli).await, 2);

        let invalid = dir.path().join("invalid.json");
        std::fs::write(&invalid, b"not json").unwrap();
        let cli = stub_cli(&[
            "pqaudit",
            "127.0.0.1:1",
            "--insecure",
            "--baseline",
            invalid.to_str().unwrap(),
        ]);
        assert_eq!(run(cli).await, 2);

        let baseline = dir.path().join("baseline.json");
        std::fs::write(
            &baseline,
            serde_json::to_vec(&stub_report(50, None)).unwrap(),
        )
        .unwrap();
        let mut old = stub_report(50, None);
        old.schema_version = "0.9".into();
        std::fs::write(&baseline, serde_json::to_vec(&old).unwrap()).unwrap();
        let cli = stub_cli(&[
            "pqaudit",
            "127.0.0.1:1",
            "--insecure",
            "--baseline",
            baseline.to_str().unwrap(),
        ]);
        assert_eq!(run(cli).await, 2);
    }
}
