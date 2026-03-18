use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, ValueEnum, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ComplianceMode {
    Nist,
    Cnsa2,
    Fips,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Json,
    Sarif,
    Cbom,
    Human,
}

#[derive(Debug, Parser)]
#[command(name = "pqaudit", about = "TLS post-quantum readiness auditor")]
pub struct Cli {
    /// Hosts to scan: example.com, example.com:8443, smtp://mail.example.com
    #[arg(required_unless_present = "targets_file")]
    pub targets: Vec<String>,

    // Scan behavior
    #[arg(short = 'f', long)]
    pub full_scan: bool,
    #[arg(long, default_value = "10")]
    pub concurrency: usize,
    #[arg(long, default_value = "5000")]
    pub timeout: u64,
    #[arg(long)]
    pub sni: Option<String>,
    #[arg(long, default_value = "2030")]
    pub q_day: u32,

    // Compliance
    #[arg(long, default_value = "nist")]
    pub compliance: ComplianceMode,

    // Output
    #[arg(short = 'o', long, default_value = "json")]
    pub output: OutputFormat,
    #[arg(long)]
    pub output_file: Option<std::path::PathBuf>,
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=100))]
    pub fail_below: Option<u8>,

    // Comparison & tracking
    #[arg(long)]
    pub baseline: Option<std::path::PathBuf>,
    #[arg(long)]
    pub compare: bool,

    // Targets from file
    #[arg(long)]
    pub targets_file: Option<std::path::PathBuf>,

    // Agent mode (MCP feature only)
    #[cfg(feature = "mcp")]
    #[arg(long)]
    pub mcp: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_single_target() {
        let args = Cli::try_parse_from(["pqaudit", "example.com"]).unwrap();
        assert_eq!(args.targets, vec!["example.com".to_string()]);
    }

    #[test]
    fn parses_fail_below() {
        let args = Cli::try_parse_from(["pqaudit", "--fail-below", "80", "example.com"]).unwrap();
        assert_eq!(args.fail_below, Some(80u8));
    }

    #[test]
    fn default_compliance_is_nist() {
        let args = Cli::try_parse_from(["pqaudit", "example.com"]).unwrap();
        assert!(matches!(args.compliance, ComplianceMode::Nist));
    }

    #[test]
    fn rejects_fail_below_over_100() {
        let result = Cli::try_parse_from(["pqaudit", "--fail-below", "101", "example.com"]);
        assert!(result.is_err());
    }
}
