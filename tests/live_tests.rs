//! Live network tests against widely used public TLS endpoints.
//!
//! These tests are opt-in because they depend on external services and DNS:
//!
//! ```sh
//! cargo test --features live-tests --test live_tests -- --nocapture
//! ```
//!
//! They are intentionally separate from the default test run and PR CI. A
//! scheduled workflow runs them daily so failures surface as a signal that an
//! endpoint's configuration or the probe changed.

#![cfg(feature = "live-tests")]

use futures::future::join_all;
use pqaudit::output::{cbom, human, json, sarif};
use pqaudit::probe::downgrade::probe_downgrade;
use pqaudit::probe::pqc_probe::{pqc_probe, ProbeConfig};
use pqaudit::scanner::{scan, ScanConfig};
use pqaudit::{DowngradeResult, ScanReport, TlsVersion};
use std::process::Command;

const TIMEOUT_MS: u64 = 15_000;

#[derive(Clone, Copy)]
struct LiveTarget {
    host: &'static str,
    /// Endpoints known to deploy a post-quantum hybrid key exchange today.
    expect_pqc: bool,
}

const TARGETS: &[LiveTarget] = &[
    LiveTarget {
        host: "cloudflare.com",
        expect_pqc: true,
    },
    LiveTarget {
        host: "www.google.com",
        expect_pqc: true,
    },
    LiveTarget {
        host: "aws.amazon.com",
        expect_pqc: true,
    },
    LiveTarget {
        host: "www.microsoft.com",
        expect_pqc: true,
    },
    LiveTarget {
        host: "www.apple.com",
        expect_pqc: true,
    },
    LiveTarget {
        host: "www.mozilla.org",
        expect_pqc: true,
    },
    LiveTarget {
        host: "github.com",
        expect_pqc: false,
    },
    LiveTarget {
        host: "en.wikipedia.org",
        expect_pqc: false,
    },
];

fn probe_config() -> ProbeConfig {
    ProbeConfig {
        timeout_ms: TIMEOUT_MS,
        ..ProbeConfig::default()
    }
}

fn scan_config(full_scan: bool) -> ScanConfig {
    ScanConfig {
        timeout_ms: TIMEOUT_MS,
        full_scan,
        concurrency: 4,
        ..ScanConfig::default()
    }
}

fn target_hosts() -> Vec<String> {
    TARGETS
        .iter()
        .map(|target| target.host.to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_primary_handshake_matrix() {
    let config = probe_config();
    let results = join_all(TARGETS.iter().map(|target| {
        let config = config.clone();
        async move { (*target, pqc_probe(target.host, 443, None, &config).await) }
    }))
    .await;

    for (target, result) in results {
        let result = result.unwrap_or_else(|error| panic!("{}: {error}", target.host));
        assert_eq!(
            result.negotiated_version,
            TlsVersion::Tls13,
            "{} did not negotiate TLS 1.3",
            target.host
        );
        assert!(
            !result.cert_chain_der.is_empty(),
            "{} returned no certificate chain",
            target.host
        );
        assert_ne!(
            result.negotiated_group.code_point, 0,
            "{} returned no negotiated group",
            target.host
        );
        assert_ne!(
            result.negotiated_suite.id, 0,
            "{} returned no negotiated cipher suite",
            target.host
        );
        if target.expect_pqc {
            assert!(
                result.negotiated_group.is_pqc,
                "{} did not negotiate a PQC group (got {})",
                target.host, result.negotiated_group.name
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_downgrade_matrix() {
    let results = join_all(TARGETS.iter().map(|target| async move {
        (
            *target,
            probe_downgrade(target.host, 443, target.host, "", TIMEOUT_MS).await,
        )
    }))
    .await;

    for (target, result) in results {
        match result {
            DowngradeResult::Accepted { negotiated_version } => {
                assert!(
                    matches!(
                        negotiated_version,
                        TlsVersion::Tls12 | TlsVersion::Tls11 | TlsVersion::Tls10
                    ),
                    "{} reported an accepted downgrade with {negotiated_version}",
                    target.host
                );
            }
            DowngradeResult::Rejected | DowngradeResult::Timeout => {}
            DowngradeResult::Error(reason) => {
                panic!("{} downgrade probe errored: {reason}", target.host);
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_scan_all_targets() {
    let hosts = target_hosts();
    let report = scan(hosts.clone(), &scan_config(false)).await;

    assert_eq!(report.targets.len(), hosts.len());
    for (target, expected) in report.targets.iter().zip(TARGETS) {
        assert_eq!(target.target, expected.host);
        assert!(
            target.error.is_none(),
            "{}: {:?}",
            target.target,
            target.error
        );
        assert!(target.score.total <= 100);
        assert!(
            target
                .cert_chain
                .as_ref()
                .is_some_and(|chain| !chain.entries.is_empty()),
            "{} has no audited certificate chain",
            target.target
        );
        assert!(
            !matches!(&target.downgrade, DowngradeResult::Error(_)),
            "{}: downgrade probe errored: {:?}",
            target.target,
            target.downgrade
        );
        let group = target
            .negotiated_group
            .as_ref()
            .unwrap_or_else(|| panic!("{}: no negotiated group", target.target));
        if expected.expect_pqc {
            assert!(
                group.is_pqc,
                "{} reported a classical group ({})",
                target.target, group.name
            );
        }
    }

    // The report must survive a JSON round trip unchanged in shape.
    let encoded = serde_json::to_string(&report).expect("serialize live report");
    let decoded: ScanReport = serde_json::from_str(&encoded).expect("deserialize live report");
    assert_eq!(decoded.targets.len(), report.targets.len());
    assert_eq!(decoded.schema_version, report.schema_version);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_full_scan_and_output_formats() {
    let report = scan(vec!["cloudflare.com".to_string()], &scan_config(true)).await;
    let target = &report.targets[0];

    assert!(target.error.is_none(), "{:?}", target.error);
    let inventory = target
        .cipher_inventory
        .as_ref()
        .expect("full scan should produce a cipher inventory");
    assert!(
        !inventory.tls13_suites.is_empty(),
        "no TLS 1.3 cipher suites enumerated"
    );
    assert!(
        !inventory.tls12_suites.is_empty(),
        "no TLS 1.2 cipher suites enumerated"
    );
    assert!(
        target
            .cert_chain
            .as_ref()
            .is_some_and(|chain| !chain.entries.is_empty()),
        "no audited certificate chain"
    );

    let json_text = json::render_json(&report);
    let json_value: serde_json::Value =
        serde_json::from_str(&json_text).expect("valid JSON output");
    assert_eq!(json_value["schema_version"], "1.0");
    assert_eq!(json_value["targets"].as_array().unwrap().len(), 1);

    let sarif_text = sarif::render_sarif(&report);
    let sarif_value: serde_json::Value =
        serde_json::from_str(&sarif_text).expect("valid SARIF output");
    assert_eq!(sarif_value["version"], "2.1.0");
    assert_eq!(sarif_value["runs"].as_array().unwrap().len(), 1);

    let cbom_text = cbom::render_cbom(&report);
    let cbom_value: serde_json::Value =
        serde_json::from_str(&cbom_text).expect("valid CBOM output");
    assert_eq!(cbom_value["bomFormat"], "CycloneDX");
    assert_eq!(cbom_value["specVersion"], "1.6");
    assert!(
        !cbom_value["components"].as_array().unwrap().is_empty(),
        "CBOM should contain cryptographic asset components"
    );

    let human_text = human::render_human(&report, false);
    assert!(human_text.contains("cloudflare.com"));
    assert!(!human_text.trim().is_empty());
}

#[test]
fn live_cli_binary_scans_popular_endpoint() {
    let executable = env!("CARGO_BIN_EXE_pqaudit");
    let output = Command::new(executable)
        .args(["--timeout", "15000", "-o", "json", "cloudflare.com"])
        .output()
        .expect("run the pqaudit binary");

    assert!(
        output.status.success(),
        "pqaudit exited with {:?}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let report: ScanReport =
        serde_json::from_slice(&output.stdout).expect("CLI should emit a valid JSON report");
    assert_eq!(report.targets.len(), 1);
    assert_eq!(report.targets[0].target, "cloudflare.com");
    assert!(report.targets[0].error.is_none());
    assert!(report.targets[0].negotiated_group.is_some());
}
