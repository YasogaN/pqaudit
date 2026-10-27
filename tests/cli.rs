use std::process::{Command, Stdio};

fn pqaudit() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pqaudit"))
}

#[test]
fn missing_targets_is_a_usage_error() {
    let output = pqaudit().output().expect("run pqaudit");
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stderr).contains("No targets specified"));
}

#[test]
fn unreachable_target_exits_2() {
    let output = pqaudit()
        .args(["--insecure", "--output", "json", "127.0.0.1:1"])
        .output()
        .expect("run pqaudit");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stdout).contains("targets"));
}

#[test]
fn mcp_mode_exits_when_stdin_is_closed() {
    let output = pqaudit()
        .args(["--mcp", "example.com"])
        .stdin(Stdio::null())
        .output()
        .expect("run pqaudit --mcp");
    assert!(
        matches!(output.status.code(), Some(0) | Some(3)),
        "unexpected MCP exit: {:?}",
        output.status
    );
}

#[test]
fn invalid_flag_is_a_usage_error() {
    let output = pqaudit()
        .arg("--definitely-not-a-flag")
        .output()
        .expect("run pqaudit");
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument"));
}

#[test]
fn help_exits_zero() {
    let output = pqaudit()
        .arg("--help")
        .output()
        .expect("run pqaudit --help");
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage"));
    assert!(output.stderr.is_empty());
}
