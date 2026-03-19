# pqaudit

A TLS post-quantum cryptography (PQC) readiness auditor. Audit endpoints against NIST IR 8547
and CNSA 2.0 deadlines, score hybrid key exchange, generate compliance documentation, and
integrate with CI/CD pipelines or AI agents — all from a single static binary.

---

## Background

NIST IR 8547 establishes hard deprecation deadlines: RSA-2048 and ECC P-256 are disallowed
after 2035. Organizations that have not migrated to post-quantum key exchange by then face
compliance failures in classified, federal, and regulated environments. The harvest-now,
decrypt-later (HNDL) threat means that long-lived sensitive data is already at risk today.

pqaudit gives security teams a single command to measure where any TLS endpoint stands against
these timelines, produce audit-ready output, and gate deployments in CI.

---

## Features

- **PQC handshake probing** — performs a live TLS connection using rustls and aws-lc-rs with
  `X25519MLKEM768` and `MLKEM1024` key share offers; reports whether the server negotiated a
  hybrid or classical key exchange
- **Cipher suite enumeration** — exhaustively enumerates supported TLS 1.3 and TLS 1.2 cipher
  suites via raw ClientHello crafting
- **Downgrade detection** — probes with a classical-only ClientHello to detect whether the
  server accepts non-PQC connections
- **Certificate chain audit** — walks the full chain to identify classical signature algorithms
  (RSA, ECDSA) and flag certificates expiring after NIST deadlines
- **HelloRetryRequest detection** — identifies servers that require a retry to negotiate PQC
  groups
- **STARTTLS support** — SMTP, IMAP, POP3, and LDAP protocol upgrade before TLS probe
- **Scored output (0-100)** — weighted rubric across five categories: key exchange (50),
  TLS version (15), cipher suite (15), certificate chain (15), and downgrade posture (5);
  timeline multipliers applied for long-lived assets
- **HNDL risk assessment** — rates harvest-now-decrypt-later exposure as NONE / LOW / MEDIUM
  / HIGH / CRITICAL based on data sensitivity and algorithm longevity
- **Remediation guidance** — per-finding config snippets for nginx, Caddy, OpenSSL, Go, and
  Java
- **Compliance modes** — `--mode nist` (default), `--mode cnsa2`, `--mode fips`
- **Multiple output formats** — human terminal output, JSON, SARIF 2.1.0, CycloneDX 1.5 CBOM
- **Baseline tracking** — diff current results against a saved baseline to detect regressions
- **Batch scanning** — scan multiple targets concurrently from a file
- **CI/CD gate** — exits 1 when score falls below a configurable threshold; integrates with
  GitHub Actions via the bundled action
- **MCP server** — exposes `scan_endpoint`, `compare_endpoints`, and `get_cbom` tools for
  agent-driven workflows

---

## Installation

### Pre-built binary

Download the latest release for your platform from the
[Releases](../../releases) page. All binaries are statically linked with no runtime
dependencies.

```sh
# Linux (x86_64)
curl -Lo pqaudit https://github.com/YOUR_ORG/pqaudit/releases/latest/download/pqaudit-x86_64-unknown-linux-musl
chmod +x pqaudit
sudo mv pqaudit /usr/local/bin/
```

### From source

Requires Rust 1.85 or later.

```sh
cargo install --git https://github.com/YOUR_ORG/pqaudit
```

Or clone and build locally:

```sh
git clone https://github.com/YOUR_ORG/pqaudit
cd pqaudit
cargo build --release
```

The compiled binary is at `target/release/pqaudit`.

---

## Usage

### Audit a single endpoint

```sh
pqaudit example.com:443
```

### Audit with a specific compliance mode

```sh
pqaudit --mode cnsa2 api.example.com:443
```

### Set a score threshold for CI gating

```sh
pqaudit --fail-under 80 api.example.com:443
```

Exit code 1 when the score is below the threshold; 0 on success.

### Output formats

```sh
# Structured JSON
pqaudit --format json api.example.com:443

# SARIF 2.1.0 (for GitHub Code Scanning, IDE integration)
pqaudit --format sarif api.example.com:443 > results.sarif

# CycloneDX 1.5 CBOM (cryptographic bill of materials)
pqaudit --format cbom api.example.com:443 > cbom.json
```

### Batch scan from a file

```sh
pqaudit --targets targets.txt --concurrency 10 --format json
```

### Save and compare baselines

```sh
# Save current results as baseline
pqaudit --format json api.example.com:443 > baseline.json

# Compare a future scan against the baseline
pqaudit --baseline baseline.json api.example.com:443
```

### STARTTLS protocols

```sh
pqaudit --starttls smtp mail.example.com:587
pqaudit --starttls imap mail.example.com:993
```

### MCP server mode

```sh
pqaudit --mcp
```

Starts a stdio-based MCP server. Configure your agent to connect to it and use
`scan_endpoint`, `compare_endpoints`, or `get_cbom`.

---

## GitHub Action

Add PQC scoring to any workflow:

```yaml
- name: Audit TLS PQC readiness
  uses: YOUR_ORG/pqaudit@v1
  with:
    target: api.example.com:443
    fail-under: 80
    mode: nist
```

The action sets output variables `score`, `grade`, and `hndl_risk`, and uploads a SARIF
report to GitHub Code Scanning when `upload-sarif` is set to `true`.

---

## Score interpretation

| Range    | Grade | Meaning                                           |
|----------|-------|---------------------------------------------------|
| 90 - 100 | A     | Full PQC readiness; meets all current deadlines   |
| 80 - 89  | B     | PQC negotiation active; minor gaps remain         |
| 60 - 79  | C     | Hybrid capable but classical fallback accepted    |
| 40 - 59  | D     | Minimal PQC support; significant exposure         |
| 0 - 39   | F     | Classical-only; critical HNDL risk                |

---

## Exit codes

| Code | Meaning                                      |
|------|----------------------------------------------|
| 0    | Success; score at or above threshold         |
| 1    | Score below `--fail-under` threshold         |
| 2    | All targets failed to connect or probe       |
| 3    | Invalid arguments                            |

---

## Compliance modes

| Mode      | Standard          | Key requirement                                      |
|-----------|-------------------|------------------------------------------------------|
| `nist`    | NIST IR 8547      | Hybrid key exchange; classical algorithms deprecated |
| `cnsa2`   | NSA CNSA 2.0      | ML-KEM-1024 mandatory; exclusive PQC by 2033         |
| `fips`    | FIPS 140-3        | FIPS-approved algorithms only                        |

---

## AI Disclosure

This project was developed with the assistance of an AI coding assistant (Claude by Anthropic).
The design specification, implementation plan, source code, tests, CI/CD configuration, and
documentation were all produced in whole or in part through AI-assisted development sessions.
All code has been reviewed and the project is maintained by human contributors who take full
responsibility for its correctness and quality.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on reporting issues, proposing changes,
and submitting pull requests.

---

## Code of Conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md). All contributors are
expected to uphold its standards.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.
