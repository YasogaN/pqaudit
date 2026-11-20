[![CI](https://github.com/YasogaN/pqaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/YasogaN/pqaudit/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/YasogaN/pqaudit)](https://github.com/YasogaN/pqaudit/releases/latest)

# pqaudit

pqaudit probes any TLS endpoint for post-quantum readiness and scores it against NIST IR 8547 (draft), CNSA 2.0, and FIPS 140-3 — single binary, CI-native, CBOM output.

```sh
$ pqaudit -o human cloudflare.com
pqaudit 0.3.0 — 2026-10-27T10:30:00Z
Compliance mode: NIST IR 8547

  ● cloudflare.com:443  score: 85/100
    HNDL: Medium
    ! [PQA002] Hybrid PQC key exchange requires HelloRetryRequest (group: X25519MLKEM768)
    ! [PQA006] Classical certificate (Leaf) with Ec { curve: "P-256" } must migrate by 2035
    ! [PQA013] Server accepts a classical-only TLS 1.3 key exchange (PQC is not enforced)
```

The probe completes a real rustls/aws-lc-rs handshake, reads the negotiated group directly from the session, and separately tests whether the server still accepts a classical-only TLS 1.3 key exchange, TLS 1.2 downgrades, and legacy TLS 1.0/1.1.

---

## Features

### Probing

- **Real PQC handshake** — completes a rustls/aws-lc-rs handshake with the provider's post-quantum preference (`X25519MLKEM768`) and reads the negotiated key-exchange group directly from the completed session.
- **Classical fallback check** — separately attempts a TLS 1.3 handshake using only classical groups, so “PQC available” is distinguished from “PQC enforced”.
- **Cipher suite enumeration** — exhaustively probes TLS 1.3 and TLS 1.2 cipher suites via raw ClientHellos (`--full-scan`).
- **Downgrade detection** — probes with a classical-only TLS 1.2 ClientHello to detect whether the server accepts a downgrade.
- **HelloRetryRequest detection** — identifies servers that require an HRR to negotiate a PQC group.
- **Legacy protocol detection** — checks whether TLS 1.0 or TLS 1.1 is still accepted.
- **STARTTLS** — performs the SMTP, IMAP, or POP3 upgrade before the TLS probe via URL schemes; implicit TLS variants (`smtps://`, `imaps://`, `pop3s://`, `ldaps://`) connect directly.
- **Resilient auditing** — if verified certificate validation fails, the probe retries without validation, captures the chain, and reports the validation error as a finding instead of losing the scan.
- **Private CAs** — `--ca-file <pem-or-der>` adds trust anchors for internal endpoints; `--insecure` skips validation entirely (the chain is still parsed and audited).

### Certificate auditing

- Parses RSA modulus bits, DSA, NIST EC curves, Ed25519/Ed448, ML-KEM, ML-DSA, and SLH-DSA subject public keys.
- Reports classical certificate keys against the active compliance deadlines, weak MD5/SHA-1 signatures, expired certificates, unparseable chain entries, and certificates that outlive their algorithm deadline.
- Scores the chain out of 15 points: 15 for an all-PQC chain, 10 when the leaf is PQC but a CA is classical, 5 when a PQC CA signs a classical leaf, and 0 for a fully classical chain.

### Scoring & Risk

- **0-100 score** — weighted rubric across five categories: key exchange (50 pts), TLS version (15), cipher suite (15), certificate chain (15), downgrade/PQC-enforcement posture (5).
- **HNDL risk** — rates harvest-now-decrypt-later exposure as NONE / LOW / MEDIUM / HIGH / CRITICAL based on algorithm longevity.
- **Compliance modes** — `nist` (NIST IR 8547 draft), `cnsa2` (NSA CNSA 2.0), `fips` (FIPS 140-3 algorithm approvals).
- **Stable rule IDs** — findings map to SARIF rules `PQA001`–`PQA015`, including classical fallback, legacy TLS, certificate validation, weak signatures, and expiry.

> pqaudit tests what the **server** supports. Whether the calling client (browser, Go TLS library, etc.) actually negotiates PQC is outside scope — check your client library's version and cipher group configuration separately.

### Output

- **Human-readable terminal output** — color-coded score, per-finding icons, HNDL rating.
- **JSON** (default) — structured report for programmatic consumption, including negotiated group, cipher suite, chain entries, fallback status, and legacy protocols.
- **SARIF 2.1.0** — for GitHub Code Scanning and IDE integration.
- **CycloneDX 1.6 CBOM** — cryptographic bill of materials listing observed key-exchange groups, cipher suites, and certificate key algorithms.
- **Baseline diff** — compare current results against a saved baseline to detect regressions.

### Integration

- **CI/CD gate** — exits 1 when the score falls below a configurable threshold; exits 2 when every target fails to probe.
- **GitHub Actions** — publishes findings to GitHub Code Scanning via SARIF on every push.
- **MCP server** — exposes `scan_endpoint`, `compare_endpoints`, and `get_cbom` tools for agent-driven workflows; enabled by default. Build with `--no-default-features` to omit the `rmcp` and `schemars` dependencies.

---

## Installation

### Pre-built binary

Download the latest release for your platform from the
[Releases](https://github.com/YasogaN/pqaudit/releases) page. Linux binaries are statically linked with musl; macOS and Windows binaries use their platform runtime.

| Platform | Artifact |
|---|---|
| Linux x86_64 (musl, static) | `pqaudit-linux-x86_64` |
| Linux aarch64 (musl, static) | `pqaudit-linux-aarch64` |
| macOS Intel | `pqaudit-macos-x86_64` |
| macOS Apple silicon | `pqaudit-macos-aarch64` |
| Windows x86_64 | `pqaudit-windows-x86_64.exe` |
| Checksums | `SHA256SUMS` |

```sh
# Linux (x86_64)
curl -Lo pqaudit https://github.com/YasogaN/pqaudit/releases/latest/download/pqaudit-linux-x86_64
chmod +x pqaudit
sudo mv pqaudit /usr/local/bin/
```

### From crates.io

The crate is published as `pqaudit`. This installs the latest published release:

```sh
cargo install pqaudit
```

Stable releases are published to crates.io; prerelease tags only create a GitHub prerelease.

### From source

Requires Rust 1.85 or later.

```sh
cargo install --git https://github.com/YasogaN/pqaudit
```

Or clone and build locally:

```sh
git clone https://github.com/YasogaN/pqaudit
cd pqaudit
cargo build --release
# Binary at target/release/pqaudit
```

---

## Quick Start

### Basic scan (JSON output)

```sh
pqaudit example.com:443
```

Default output is JSON. Pipe to `jq` for readable output:

```sh
pqaudit example.com:443 | jq .
```

### Human-readable output

```sh
pqaudit -o human example.com:443
```

### Compliance mode

```sh
pqaudit --compliance cnsa2 example.com:443
```

Available modes: `nist` (default), `cnsa2`, `fips`.

### CI gate — fail below a score threshold

```sh
pqaudit --fail-below 80 example.com:443
```

Exits 1 if the score is below the threshold; 0 on success. See [Exit codes](#exit-codes).

### Output formats

```sh
# Human-readable terminal output
pqaudit -o human example.com:443

# SARIF 2.1.0 (GitHub Code Scanning, IDEs)
pqaudit -o sarif example.com:443 > results.sarif

# CycloneDX 1.6 CBOM
pqaudit -o cbom example.com:443 > cbom.json

# Write output to a file instead of stdout
pqaudit -o json --output-file results.json example.com:443
```

### Full cipher enumeration

```sh
pqaudit --full-scan example.com:443
```

Enumerates all supported cipher suites via raw ClientHello probing. Slower but produces a
complete `cipher_inventory` in the report. Note: sequential ClientHello probing against
WAF-protected or rate-limited targets may produce false negatives — missing suites in the
inventory do not guarantee they are unsupported.

### Batch scan

```sh
# targets.txt: one host per line, blank lines ignored
pqaudit --targets-file targets.txt --concurrency 10
```

### Baseline tracking

```sh
# Save a baseline
pqaudit -o json example.com:443 > baseline.json

# Compare a later scan against the baseline (diff printed to stderr)
pqaudit --baseline baseline.json example.com:443
```

### STARTTLS protocols

Pass a URL scheme to trigger STARTTLS before the TLS probe:

```sh
pqaudit smtp://mail.example.com:587
pqaudit imap://mail.example.com:993
pqaudit pop3://mail.example.com:110
```

For implicit-TLS connections (direct TLS, no upgrade): use `smtps://`, `imaps://`, `pop3s://`,
or `ldaps://`.

### SNI override and custom timeout

```sh
# Override SNI (useful for IP targets or split-horizon DNS)
pqaudit --sni api.example.com 203.0.113.5:443

# Set connect/handshake timeout in milliseconds (default: 5000)
pqaudit --timeout 10000 example.com:443
```

### Private CAs and untrusted endpoints

```sh
# Add a PEM bundle or DER certificate as a trust anchor
pqaudit --ca-file internal-ca.pem internal.example.com:443

# Audit an endpoint with an expired/self-signed chain; the chain is still captured
pqaudit --insecure staging.example.com:443
```

### Legacy TLS and fallback signals

The normal probe already reports:

- whether a PQC group was negotiated and whether it required an HRR,
- whether the server still accepts a classical-only TLS 1.3 key exchange (`PQA013`),
- whether TLS 1.2 downgrades are accepted (`PQA007`),
- whether TLS 1.0/1.1 are still accepted (`PQA014`),
- whether the verified chain failed validation (`PQA015`).

### MCP server mode

```sh
pqaudit --mcp
```

Starts a stdio-based MCP server exposing `scan_endpoint`, `compare_endpoints`, and `get_cbom`.
See the [MCP Integration](https://github.com/YasogaN/pqaudit/wiki/MCP-Integration) wiki page
for setup and tool schemas.

---

## Reference

### Score grades

| Range    | Grade | Meaning                                           |
|----------|-------|---------------------------------------------------|
| 90 – 100 | A     | Full PQC readiness; meets all current deadlines   |
| 80 – 89  | B     | PQC negotiation active; minor gaps remain         |
| 60 – 79  | C     | Hybrid capable but classical fallback accepted    |
| 40 – 59  | D     | Minimal PQC support; significant exposure         |
| 0 – 39   | F     | Classical-only; critical HNDL risk                |

See the [Scoring System](https://github.com/YasogaN/pqaudit/wiki/Scoring-System) wiki page for
the full weighted rubric and HNDL model.

### Exit codes

| Code | Meaning                                      |
|------|----------------------------------------------|
| 0    | Success; score at or above threshold         |
| 1    | Score below `--fail-below` threshold         |
| 2    | All targets failed to connect or probe       |
| 3    | Invalid arguments                            |

Exit 2 takes priority: it fires when all targets error regardless of `--fail-below`. See
[CI/CD Integration](https://github.com/YasogaN/pqaudit/wiki/CI-CD-Integration) for full
semantics and workflow examples.

### Compliance modes

| Mode    | Standard     | Key requirement |
|---------|--------------|-----------------|
| `nist`  | NIST IR 8547 (IPD) | 112-bit quantum-vulnerable algorithms deprecated after 2030 and disallowed after 2035; ≥128-bit variants disallowed after 2035. |
| `cnsa2` | NSA CNSA 2.0 | New NSS acquisitions by 2027; exclusive use by 2030 for networking/signing and 2033 for web/OS/other systems; ML-KEM-1024 and ML-DSA-87 required. |
| `fips`  | FIPS 140-3 | Algorithm-approval gates only. This mode does not apply NIST IR 8547 transition deadlines. |

NIST IR 8547 is still an Initial Public Draft; the deadline table is centralised in `src/audit/tables/nist_ir8547.rs` so a final publication can be adopted in one place. See [Compliance Modes](https://github.com/YasogaN/pqaudit/wiki/Compliance-Modes) for the full tables.

---

## GitHub Action

pqaudit is published to the [GitHub Marketplace](https://github.com/marketplace/actions/pqaudit-tls-scan).
Drop the following into `.github/workflows/pqaudit.yml` to scan your production endpoint on
every push and publish findings to Security → Code Scanning:

```yaml
name: PQC Audit
on: push
jobs:
  pqc-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: YasogaN/pqaudit@v0
        with:
          targets: api.example.com
```

The action downloads the Linux x86_64 binary, so run it on `ubuntu-latest`.

### Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `targets` | yes | — | Space-separated list of hosts to scan (`host`, `host:port`, `smtp://host`) |
| `compliance` | no | `nist` | Scoring framework: `nist`, `cnsa2`, or `fips` |
| `fail-below` | no | `0` | Exit 1 if PQC score is below this threshold (0 disables the check) |
| `upload-sarif` | no | `true` | Upload SARIF to GitHub Code Scanning (requires `security-events: write`) |

### Outputs

| Output | Description |
|---|---|
| `sarif-file` | Absolute path to the generated SARIF file (useful if `upload-sarif: false`) |

### Advanced usage

```yaml
- uses: YasogaN/pqaudit@v0
  with:
    targets: api.example.com api2.example.com:8443
    compliance: cnsa2
    fail-below: 80
    upload-sarif: false   # handle upload yourself

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.pqaudit.outputs.sarif-file }}
    category: pqc-audit
```

---

## Testing

```sh
# Unit + integration tests (in-process TLS/STARTTLS servers; no network required)
cargo test --locked --no-default-features
cargo test --locked --features mcp

# Live matrix against popular public endpoints (requires network access)
cargo test --locked --features live-tests --test live_tests -- --nocapture

# Verify crates.io packaging without uploading
cargo publish --dry-run --locked

# 100% line-coverage check (excludes the test-only src/test_support.rs harness)
cargo llvm-cov --no-default-features --features mcp --workspace --all-targets \
  --ignore-filename-regex 'src/test_support.rs' --lcov --output-path lcov.info
```

The integration suite starts real rustls servers, including SMTP STARTTLS and HTTP-style raw ClientHello responders, so certificate capture, PQC negotiation, HRR detection, classical fallback, legacy probes, cipher enumeration, and error paths are exercised without external services. The live suite probes Cloudflare, Google, AWS, Microsoft, Apple, Mozilla, GitHub, and Wikipedia, then checks TLS 1.3, PQC negotiation where expected, certificate capture, downgrade classification, the full scan pipeline, every output format, and the compiled CLI. It runs nightly and on demand via the `Live TLS tests` workflow, separately from PR CI.

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

---

*Initially developed with Anthropic's Claude and Claude Code. Later development, hardening, and testing were assisted by DeepSeek V4.1 Flash, DeepSeek V4.1 Flash (1017), and OpenCode. Code reviewed and maintained by human contributors who take full responsibility for correctness and quality.*
