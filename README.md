[![CI](https://github.com/YasogaN/pqaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/YasogaN/pqaudit/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/YasogaN/pqaudit)](https://github.com/YasogaN/pqaudit/releases/latest)

# pqaudit

pqaudit probes any TLS endpoint for post-quantum readiness and scores it against NIST IR 8547,
CNSA 2.0, and FIPS 140-3 — single binary, CI-native, CBOM output.

```sh
$ pqaudit -o human cloudflare.com
pqaudit 0.1.0 — 2026-03-19T14:30:50Z
Compliance mode: NIST IR 8547

  ● cloudflare.com:443  score: 70/100
    HNDL: Medium
    ! [PQA002] Hybrid PQC key exchange requires HelloRetryRequest (group: X25519MLKEM768)
    ! [PQA005] Classical certificate (Leaf) with Ec { curve: "P-256" } deprecated for new use by 2030; disallowed after 2035
    ! [PQA005] Classical certificate (Intermediate { depth: 1 }) with Ec { curve: "P-256" } deprecated for new use by 2030; disallowed after 2035
    ! [PQA005] Classical certificate (Root) with Ec { curve: "P-384" } deprecated for new use by 2030; disallowed after 2035
    ✗ [PQA007] Server accepted TLS downgrade below 1.3
```

---

## Features

### Probing

- **PQC handshake** — connects with `X25519MLKEM768` and `MLKEM1024` key share offers via
  rustls and aws-lc-rs; reports whether the server negotiated hybrid or classical key exchange
- **Cipher suite enumeration** — exhaustively tests supported TLS 1.3 and TLS 1.2 cipher
  suites via raw ClientHello crafting (`--full-scan`)
- **Downgrade detection** — probes with a classical-only ClientHello to detect whether the
  server accepts non-PQC connections
- **HelloRetryRequest detection** — identifies servers that require a retry to negotiate PQC
  groups
- **STARTTLS** — SMTP, IMAP, and POP3 protocol upgrade before TLS probe via URL schemes

### Scoring & Risk

- **0-100 score** — weighted rubric across five categories: key exchange (50 pts), TLS
  version (15), cipher suite (15), certificate chain (15), downgrade posture (5)
- **HNDL risk** — rates harvest-now-decrypt-later exposure as NONE / LOW / MEDIUM / HIGH /
  CRITICAL based on algorithm longevity; use `--sensitivity <low|medium|high|critical>` to
  incorporate data classification into the rating (default: unrated)
- **Compliance modes** — `nist` (NIST IR 8547), `cnsa2` (NSA CNSA 2.0), `fips` (FIPS 140-3)

> pqaudit tests what the **server** supports. Whether the calling client (browser, Go TLS
> library, etc.) actually negotiates PQC is outside scope — check your client library's
> version and cipher group configuration separately.

### Output

- **Human-readable terminal output** — color-coded score, per-finding icons, HNDL rating
- **JSON** (default) — structured report for programmatic consumption
- **SARIF 2.1.0** — for GitHub Code Scanning and IDE integration
- **CycloneDX 1.5 CBOM** — cryptographic bill of materials listing all observed algorithms
- **Baseline diff** — compare current results against a saved baseline to detect regressions

### Integration

- **CI/CD gate** — exits 1 when score falls below a configurable threshold
- **GitHub Actions** — reference workflow for automated PQC auditing with SARIF upload
- **MCP server** — exposes `scan_endpoint`, `compare_endpoints`, and `get_cbom` tools for
  agent-driven workflows; disabled by default (opt in with `--features mcp` at build time to
  avoid pulling `rmcp` and `schemars` into the CLI binary)

---

## Installation

### Pre-built binary

Download the latest release for your platform from the
[Releases](https://github.com/YasogaN/pqaudit/releases) page. All binaries are statically
linked with no runtime dependencies.

```sh
# Linux (x86_64)
curl -Lo pqaudit https://github.com/YasogaN/pqaudit/releases/latest/download/pqaudit-x86_64-unknown-linux-musl
chmod +x pqaudit
sudo mv pqaudit /usr/local/bin/
```

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

# CycloneDX 1.5 CBOM
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

| Mode    | Standard     | Key requirement                                      |
|---------|--------------|------------------------------------------------------|
| `nist`  | NIST IR 8547 | Hybrid key exchange; classical algorithms deprecated |
| `cnsa2` | NSA CNSA 2.0 | ML-KEM-1024 mandatory; exclusive PQC by 2033         |
| `fips`  | FIPS 140-3   | FIPS-approved algorithms only; binary gate scoring   |

See [Compliance Modes](https://github.com/YasogaN/pqaudit/wiki/Compliance-Modes) for full
timelines and algorithm tables.

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

*Developed with AI assistance (Claude, Anthropic). Code reviewed and maintained by human
contributors who take full responsibility for correctness and quality.*
