# README & Wiki Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the stale pqaudit README with a polished, accurate B/C-style document and create 9 detailed GitHub wiki pages covering the full reference documentation.

**Architecture:** Two independent deliverables: (1) overwrite `README.md` in the main repo, commit, push; (2) clone the wiki git repo, write 9 `.md` pages, push. All content verified against source code before writing.

**Tech Stack:** Markdown, GitHub wiki (separate git repo at `https://github.com/YasogaN/pqaudit.wiki.git`), Rust source for verification.

**Spec:** `docs/superpowers/specs/2026-03-19-readme-wiki-overhaul-design.md`

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Overwrite | `README.md` | Main project README |
| Create | `wiki/Home.md` | Wiki landing page and navigation index |
| Create | `wiki/Scoring-System.md` | Full weighted rubric, HNDL model |
| Create | `wiki/Finding-Codes.md` | PQA001–PQA009 reference |
| Create | `wiki/Compliance-Modes.md` | NIST/CNSA2/FIPS deep-dive |
| Create | `wiki/Output-Formats.md` | JSON schema, SARIF, CBOM, human anatomy |
| Create | `wiki/CI-CD-Integration.md` | GitHub Actions, GitLab CI, exit codes |
| Create | `wiki/MCP-Integration.md` | Tool schemas, Claude Desktop config |
| Create | `wiki/Baseline-Tracking.md` | Baseline workflow, diff format |
| Create | `wiki/STARTTLS.md` | Protocol details, scheme reference |

Wiki files are written locally to a `wiki/` directory (the cloned wiki repo), not inside the main repo.

---

## Source Files Reference

Before writing any wiki page, read the listed source files. All line numbers are approximate — re-verify logic in the named file.

| Wiki page | Source files to read |
|-----------|----------------------|
| Scoring-System | `src/audit/scoring/weighted.rs`, `src/audit/scoring/model.rs`, `src/audit/scoring/binary_gates.rs`, `src/audit/scoring/cnsa2_strict.rs`, `src/audit/hndl.rs` |
| Finding-Codes | `src/output/sarif.rs`, `src/audit/findings.rs`, `src/audit/remediation.rs`, `src/audit/scoring/weighted.rs` |
| Compliance-Modes | `src/audit/tables/nist_ir8547.rs`, `src/audit/tables/cnsa2.rs`, `src/audit/tables/fips.rs`, `src/audit/compliance.rs` |
| Output-Formats | `src/output/json.rs`, `src/output/sarif.rs`, `src/output/cbom.rs`, `src/output/human.rs`, `src/lib.rs` |
| CI-CD-Integration | `src/main.rs` (exit code logic), `src/cli/mod.rs` |
| MCP-Integration | `src/mcp/mod.rs` |
| Baseline-Tracking | `src/baseline/mod.rs`, `src/main.rs` |
| STARTTLS | `src/probe/starttls.rs` |

---

## Task 1: Overwrite README.md

**Files:**
- Overwrite: `README.md`

- [ ] **Step 1: Replace README.md with the new content below**

Write the following exactly as shown. The demo block is static output captured from `./target/release/pqaudit -o human cloudflare.com` with ANSI escape codes stripped. If you want fresher output, rebuild (`cargo build --release`) and re-run, but strip all ANSI before embedding.

```markdown
[![CI](https://github.com/YasogaN/pqaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/YasogaN/pqaudit/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/YasogaN/pqaudit)](https://github.com/YasogaN/pqaudit/releases/latest)

# pqaudit

Audit any TLS endpoint for post-quantum cryptography readiness in seconds. With NIST's 2035
deadline approaching and harvest-now-decrypt-later attacks active today, there's no safer time
to know where your services stand.

```sh
$ pqaudit -o human cloudflare.com
pqaudit 0.1.0 — 2026-03-19T14:30:50Z
Compliance mode: NIST IR 8547

  ● cloudflare.com:443  score: 70/100
    HNDL: Medium
    ! [PQA002] Hybrid PQC key exchange requires HelloRetryRequest (group: X25519MLKEM768)
    ! [PQA005] Classical certificate (Leaf) with Ec { curve: "P-256" } must migrate by 2030
    ! [PQA005] Classical certificate (Intermediate { depth: 1 }) with Ec { curve: "P-256" } must migrate by 2030
    ! [PQA005] Classical certificate (Root) with Ec { curve: "P-384" } must migrate by 2030
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
  CRITICAL based on algorithm longevity and data sensitivity
- **Compliance modes** — `nist` (NIST IR 8547), `cnsa2` (NSA CNSA 2.0), `fips` (FIPS 140-3)

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
  agent-driven workflows

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
complete `cipher_inventory` in the report.

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
```

- [ ] **Step 2: Verify the README renders correctly and all flags are accurate**

Check against `src/cli/mod.rs`: confirm `--compliance`, `--fail-below`, `-o`/`--output`, `--targets-file`, `--full-scan`, `--baseline`, `--sni`, `--timeout`, `--concurrency`, `--output-file`, `--mcp` all match exactly.

Run:
```sh
grep -n "YOUR_ORG\|--mode\|--format\|--fail-under\|--targets " README.md
```
Expected: no output (none of those stale strings remain).

- [ ] **Step 3: Commit**

```sh
git add README.md
git commit -m "docs: overhaul README with accurate CLI reference and wiki links"
```

---

## Task 2: Clone wiki repo

**Files:**
- Create: `wiki/` directory (cloned from `https://github.com/YasogaN/pqaudit.wiki.git`)

- [ ] **Step 1: Clone the wiki repo**

```sh
git clone https://github.com/YasogaN/pqaudit.wiki.git wiki
```

If the wiki hasn't been initialized yet on GitHub, go to the repo → Wiki tab → create the first page manually in the UI (GitHub requires at least one page to activate the wiki), then clone.

- [ ] **Step 2: Confirm the clone succeeded**

```sh
ls wiki/
```

Expected: one or more `.md` files (or an empty directory if freshly initialized).

---

## Task 3: Wiki — Home page

**Files:**
- Create/overwrite: `wiki/Home.md`

- [ ] **Step 1: Write `wiki/Home.md`**

```markdown
# pqaudit Wiki

**pqaudit** audits TLS endpoints for post-quantum cryptography (PQC) readiness. It probes live
servers, scores them against NIST IR 8547 timelines, assesses harvest-now-decrypt-later (HNDL)
exposure, and outputs results in multiple formats — all from a single static binary.

## Use Cases

- **Security audits** — measure where your endpoints stand against NIST's 2035 deprecation
  deadline for RSA and ECC
- **CI/CD gating** — fail builds when PQC readiness drops below a threshold
- **Agent workflows** — use the MCP server to drive pqaudit from Claude or other AI agents
- **Compliance reporting** — produce SARIF, CycloneDX CBOM, or JSON reports for audit trails

## Pages

| Page | Contents |
|------|----------|
| [Scoring System](Scoring-System) | Weighted rubric, point values, HNDL model, grade table |
| [Finding Codes](Finding-Codes) | PQA001–PQA009 reference with remediation snippets |
| [Compliance Modes](Compliance-Modes) | NIST IR 8547, CNSA 2.0, FIPS 140-3 deep-dive |
| [Output Formats](Output-Formats) | JSON schema, SARIF 2.1.0, CycloneDX 1.5 CBOM, human output |
| [CI/CD Integration](CI-CD-Integration) | GitHub Actions, GitLab CI, exit code semantics |
| [MCP Integration](MCP-Integration) | Tool schemas, Claude Desktop config, example sessions |
| [Baseline Tracking](Baseline-Tracking) | Save/compare baselines, diff format, CI pattern |
| [STARTTLS](STARTTLS) | Protocol details, URL scheme reference, port defaults |

## Quick Links

- [Installation](https://github.com/YasogaN/pqaudit#installation)
- [Quick Start](https://github.com/YasogaN/pqaudit#quick-start)
- [CI/CD Integration](CI-CD-Integration)
- [MCP Integration](MCP-Integration)
```

- [ ] **Step 2: Commit**

```sh
cd wiki
git add Home.md
git commit -m "wiki: add Home page"
```

---

## Task 4: Wiki — Scoring System

**Files:**
- Create: `wiki/Scoring-System.md`

- [ ] **Step 1: Read source files**

Read these files in full before writing:
- `src/audit/scoring/weighted.rs` — point values for all categories
- `src/audit/scoring/model.rs` — ScoringResult struct, ScoringModel trait
- `src/audit/scoring/binary_gates.rs` — FIPS binary gate model
- `src/audit/scoring/cnsa2_strict.rs` — CNSA2 strict model
- `src/audit/hndl.rs` — HNDL model, HndlRating enum, HndlConfig

- [ ] **Step 2: Write `wiki/Scoring-System.md`**

The page must document:

**Overview section:** The score is 0–100, computed from 5 weighted categories. Total is capped at 100.

**Key Exchange (max 50 points)** — values from `weighted.rs::key_exchange_points()`:

| Code point | Group | Points |
|------------|-------|--------|
| 0x11EC (no HRR) | X25519MLKEM768 | 50 |
| 0x11EC (with HRR) | X25519MLKEM768 | 40 |
| 0x11EB | SecP256r1MLKEM768 | 45 |
| 0x11ED | SecP384r1MLKEM1024 | 50 |
| 0x0202 | Pure ML-KEM-1024 | 50 |
| 0x0201 (pre-2033) | Pure ML-KEM-768 | 48 |
| 0x0201 (2033+) | Pure ML-KEM-768 | 50 |
| 0x6399 | Kyber Draft (deprecated) | 20 |
| any other | Classical only | 0 |

**TLS Version (max 15 points)** — values from `tls_version_points()`:
- TLS 1.3 → 15
- TLS 1.2 → 5
- Other → 0

**Cipher Suite (max 15 points)** — values from `cipher_suite_points()`:
- AES-256-GCM (0x1302, 0xC02C, 0xC030) or ChaCha20-Poly1305 (0x1303, 0xCCA8, 0xCCA9) → 15
- AES-128-GCM (0x1301, 0xC02B, 0xC02F) → 8
- Other → 0

**Certificate Chain (max 15 points):**
This category is planned but not yet active in this release — currently scores 0 for all endpoints. Full cert chain scoring is planned for a future release.

**Downgrade Posture (max 5 points)** — values from `downgrade_points()`:
- Downgrade rejected → 5
- Downgrade accepted → 0

**Timeline Multiplier section** — from `timeline_multiplier()`:

| Years until disallowance | Multiplier |
|--------------------------|-----------|
| ≥ 9 | 1.00 |
| ≥ 5 | 0.75 |
| ≥ 2 | 0.40 |
| ≥ 1 | 0.10 |
| ≤ 0 (deadline passed) | 0.00 |

Explain when this multiplier is applied (long-lived assets, cert expiry relative to algorithm deadline).

**Grade Boundaries section:**

| Score | Grade | Terminal color |
|-------|-------|---------------|
| 90–100 | A | Green |
| 80–89 | B | Green |
| 60–79 | C | Yellow |
| 40–59 | D | Red |
| 0–39 | F | Red |

Note: color thresholds (≥80=green, ≥60=yellow, <60=red) come from `src/output/human.rs`. The A/B/C/D/F grade labels are a documentation convention.

**CNSA2 and FIPS differences section:** Read `cnsa2_strict.rs` and `binary_gates.rs` and document how scoring differs under those modes (e.g., binary pass/fail vs. weighted, ML-KEM-1024 requirement).

**HNDL Model section** — from `src/audit/hndl.rs`:
- What HNDL means (harvest-now-decrypt-later)
- HndlRating enum values: None, Low, Medium, High, Critical
- How the exposure window is calculated (years until Q-day, algorithm longevity)
- How `--q-day` (default 2030) configures the Q-day year
- What `cert_expires_before_q_day` means in context

- [ ] **Step 3: Commit**

```sh
git add Scoring-System.md
git commit -m "wiki: add Scoring System page"
```

---

## Task 5: Wiki — Finding Codes

**Files:**
- Create: `wiki/Finding-Codes.md`

- [ ] **Step 1: Read source files**

Read these files in full:
- `src/output/sarif.rs` — `rule_definitions()` function for all 9 codes, names, descriptions
- `src/audit/findings.rs` — `FindingKind` enum, what triggers each variant
- `src/audit/remediation.rs` — `remediation_for()` function and all config snippets
- `src/audit/scoring/weighted.rs` — `severity()` method for NIST severities

- [ ] **Step 2: Write `wiki/Finding-Codes.md`**

Intro: pqaudit reports findings using codes PQA001–PQA009. Each finding has a severity (Error/Warning/Note), a human-readable message, and where available, remediation config snippets.

Write one section per code using this structure:

```
## PQA001 — ClassicalKeyExchangeOnly

**Severity (NIST):** Error
**Trigger:** Server negotiated a classical (non-PQC) key exchange group (e.g., x25519, P-256).
**Description:** The server did not negotiate a hybrid post-quantum key exchange. All current
data transmitted over this connection is vulnerable to harvest-now-decrypt-later attacks.

### Remediation
[include the config snippets from `remediation_for(FindingKind::ClassicalKeyExchangeOnly{..})` verbatim]
```

Repeat for all 9 codes: PQA001–PQA009. All code names, descriptions, and trigger conditions must be taken verbatim from the source files listed above — do not invent or paraphrase.

For severity: read the `severity()` method in `weighted.rs` (NIST model), and the corresponding method in `cnsa2_strict.rs` and `binary_gates.rs` for CNSA2 and FIPS severities.

- [ ] **Step 3: Commit**

```sh
git add Finding-Codes.md
git commit -m "wiki: add Finding Codes reference page"
```

---

## Task 6: Wiki — Compliance Modes

**Files:**
- Create: `wiki/Compliance-Modes.md`

- [ ] **Step 1: Read source files**

Read these files in full:
- `src/audit/tables/nist_ir8547.rs` — NIST deadline table constants
- `src/audit/tables/cnsa2.rs` — CNSA2 table constants
- `src/audit/tables/fips.rs` — FIPS approved algorithm list
- `src/audit/compliance.rs` — `compliance_pair()` function showing which model+table each mode uses

- [ ] **Step 2: Write `wiki/Compliance-Modes.md`**

The page must cover:

**How `--compliance` works:** It selects a scoring model and a deadline table. The model determines point values and severity assignments; the table determines which algorithms are deprecated and by when.

**NIST IR 8547 (`--compliance nist`, default):**
- Source: NIST IR 8547 (Initial Public Draft)
- Derive the deprecation timeline from `nist_ir8547.rs` constants — document which algorithms are deprecated and in which year
- Key exchange requirement: hybrid PQC (MLKEM + classical)
- Certificate signature: classical certs (RSA, ECDSA) must migrate by 2030 (P-256/P-384) or 2035 (RSA)

**CNSA 2.0 (`--compliance cnsa2`):**
- Source: NSA CNSA 2.0 guidance
- Derive requirements from `cnsa2.rs` — document algorithm requirements and 2033 exclusive-PQC deadline
- ML-KEM-1024 is mandatory (not ML-KEM-768)
- More stringent than NIST; some findings that are Warnings under NIST become Errors under CNSA2

**FIPS 140-3 (`--compliance fips`):**
- Source: FIPS 140-3
- Derive approved algorithm list from `fips.rs`
- Uses binary gate scoring (pass/fail per category) rather than weighted rubric — derive from `binary_gates.rs`
- Focus on FIPS-approved algorithm compliance, not PQC migration timeline

**Side-by-side comparison table:** algorithm × mode showing allowed/deprecated/required.

**When to choose each mode:** brief guidance (NIST for general use, CNSA2 for NSS/DoD contexts, FIPS for environments requiring FIPS 140-3 validation).

- [ ] **Step 3: Commit**

```sh
git add Compliance-Modes.md
git commit -m "wiki: add Compliance Modes page"
```

---

## Task 7: Wiki — Output Formats

**Files:**
- Create: `wiki/Output-Formats.md`

- [ ] **Step 1: Read source files**

Read these files in full:
- `src/lib.rs` — all public types: `ScanReport`, `TargetReport`, `ScoringResult`, `CategoryScore`, `HndlAssessment`, `Finding`, `CertChainReport`, `CipherInventory`, `DowngradeResult`, `ComparisonReport`
- `src/output/json.rs` — `render_json()` to understand what the JSON output looks like
- `src/output/sarif.rs` — `render_sarif()`, `rule_definitions()`, SARIF structure
- `src/output/cbom.rs` — `render_cbom()`, CBOM structure
- `src/output/human.rs` — `render_human()`, output anatomy
- `src/output/compare.rs` — `build_comparison()`, comparison report structure

- [ ] **Step 2: Write `wiki/Output-Formats.md`**

**JSON (default, `-o json`):**
Run `./target/release/pqaudit -o json example.com:443 | jq .` to get an example, then annotate it. Document every field in `ScanReport` and `TargetReport` derived from the type definitions in `src/lib.rs`. Include the `comparison` field structure (present when `--compare` is passed).

Example structure to document:
```json
{
  "schema_version": "1.0",
  "scanned_at": "<RFC 3339 timestamp>",
  "compliance_mode": "Nist",
  "targets": [
    {
      "target": "<original target string>",
      "port": 443,
      "score": {
        "total": 70,
        "key_exchange": { "name": "key_exchange", "points": 40, "max_points": 50, "notes": [] },
        "tls_version": { ... },
        "cipher_suite": { ... },
        "cert_chain": { ... },
        "downgrade_posture": { ... }
      },
      "hndl": {
        "rating": "Medium",
        "exposure_window_years": <float>,
        "cert_expires_before_q_day": <bool>,
        "notes": [...]
      },
      "findings": [
        { "severity": "Warning", "kind": { ... } }
      ],
      "cert_chain": { "entries": [...], "findings": [...] },
      "cipher_inventory": null,
      "downgrade": "Rejected",
      "error": null
    }
  ],
  "comparison": null
}
```
Derive exact field names and types from `src/lib.rs` — do not guess.

**SARIF 2.1.0 (`-o sarif`):**
- Version string: `"2.1.0"` (from `SARIF_VERSION` const)
- Schema URL: `"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"` (from `SARIF_SCHEMA` const)
- Structure: `version`, `$schema`, `runs[0].tool.driver` (name, version, informationUri, rules), `runs[0].results`
- Location URI format: `tls://host:port`
- Severity mapping: Error→`"error"`, Warning→`"warning"`, Note→`"note"`
- All 9 rule definitions are always present regardless of active findings
- GitHub Code Scanning upload: include a workflow step using `github/codeql-action/upload-sarif@v3`

**CycloneDX 1.5 CBOM (`-o cbom`):**
- `bomFormat`: `"CycloneDX"`, `specVersion`: `"1.5"` (both from source constants)
- `serialNumber`: `urn:pqaudit:<scanned_at with colons/dots replaced>`
- `components`: each cipher suite and certificate algorithm becomes one `cryptographic-asset` component
- `cryptoProperties.assetType`: always `"algorithm"`
- `evidence.occurrences`: list of `{ "location": "host:port (cipher suite/cert position)" }`
- Note: cipher inventory only appears if `--full-scan` was used; cert algorithms always appear

**Human terminal (`-o human`):**
Document the output anatomy from `src/output/human.rs`:
- Header line: `pqaudit VERSION — TIMESTAMP`
- Compliance mode line: `Compliance mode: <mode name>`
- Per-target block:
  - `  ● TARGET:PORT  score: N/100` (color: green ≥80, yellow ≥60, red <60)
  - `    HNDL: <rating>` (green for None/Low, yellow for Medium, red for High/Critical)
  - One line per finding: `    <icon> [PQAXXX] <message>` (✗=Error, !=Warning, ·=Note)
  - `    ✓ No findings` if no findings
  - `    ERROR <message>` if probe failed
- Comparison table (when `--compare` is used): category × target matrix with winner highlighted

- [ ] **Step 3: Commit**

```sh
git add Output-Formats.md
git commit -m "wiki: add Output Formats page"
```

---

## Task 8: Wiki — CI/CD Integration

**Files:**
- Create: `wiki/CI-CD-Integration.md`

- [ ] **Step 1: Read source files**

Read:
- `src/main.rs` — `determine_exit_code()` function (the complete exit code logic)
- `src/cli/mod.rs` — all flags and defaults

- [ ] **Step 2: Write `wiki/CI-CD-Integration.md`**

**Exit Codes section** (derive from `determine_exit_code()` in `src/main.rs`):

| Code | Condition | Notes |
|------|-----------|-------|
| 0 | All targets probed; score at or above `--fail-below` (or no threshold set) | |
| 1 | At least one target's score < `--fail-below` threshold | Only checked if not all targets errored |
| 2 | All targets failed to connect or probe (`error` field set on all) | Checked before exit 1 |
| 3 | Invalid arguments | Handled before scanning starts |

Important: exit 2 takes priority over exit 1. If all targets error and scores would be below threshold, exit 2 is returned.

**GitHub Actions example:**

```yaml
name: PQC Audit

on:
  push:
    branches: [main]
  pull_request:

jobs:
  pqc-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Download pqaudit
        run: |
          curl -Lo pqaudit https://github.com/YasogaN/pqaudit/releases/latest/download/pqaudit-x86_64-unknown-linux-musl
          chmod +x pqaudit

      - name: Audit TLS PQC readiness
        run: ./pqaudit --fail-below 80 -o sarif example.com:443 > results.sarif

      - name: Upload SARIF to Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

Note: this invokes the binary directly — there is no published pqaudit GitHub Actions marketplace action.

**GitLab CI example:**

```yaml
pqc-audit:
  stage: test
  image: ubuntu:latest
  script:
    - curl -Lo pqaudit https://github.com/YasogaN/pqaudit/releases/latest/download/pqaudit-x86_64-unknown-linux-musl
    - chmod +x pqaudit
    - ./pqaudit --fail-below 80 example.com:443
  allow_failure: false
```

**`--fail-below` strategy:** Recommend 80 for general NIST compliance, 90 for CNSA2 mode.

**Batch scan pattern:** For large inventories, use `--targets-file targets.txt` (one host per line, blank lines ignored) with `--concurrency` (default 10) to control parallelism.

- [ ] **Step 3: Commit**

```sh
git add CI-CD-Integration.md
git commit -m "wiki: add CI/CD Integration page"
```

---

## Task 9: Wiki — MCP Integration

**Files:**
- Create: `wiki/MCP-Integration.md`

- [ ] **Step 1: Read source files**

Read `src/mcp/mod.rs` in full — all parameter structs, tool implementations, and `run_mcp_server()`.

- [ ] **Step 2: Write `wiki/MCP-Integration.md`**

**Overview:** `pqaudit --mcp` starts a Model Context Protocol server over stdio. It exposes three tools that let AI agents scan endpoints, compare them, and retrieve CBOM data — without needing to spawn subprocesses or parse CLI output.

**Starting the server:**
```sh
pqaudit --mcp
```
The process reads JSON-RPC from stdin and writes responses to stdout. It exits when stdin closes. Requires the `mcp` feature (enabled by default).

**Tool: `scan_endpoint`**

Parameters (from `ScanEndpointParams` struct):
```json
{
  "target": "example.com:443",
  "timeout_ms": 5000,
  "full_scan": false
}
```
- `target` (string, required): host to scan; accepts `host`, `host:port`, `smtp://host`, etc.
- `timeout_ms` (number, optional, default 5000): probe timeout in milliseconds
- `full_scan` (boolean, optional, default false): enumerate all cipher suites

Returns: `{ "content": "<JSON ScanReport>" }` — the content field is a JSON string of the full `ScanReport`.

**Tool: `compare_endpoints`**

Parameters (from `CompareEndpointsParams` struct):
```json
{
  "targets": ["example.com:443", "api.example.com:443"],
  "timeout_ms": 5000
}
```
- `targets` (array of strings, required): list of hosts to scan and compare
- `timeout_ms` (number, optional, default 5000)

Returns: `{ "content": "<JSON ScanReport with comparison object>" }` — includes a `comparison` field with a side-by-side category breakdown.

**Tool: `get_cbom`**

Parameters (from `GetCbomParams` struct):
```json
{
  "target": "example.com:443",
  "timeout_ms": 5000
}
```
- `target` (string, required)
- `timeout_ms` (number, optional, default 5000)

Always runs with `full_scan: true` (cipher inventory required for CBOM). Returns: `{ "content": "<CycloneDX 1.5 CBOM JSON>" }`.

**Claude Desktop configuration:**

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "pqaudit": {
      "command": "pqaudit",
      "args": ["--mcp"]
    }
  }
}
```

If `pqaudit` is not in PATH, use the absolute path to the binary.

**Example agent session:**

Show a realistic JSON-RPC exchange for `scan_endpoint` — request with `target: "example.com:443"` and the response with the full JSON ScanReport content. Derive the exact response structure from `src/output/json.rs` and `src/lib.rs` types.

- [ ] **Step 3: Commit**

```sh
git add MCP-Integration.md
git commit -m "wiki: add MCP Integration page"
```

---

## Task 10: Wiki — Baseline Tracking

**Files:**
- Create: `wiki/Baseline-Tracking.md`

- [ ] **Step 1: Read source files**

Read:
- `src/baseline/mod.rs` — `TargetDiff` struct, `diff_reports()`, `load_baseline()`
- `src/main.rs` — the baseline loading and diff printing block (around lines 57-88, re-verify)

- [ ] **Step 2: Write `wiki/Baseline-Tracking.md`**

**What baselines are:** A baseline is a JSON `ScanReport` file produced by `pqaudit -o json`. It records scores and findings for a set of targets at a point in time.

**Saving a baseline:**
```sh
pqaudit -o json example.com:443 > baseline.json
```

**Comparing against a baseline:**
```sh
pqaudit --baseline baseline.json example.com:443
```
The diff is printed to **stderr**, one line per target that appears in both the baseline and the current scan.

**Diff output format** (from `main.rs` diff printing logic):
```
↑ example.com score: +15 (resolved: 2, new: 0)
↓ api.example.com score: -10 (resolved: 0, new: 1)
```
- `↑` = score improved, `↓` = score decreased
- `score: +N` = `score_delta` (current total − baseline total)
- `resolved: N` = finding SARIF rule IDs present in baseline but gone in current
- `new: N` = finding SARIF rule IDs in current but absent from baseline

**`TargetDiff` struct fields** (from `src/baseline/mod.rs`):
- `target`: target string
- `score_delta`: i16, positive = improvement
- `score_improved`: bool
- `resolved_findings`: Vec<String> of SARIF rule IDs (e.g., `"PQA001"`)
- `new_findings`: Vec<String> of SARIF rule IDs

**Schema version mismatch:** If the baseline `schema_version` differs from the current report's, the diff is skipped with an error on stderr. Always use baselines generated by the same version of pqaudit.

**`--compare` vs `--baseline`:**
- `--baseline FILE`: diffs the current scan against a *prior* scan saved in FILE
- `--compare`: builds a side-by-side comparison table across all targets in the *current* scan only (no prior state needed); output appears in the JSON `comparison` field and in human output

**Recommended CI pattern:**
```yaml
# On merge to main: save new baseline
- run: ./pqaudit -o json example.com:443 > baseline.json
- uses: actions/upload-artifact@v4
  with:
    name: pqaudit-baseline
    path: baseline.json

# On pull request: download baseline and diff
- uses: actions/download-artifact@v4
  with:
    name: pqaudit-baseline
- run: ./pqaudit --baseline baseline.json --fail-below 80 example.com:443
```

- [ ] **Step 3: Commit**

```sh
git add Baseline-Tracking.md
git commit -m "wiki: add Baseline Tracking page"
```

---

## Task 11: Wiki — STARTTLS

**Files:**
- Create: `wiki/STARTTLS.md`

- [ ] **Step 1: Read source files**

Read `src/probe/starttls.rs` in full — `parse_scheme()`, `SCHEMES` const, `smtp_upgrade()`, `imap_upgrade()`, `pop3_upgrade()`, `ldap_upgrade()`, `upgrade_to_tls()`.

- [ ] **Step 2: Write `wiki/STARTTLS.md`**

**How it works:** Pass a URL scheme as the target argument. pqaudit parses the scheme, opens a plain TCP connection, performs the protocol-specific STARTTLS upgrade, and then proceeds with the TLS probe. No separate flag is needed.

**URL Scheme Reference** — all entries from the `SCHEMES` const in `parse_scheme()`:

| Scheme | Default Port | Mode |
|--------|-------------|------|
| `smtp://` | 25 | STARTTLS upgrade |
| `smtps://` | 465 | Direct TLS (no upgrade) |
| `imap://` | 143 | STARTTLS upgrade |
| `imaps://` | 993 | Direct TLS (no upgrade) |
| `pop3://` | 110 | STARTTLS upgrade |
| `pop3s://` | 995 | Direct TLS (no upgrade) |
| `ldap://` | 389 | **Not implemented** — returns error; use `ldaps://` |
| `ldaps://` | 636 | Direct TLS (no upgrade) |
| `https://` | 443 | Direct TLS (no upgrade) |
| `http://` | 80 | Bare TCP — tool issues TLS ClientHello directly (no app-layer upgrade) |
| (no scheme) | 443 | Direct TLS (no upgrade) |

**Port override:** Append `:PORT` to override the default:
```sh
pqaudit smtp://mail.example.com:587
pqaudit imap://mail.example.com:993
```

**Per-protocol handshake details** — derive all sequences from the source `*_upgrade()` functions:

SMTP (`smtp_upgrade()`):
1. Read `220` banner from server
2. Send `EHLO pqaudit\r\n`
3. Read multi-line EHLO response (lines until one not starting with `250-`)
4. Send `STARTTLS\r\n`
5. Read `220` response confirming TLS negotiation can begin

IMAP (`imap_upgrade()`):
1. Read `* OK` greeting from server
2. Send `A001 STARTTLS\r\n` (no CAPABILITY step)
3. Read `A001 OK` response

POP3 (`pop3_upgrade()`):
1. Read `+OK` banner from server
2. Send `STLS\r\n` (no CAPA step)
3. Read `+OK` response

LDAP (`ldap_upgrade()`): Not implemented. Returns `StarttlsUpgradeFailed` with message "LDAP STARTTLS not yet implemented; use ldaps:// for implicit TLS". Use `ldaps://` on port 636 for LDAP servers.

**IPv6 addresses:** Use bracket notation:
```sh
pqaudit smtp://[::1]:587
pqaudit [::1]:443
```

**Direct TLS vs STARTTLS:** The `s`-suffixed schemes (`smtps://`, `imaps://`, `pop3s://`, `ldaps://`) connect directly with TLS on the wire — no plaintext upgrade. Use these for ports that speak TLS from the first byte (465, 993, 995, 636).

- [ ] **Step 3: Commit**

```sh
git add STARTTLS.md
git commit -m "wiki: add STARTTLS page"
```

---

## Task 12: Push wiki and main repo

- [ ] **Step 1: Push the wiki**

```sh
cd wiki
git push origin master
```

Verify the pages appear at `https://github.com/YasogaN/pqaudit/wiki`.

- [ ] **Step 2: Push the main repo**

```sh
cd ..
git push origin main
```

- [ ] **Step 3: Verify CI passes**

```sh
gh run watch
```

Wait for the CI run triggered by the README push. Confirm lint and tests pass.

- [ ] **Step 4: Spot-check the rendered README on GitHub**

Open `https://github.com/YasogaN/pqaudit` in a browser. Verify:
- Badges render correctly
- Demo code block displays cleanly (no garbled ANSI)
- All links to wiki pages resolve

- [ ] **Step 5: Spot-check the wiki**

Open `https://github.com/YasogaN/pqaudit/wiki`. Verify all 9 pages appear in the sidebar and the Home page navigation table links work.
