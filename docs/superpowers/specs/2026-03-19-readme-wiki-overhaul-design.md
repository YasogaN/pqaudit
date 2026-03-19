# README & Wiki Overhaul — Design Spec

**Date:** 2026-03-19
**Status:** Approved

---

## Goal

Overhaul the pqaudit README to a polished, accurate, B/C-style document that serves security engineers, DevOps/platform engineers, and developers equally. Create a companion set of extremely detailed GitHub wiki pages covering everything too deep for the README.

---

## Source-Verified Facts

All claims below are verified against source before the spec was written. Implementers must re-verify against the same sources before writing documentation.

| Fact | Value | Source |
|------|-------|--------|
| Default output format | `json` | `src/cli/mod.rs:43` `default_value = "json"` |
| SARIF version | `2.1.0` | `src/output/sarif.rs:5` `const SARIF_VERSION` |
| CycloneDX spec version | `1.5` | `src/output/cbom.rs:6` `const CBOM_SPEC_VERSION` |
| CycloneDX bomFormat | `"CycloneDX"` | `src/output/cbom.rs:5` `const CBOM_FORMAT` |
| Exit code 3 | invalid args | `src/main.rs:15-17` `std::process::exit(3)` |
| Exit code 2 | all targets errored | `src/main.rs:126-128` |
| Exit code 1 | any target below `--fail-below` | `src/main.rs:131-137` |
| Exit codes 1 and 2 | mutually exclusive: 2 checked first | `src/main.rs:124-141` |
| `--targets-file` format | one host per line; blank lines ignored | `src/main.rs:36-39` |
| MCP transport | stdio | `src/mcp/mod.rs:155` `rmcp::transport::stdio()` |
| MCP tools | `scan_endpoint`, `compare_endpoints`, `get_cbom` | `src/mcp/mod.rs:79,99,118` |
| Finding codes | PQA001–PQA009 (9 total) | `src/output/sarif.rs:9-65` |
| Score coloring thresholds | green ≥80, yellow ≥60, red <60 | `src/output/human.rs:117-125` |
| Grade table (A/B/C/D/F) | README-only convention; not in source | n/a — keep existing values |
| Scoring categories | key_exchange (50), tls_version (15), cipher_suite (15), cert_chain (15), downgrade_posture (5) | `src/audit/scoring/weighted.rs` and `model.rs` |
| GitHub Action | No published marketplace action; CI docs show a workflow YAML example | n/a |
| Rust minimum version | 1.85 | `Cargo.toml:rust-version` |

---

## README Design

### Tone & Style
Professional but approachable (ripgrep/bat style) with some developer-marketing flair. Badges, real terminal demo, grouped features. All flag names and behaviours match `src/cli/mod.rs` exactly.

### Structure: Hook → Quick Start → Features → Reference

**1. Badge header**
- CI status badge (`YasogaN/pqaudit`)
- License: Apache-2.0
- Latest Release

**2. Title + 2-sentence hook**
What it is and why it matters today (HNDL threat, 2035 deadline).

**3. Real terminal demo block**
Static block captured from `./target/release/pqaudit -o human cloudflare.com:443` with ANSI escape codes stripped. Uses `-o human` explicitly (default is `json`).

**4. Features — 4 grouped categories**
- **Probing** — PQC handshake (X25519MLKEM768/MLKEM1024), cipher suite enumeration (`--full-scan`), downgrade detection, HelloRetryRequest detection, STARTTLS (smtp/imap/pop3 URL schemes; ldap STARTTLS not yet implemented)
- **Scoring & Risk** — 0-100 weighted rubric, HNDL exposure rating (NONE/LOW/MEDIUM/HIGH/CRITICAL), three compliance modes
- **Output** — human terminal, JSON, SARIF 2.1.0, CycloneDX 1.5 CBOM, baseline diff
- **Integration** — CI/CD exit codes, GitHub Actions workflow, MCP stdio server

**5. Installation**
- Pre-built binary: `curl` one-liner for Linux x86_64, replace `YOUR_ORG` with `YasogaN`
- From source: `cargo install` + clone/build; requires Rust 1.85+

**6. Quick Start — one example per scenario**
Each example is a minimal working command with a one-line explanation:

| Scenario | Key flags |
|----------|-----------|
| Basic scan (JSON output) | `pqaudit example.com:443` |
| Human-readable output | `pqaudit -o human example.com:443` |
| Compliance mode | `--compliance cnsa2` |
| CI gate | `--fail-below 80` + exit code note |
| Output formats | `-o human`, `-o json`, `-o sarif`, `-o cbom`, `--output-file` |
| Full cipher enumeration | `--full-scan` |
| Batch scan | `--targets-file targets.txt --concurrency 10` (one host per line) |
| Baseline save & compare | `--baseline baseline.json` |
| STARTTLS | `smtp://mail.example.com:587`, `imap://`, `pop3://` (note: `ldap://` STARTTLS not implemented; use `ldaps://`) |
| SNI override | `--sni api.example.com 203.0.113.5:443` |
| Custom timeout | `--timeout 10000` (milliseconds, default 5000) |
| MCP server | `pqaudit --mcp` — brief description + link to wiki |

**7. Reference tables**
- Score grade table (A–F, ranges, meaning) — keep existing values; note link to Scoring-System wiki
- Exit codes table (0/1/2/3) — fix `--fail-under` → `--fail-below`; note 1 and 2 are mutually exclusive (2 checked first)
- Compliance modes table (nist/cnsa2/fips) — note link to Compliance-Modes wiki

**8. Unchanged sections**
AI Disclosure, Contributing, Code of Conduct, License.

### Fix List for README
- Exit codes table: `--fail-under` → `--fail-below`
- Replace all `YOUR_ORG` with `YasogaN`
- Remove stale `--mode` / `--format` / `--fail-under` / `--targets` / `--starttls` references if any remain

---

## Wiki Design

**Push method:** Clone `https://github.com/YasogaN/pqaudit.wiki.git` using existing git credentials (manual push, not CI). Each wiki page = one `.md` file named with hyphens matching the page title.

### Page: Home
**Content:**
- One-paragraph project summary
- Key use cases: security audits, CI/CD gating, agent/MCP workflows
- Full navigation index linking all 8 other wiki pages with one-line descriptions
- Quick links: Installation, CI/CD Integration, MCP Integration

---

### Page: Scoring-System
**Verify against:** `src/audit/scoring/weighted.rs`, `src/audit/scoring/model.rs`, `src/audit/scoring/binary_gates.rs`, `src/audit/scoring/cnsa2_strict.rs`, `src/audit/hndl.rs`

**Content:**
- Overview: 0-100 weighted rubric across 5 categories
- Category table with max points and what earns/loses points:
  - Key Exchange (max 50): X25519MLKEM768 no-HRR=50, with HRR=40; SecP256r1MLKEM768=45; SecP384r1MLKEM1024=50; pure ML-KEM-1024=50; pure ML-KEM-768=48 (50 after 2033); Kyber Draft (0x6399)=20; classical=0
  - TLS Version (max 15): TLS 1.3=15, TLS 1.2=5, other=0
  - Cipher Suite (max 15): AES-256-GCM or ChaCha20-Poly1305=15; AES-128-GCM=8; other=0
  - Certificate Chain (max 15): currently 0 (not yet fully implemented — note this)
  - Downgrade Posture (max 5): rejected=5, accepted=0
- Timeline multiplier table: years-until-disallowance → multiplier (≥9=1.00, ≥5=0.75, ≥2=0.40, ≥1=0.10, ≤0=0.00)
- Grade boundaries (README convention, not in source): A=90-100, B=80-89, C=60-79, D=40-59, F=0-39
- Score color thresholds from human output: green ≥80, yellow ≥60, red <60
- CNSA2 strict mode differences: read `src/audit/scoring/cnsa2_strict.rs` and `binary_gates.rs` before writing this section
- HNDL model (from `src/audit/hndl.rs`): exposure window calculation, rating thresholds (NONE/LOW/MEDIUM/HIGH/CRITICAL), how `--q-day` sets the Q-day year, what `cert_expires_before_q_day` means

---

### Page: Finding-Codes
**Verify against:** `src/output/sarif.rs` (rule definitions), `src/audit/findings.rs`, `src/audit/remediation.rs`, `src/audit/scoring/weighted.rs` (severity assignments)

**Content:**
One section per finding code using consistent structure: Code, Name, Description, Trigger condition, Severity (NIST/CNSA2/FIPS), Remediation snippets.

All 9 codes from `rule_definitions()` in `src/output/sarif.rs`:

| Code | Name | Short description |
|------|------|-------------------|
| PQA001 | ClassicalKeyExchangeOnly | Server uses classical key exchange only |
| PQA002 | HybridKeyExchangeHrrRequired | Hybrid PQC requires HelloRetryRequest |
| PQA003 | DeprecatedPqcDraftCodepoint | Deprecated pre-standard PQC code point (0x6399) |
| PQA004 | WeakSymmetricCipher | Weak or deprecated symmetric cipher |
| PQA005 | ClassicalCertificateDeadlineSoon | Classical cert, deadline by 2030 |
| PQA006 | ClassicalCertificateDeadlineLater | Classical cert, later deadline |
| PQA007 | DowngradeAccepted | Server accepts TLS downgrade below 1.3 |
| PQA008 | TlsVersionInsufficient | Server max TLS version below 1.3 |
| PQA009 | CertExpiresAfterDeadline | Cert expiry past algorithm disallowance deadline |

Read `src/audit/remediation.rs` for all config snippets (nginx, Caddy, OpenSSL, Go, Java) — reproduce them verbatim.

---

### Page: Compliance-Modes
**Verify against:** `src/audit/tables/nist_ir8547.rs`, `src/audit/tables/cnsa2.rs`, `src/audit/tables/fips.rs`, `src/audit/compliance.rs`

**Content:**
- What `--compliance` controls: which scoring model and deadline table are applied
- NIST IR 8547 (`--compliance nist`): deprecation timeline, affected algorithms, key exchange requirements — read the table constants from source
- CNSA 2.0 (`--compliance cnsa2`): ML-KEM-1024 requirement, 2033 exclusive-PQC deadline, what differs from NIST mode
- FIPS 140-3 (`--compliance fips`): approved algorithm set as encoded in source; binary-gate scoring model
- Side-by-side comparison table: algorithm × mode (allowed / deprecated / required)
- Guidance: when to choose each mode

---

### Page: Output-Formats
**Verify against:** `src/output/json.rs`, `src/output/sarif.rs`, `src/output/cbom.rs`, `src/output/human.rs`, `src/lib.rs` (type definitions)

**Content:**
- **JSON** (default): full annotated schema derived from `ScanReport` and `TargetReport` type definitions; realistic example output; all fields explained including `comparison` field when `--compare` is used
- **SARIF 2.1.0**: structure walkthrough (version field, `$schema`, runs, tool/driver, rules array, results array, locations); how findings map to results; `tls://host:port` URI format; how to upload to GitHub Code Scanning (workflow step)
- **CycloneDX 1.5 CBOM**: `bomFormat`, `specVersion`, `serialNumber`, `metadata`, `components`; how cipher inventory and cert chain map to `cryptographic-asset` components; `cryptoProperties.algorithmProperties` structure
- **Human**: header line (`pqaudit VERSION — TIMESTAMP`), compliance mode line, per-target block (● host:port score, HNDL rating, findings with icons ✓/!/✗, ERROR for failed probes); comparison table when `--compare` used

---

### Page: CI-CD-Integration
**Verify against:** `src/main.rs` (exit code logic at lines 124-141), `src/cli/mod.rs` (flag defaults)

**Content:**
- Exit code reference (verified from source, 2 checked before 1):
  - 0: success (all targets probed; score at or above threshold if set)
  - 1: at least one target below `--fail-below` threshold (and not all errored)
  - 2: all targets failed to connect or probe
  - 3: invalid arguments (handled before scan starts)
- GitHub Actions: full workflow YAML — install binary from release, run scan, capture exit code, upload SARIF to Code Scanning. This is a workflow YAML example invoking the binary directly, NOT a marketplace action.
- GitLab CI: equivalent `.gitlab-ci.yml`
- `--fail-below` strategy: recommended values per compliance posture (e.g. 80 for NIST, 90 for CNSA2)
- Batch scan for large inventories: `--targets-file` with one host per line (blank lines ignored), `--concurrency` default 10

---

### Page: MCP-Integration
**Verify against:** `src/mcp/mod.rs`

**Content:**
- What the MCP server does: exposes pqaudit over the Model Context Protocol via stdio transport; returns JSON ScanReport or CBOM from the three registered tools
- How to start: `pqaudit --mcp` (requires `mcp` feature, on by default); process stays alive until stdin closes
- Three tools (all verified from source):
  - `scan_endpoint`: params `target` (string), `timeout_ms` (u64, default 5000), `full_scan` (bool, default false); returns JSON ScanReport
  - `compare_endpoints`: params `targets` (Vec<string>), `timeout_ms` (u64, default 5000); returns JSON ScanReport with comparison object
  - `get_cbom`: params `target` (string), `timeout_ms` (u64, default 5000); always runs with `full_scan=true`; returns CycloneDX 1.5 CBOM JSON
- Claude Desktop `claude_desktop_config.json` example: `{"mcpServers": {"pqaudit": {"command": "pqaudit", "args": ["--mcp"]}}}`
- Example agent sessions: realistic JSON request/response pairs for each tool showing a real scan result

---

### Page: Baseline-Tracking
**Verify against:** `src/baseline/mod.rs`, `src/main.rs` (baseline diff output at lines 57-88)

**Content:**
- Baseline file format: a JSON `ScanReport` produced by `pqaudit -o json` (schema_version must match)
- Saving a baseline: `pqaudit -o json example.com:443 > baseline.json`
- Comparing against baseline: `pqaudit --baseline baseline.json example.com:443`
- Diff output (printed to stderr, one line per target): `↑/↓ TARGET score: DELTA (resolved: N, new: N)`
- What the diff contains (from `TargetDiff` struct): `score_delta` (i16, current − baseline), `score_improved` (bool), `resolved_findings` (SARIF rule IDs gone), `new_findings` (SARIF rule IDs added)
- Schema version mismatch: if `schema_version` differs, diff is skipped with an error
- `--compare` flag: builds a side-by-side comparison table across all targets in the same scan (different from `--baseline`, which diffs against a prior scan)
- Recommended CI pattern: save baseline on main-branch merge, diff on pull requests, fail on score regression

---

### Page: STARTTLS
**Verify against:** `src/probe/starttls.rs` (`parse_scheme` function and `SCHEMES` constant)

**Content:**
- How STARTTLS is triggered: pass a URL scheme as part of the target argument (no separate flag)
- URL scheme reference table (all entries from `SCHEMES` const in source):

| Scheme | Default Port | Protocol | Upgrade Command |
|--------|-------------|----------|-----------------|
| `smtp://` | 25 | STARTTLS | EHLO → STARTTLS |
| `smtps://` | 465 | Direct TLS | n/a |
| `imap://` | 143 | STARTTLS | CAPABILITY → STARTTLS |
| `imaps://` | 993 | Direct TLS | n/a |
| `pop3://` | 110 | STARTTLS | CAPA → STLS |
| `pop3s://` | 995 | Direct TLS | n/a |
| `ldap://` | 389 | **Not implemented** — returns error; use `ldaps://` | n/a |
| `ldaps://` | 636 | Direct TLS | n/a |
| `https://` | 443 | Direct TLS | n/a |
| `http://` | 80 | Direct TLS | n/a |

- Per-protocol handshake walk-through: SMTP (EHLO exchange, STARTTLS command, 220 response), IMAP (CAPABILITY response, STARTTLS, OK), POP3 (CAPA, STLS, +OK)
- **`ldap://` STARTTLS is not implemented** (`src/probe/starttls.rs` returns `StarttlsUpgradeFailed`): document as a known limitation; direct users to use `ldaps://` on port 636 instead
- Port override: append `:PORT` to override the default, e.g. `smtp://mail.example.com:587`
- `smtp://` vs `smtps://`: STARTTLS upgrade on a plain-text connection vs. direct TLS — use `smtp://` for port 25/587, `smtps://` for port 465
- IPv6: `[::1]:port` syntax is supported

---

## Implementation Order

> **Note on line numbers:** Line-number citations in this spec are approximate and may drift as code changes. Treat them as navigation hints, not anchors — re-verify the relevant logic in the named file before writing any documentation.

1. Read all listed source files for each section before drafting any content
2. SARIF version (2.1.0) and CycloneDX version (1.5) confirmed in source — verify again before writing Output-Formats sections
3. Write README: fix `--fail-under` → `--fail-below`, replace `YOUR_ORG` → `YasogaN`, write new content; commit to main branch
4. Clone wiki repo: `git clone https://github.com/YasogaN/pqaudit.wiki.git`; write all pages as `.md` files; push with existing git credentials
5. Verify every code example and flag reference against source before committing
