# README & Wiki Overhaul — Design Spec

**Date:** 2026-03-19
**Status:** Approved

---

## Goal

Overhaul the pqaudit README to a polished, accurate, B/C-style document that serves security engineers, DevOps/platform engineers, and developers equally. Create a companion set of extremely detailed GitHub wiki pages covering everything too deep for the README.

---

## README Design

### Tone & Style
Professional but approachable, like ripgrep or bat. Some developer-marketing flair (badges, real demo). Every claim verified against source code.

### Structure (Hook → Quick start → Features → Reference)

1. **Badge header** — CI status · License: Apache-2.0 · Latest Release
2. **Title + 2-sentence hook** — what it is and why it matters in one breath
3. **Real terminal demo block** — actual output from `pqaudit -o human cloudflare.com:443`, ANSI stripped
4. **Features** — four grouped categories:
   - Probing (PQC handshake, cipher enumeration, downgrade, HRR, STARTTLS)
   - Scoring & Risk (0-100 rubric, HNDL assessment, compliance modes)
   - Output (human, JSON, SARIF 2.1.0, CycloneDX 1.5 CBOM, baseline diff)
   - Integration (CI/CD gate, GitHub Action, MCP server)
5. **Installation** — pre-built binary (curl one-liner for Linux x86_64) + from source
6. **Quick Start** — focused examples, one per scenario:
   - Basic scan
   - Compliance mode
   - Fail-below threshold (CI gate)
   - Output formats (human, JSON, SARIF, CBOM, file output)
   - Full cipher scan (`--full-scan`)
   - Batch scan from file
   - Baseline save & compare
   - STARTTLS protocols (URL scheme)
   - SNI override / custom timeout
   - MCP server mode
7. **Reference tables** — Score grades, exit codes, compliance modes; each table links to the corresponding wiki page for deeper detail
8. **AI Disclosure** — unchanged
9. **Contributing · Code of Conduct · License** — unchanged

### Constraints
- Fix the remaining stale reference: exit codes table still says `--fail-under` (must be `--fail-below`)
- All flag names, defaults, and behaviours must match `src/cli/mod.rs` exactly
- `YOUR_ORG` placeholders replaced with `YasogaN`

---

## Wiki Design

Repo: `YasogaN/pqaudit` — wiki pushed via git to the `.wiki.git` remote.

All content verified against source before writing. No claims made that aren't in the code.

### Pages

#### Home
- Project summary, key use cases
- Full navigation index linking every wiki page
- Quick links to installation, CI integration, MCP

#### Scoring-System
Verified against: `src/audit/scoring/weighted.rs`, `src/audit/scoring/model.rs`, `src/audit/scoring/binary_gates.rs`, `src/audit/scoring/cnsa2_strict.rs`, `src/audit/hndl.rs`
- Full weighted rubric: each category, its max points, what earns/loses points
- Timeline multiplier logic explained
- Grade boundaries (A/B/C/D/F) with what each means operationally
- HNDL model: exposure window calculation, rating thresholds (NONE/LOW/MEDIUM/HIGH/CRITICAL), `--q-day` config
- CNSA2 strict / binary gate scoring differences

#### Finding-Codes
Verified against: `src/audit/findings.rs`, `src/audit/remediation.rs`, `src/audit/scoring/model.rs`
- Every `FindingKind` variant: code, description, what triggers it
- Severity per compliance mode (NIST vs CNSA2 vs FIPS)
- Remediation snippets per finding: nginx, Caddy, OpenSSL, Go, Java

#### Compliance-Modes
Verified against: `src/audit/tables/nist_ir8547.rs`, `src/audit/tables/cnsa2.rs`, `src/audit/tables/fips.rs`, `src/audit/compliance.rs`
- NIST IR 8547: full deprecation timeline, which algorithms are affected and by when
- CNSA 2.0: ML-KEM-1024 requirement, 2033 exclusive-PQC deadline
- FIPS 140-3: approved algorithm list
- Side-by-side comparison table
- When to use each mode

#### Output-Formats
Verified against: `src/output/json.rs`, `src/output/sarif.rs`, `src/output/cbom.rs`, `src/output/human.rs`
- JSON: full annotated schema with example output
- SARIF 2.1.0: structure walkthrough, how to upload to GitHub Code Scanning
- CycloneDX 1.5 CBOM: field mapping, how components map to cipher inventory
- Human: output anatomy (header, per-target block, findings, score)

#### CI-CD-Integration
Verified against: `src/main.rs` (exit codes), CLI defaults
- GitHub Actions: full workflow YAML with SARIF upload
- GitLab CI: equivalent `.gitlab-ci.yml`
- Exit code semantics: 0/1/2/3 with CI implications
- `--fail-below` strategy: recommended thresholds per compliance posture
- Batch scan pattern for large inventories

#### MCP-Integration
Verified against: `src/mcp/mod.rs`
- stdio transport setup and process invocation
- Tool schemas: `scan_endpoint`, `compare_endpoints`, `get_cbom` — full JSON input/output
- Claude Desktop `claude_desktop_config.json` example
- Example agent sessions showing realistic request/response pairs

#### Baseline-Tracking
Verified against: `src/baseline/mod.rs`, `src/main.rs` (baseline diff output)
- Save/load workflow
- Diff output format: score delta, resolved findings, new findings
- Recommended CI pattern: save baseline on main, diff on PRs
- Regression detection strategy

#### STARTTLS
Verified against: `src/probe/starttls.rs`
- Per-protocol handshake details: SMTP (EHLO/STARTTLS), IMAP (CAPABILITY/STARTTLS), POP3 (CAPA/STLS), LDAP (ExtendedRequest OID)
- URL scheme reference table: scheme → default port → STARTTLS command
- When to use `smtp://` vs `smtps://` (direct TLS vs STARTTLS)
- Known server behaviour notes

---

## Implementation Notes

- Wiki pushed via: `git clone https://github.com/YasogaN/pqaudit.wiki.git`, write pages, push
- Each wiki page is a `.md` file; filename = page title with hyphens
- README changes committed to main branch as a single commit
- All source files read before drafting content for their section
