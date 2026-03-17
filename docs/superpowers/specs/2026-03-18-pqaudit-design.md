# pqaudit — Design Specification

**Date:** 2026-03-18
**Status:** Approved
**Repository:** https://github.com/YasogaN/pqaudit
**License:** Apache-2.0
**Language:** Rust

---

## 1. Problem Statement

NIST IR 8547 (November 2024) sets hard deadlines: RSA-2048 and ECC P-256 deprecated after 2030, disallowed after 2035. ML-KEM (FIPS 203) and ML-DSA (FIPS 204) are finalized NIST standards, but tooling to audit existing TLS infrastructure for post-quantum readiness is fragmented and incomplete.

At least six PQC scanning tools appeared in 2025 alone — none combine live TLS endpoint scanning, compliance scoring, CBOM generation, SARIF output, and agent integration in a single static binary. testssl.sh (8.9k stars) detects PQC groups when present but does not warn when absent, has no scoring, and requires a PQC-capable OpenSSL 3.6+ build. pqcscan (Rust, July 2025) and tlsferret (Rust, June 2025) are both early-stage with no scoring, no CBOM, no SARIF, and no extensible compliance framework.

**pqaudit fills the gap:** a single static Rust binary that scans live TLS endpoints, scores PQC readiness against NIST IR 8547 and CNSA 2.0, generates a Cryptographic Bill of Materials, emits SARIF for CI/CD integration, and ships an MCP server mode for agent consumption.

---

## 2. Competitive Landscape

| Tool | Lang | Hybrid scan | PQC score | CBOM | SARIF | Agent/MCP | Status |
|---|---|---|---|---|---|---|---|
| testssl.sh | Bash | Active enum | ✗ | ✗ | ✗ | ✗ | 8.9k★, no PQC gap flag |
| pqcscan | Rust | Passive only | ✗ | ✗ | ✗ | ✗ | July 2025, minimal |
| tlsferret | Rust | Active enum | ✗ | ✗ | ✗ | ✗ | June 2025, v0.1, 11 commits |
| sslyze | Python | Active enum | ✗ | ✗ | ✗ | ✗ | No PQC awareness |
| ImmuniWeb | Web UI | Passive | Partial | ✗ | ✗ | ✗ | Online only, no CLI |
| **pqaudit** | **Rust** | **Both** | **✓** | **✓** | **✓** | **✓** | **This project** |

---

## 3. Scope (v1 / MVP)

All features below ship in v1:

- Passive PQC probe (default, ~1–2s/host) + active cipher suite enumeration (`--full-scan`, ~30–120s/host)
- PQC readiness score 0–100 (weighted rubric + NIST IR 8547 timeline multipliers)
- HNDL (harvest-now-decrypt-later) risk rating: NONE/LOW/MEDIUM/HIGH/CRITICAL
- Full certificate chain audit (leaf + intermediates + root, key type/size/expiry vs deadline)
- Certificate expiry × NIST deadline correlation
- HelloRetryRequest detection and scoring penalty
- Downgrade probe (classical-only ClientHello, flags servers that accept it)
- Kyber draft detection (code point 0x6399, deprecated pre-FIPS implementation)
- STARTTLS support: SMTP, IMAP, POP3, LDAP
- Output formats: JSON (default), SARIF 2.1.0, CycloneDX 1.6 CBOM, human (colored terminal)
- `--compliance` flag: `nist` (default), `cnsa2`, `fips`
- `--fail-below <N>` for CI/CD gate (exit code 1)
- `--baseline` for diff against prior scan (progress tracking)
- `--compare` for side-by-side multi-endpoint table
- Batch scanning from `--targets-file`
- Remediation guidance per finding with config snippets (nginx, caddy, openssl, go, java)
- MCP server mode (`--mcp` flag, `rmcp` 1.2.0) with `scan_endpoint`, `compare_endpoints`, `get_cbom` tools
- Claude skill (`skills/pqaudit.md`) shipped in repo
- GitHub Action (published to GitHub Marketplace)
- Extensible scoring architecture: new compliance frameworks added by adding one table file + one optional model file
- Static binary: no runtime dependencies, cross-compiled for Linux/macOS/Windows

---

## 4. Architecture

### 4.1 Approach

**Approach C: rustls + raw TLS record crafting.**

- `rustls` 0.23.37 + `aws-lc-rs` 1.16.1 handles the authoritative PQC handshake and certificate chain retrieval.
- A lightweight raw TLS record layer over `tokio::net::TcpStream` sends crafted ClientHello messages and parses ServerHello/Alert responses for active enumeration. Never completes the handshake — no keys derived, no certs exchanged.
- Fully static binary (`RUSTFLAGS="-C target-feature=+crt-static"`). No OpenSSL runtime dependency.

Rejected alternatives:
- **rustls-only:** Cannot exhaustively enumerate legacy cipher suites — rustls won't negotiate weak/deprecated suites by design.
- **rustls + native-tls:** Dynamic OpenSSL dependency breaks static binary promise.

### 4.2 Module Structure

```
pqaudit/
├── src/
│   ├── main.rs
│   ├── cli.rs
│   ├── scanner.rs              # Orchestrator: drives probe → audit → output pipeline
│   ├── mcp.rs                  # MCP server adapter (rmcp 1.2.0, --mcp flag)
│   │
│   ├── probe/
│   │   ├── mod.rs
│   │   ├── handshake.rs        # Raw TCP → TLS record layer (ClientHello builder/parser)
│   │   ├── cipher_enum.rs      # Active enumeration: iterates cipher suite batches
│   │   ├── pqc_probe.rs        # rustls-based PQC handshake (actual connection)
│   │   ├── downgrade.rs        # Classical-only ClientHello probe
│   │   ├── hrr.rs              # HelloRetryRequest detection
│   │   └── starttls.rs         # SMTP/IMAP/POP3/LDAP protocol upgrade
│   │
│   ├── audit/
│   │   ├── mod.rs
│   │   ├── findings.rs         # FindingKind enum (typed, exhaustive)
│   │   ├── cert_chain.rs       # Certificate chain walk + key extraction
│   │   ├── compliance.rs       # ComplianceMode enum, ties table + model together
│   │   ├── remediation.rs      # Per-finding remediation + config snippets
│   │   ├── hndl.rs             # HNDL risk model trait + default implementation
│   │   ├── tables/
│   │   │   ├── mod.rs
│   │   │   ├── nist_ir8547.rs  # NIST IR 8547 deprecation deadlines
│   │   │   ├── cnsa2.rs        # NSA CNSA 2.0 algorithm requirements + timelines
│   │   │   ├── fips.rs         # FIPS 140-3 approved algorithm list
│   │   │   ├── iana_groups.rs  # TLS NamedGroup registry: code point → name → PQC status
│   │   │   ├── iana_ciphers.rs # TLS cipher suite registry: ID → name → strength class
│   │   │   └── iana_sigalgs.rs # TLS signature algorithm registry
│   │   └── scoring/
│   │       ├── mod.rs          # model_for() factory + ComplianceMode
│   │       ├── model.rs        # ScoringModel trait, ScoringResult, CategoryScore
│   │       ├── weighted.rs     # Default weighted + timeline-multiplier model
│   │       ├── binary_gates.rs # Strict pass/fail model
│   │       └── cnsa2_strict.rs # CNSA 2.0 hard-requirement model
│   │
│   ├── output/
│   │   ├── mod.rs
│   │   ├── json.rs
│   │   ├── sarif.rs
│   │   ├── cbom.rs
│   │   ├── human.rs
│   │   └── compare.rs
│   │
│   └── baseline.rs
│
├── tests/
│   ├── fixtures/               # Pre-recorded TLS handshake byte captures
│   └── integration/
│
├── skills/
│   └── pqaudit.md              # Claude skill
│
├── .github/
│   ├── workflows/
│   │   ├── ci.yml
│   │   └── release.yml
│   └── actions/pqaudit/        # GitHub Action
│       └── action.yml
│
└── mcp-config.example.json
```

### 4.3 Data Flow

```
CLI args / MCP tool call
  → scanner::scan(targets, config)
      → for each target (concurrent via tokio, bounded by semaphore):
          probe::pqc_probe     → PqcHandshakeResult  (rustls, authoritative)
          probe::cipher_enum   → CipherInventory      (raw probe, --full-scan only)
          probe::downgrade     → DowngradeResult      (raw probe)
          probe::hrr           → HrrResult            (from pqc_probe)
          probe::starttls      → TcpStream upgrade    (if smtp://, imap://, etc.)
      → audit::cert_chain      → CertChainReport
      → audit::findings        → Vec<Finding>
      → audit::scoring         → ScoringResult (0–100 + breakdown)
      → audit::hndl            → HndlAssessment
      → audit::remediation     → Vec<Remediation>
      → output::{json,sarif,cbom,human}
      → baseline::diff         → BaselineDiff (if --baseline)
```

---

## 5. Dependencies

| Crate | Version | Purpose |
|---|---|---|
| `rustls` | 0.23.37 | PQC-capable TLS handshake |
| `aws-lc-rs` | 1.16.1 | Crypto backend (ML-KEM, static link) |
| `tokio` | 1.50.0 | Async runtime |
| `tokio-rustls` | 0.26.4 | Async TLS streams |
| `clap` | 4.6.0 | CLI (requires Rust 1.85) |
| `x509-parser` | 0.18.1 | Certificate chain parsing |
| `cyclonedx-bom` | 0.8.0 | CycloneDX 1.6 CBOM output |
| `serde-sarif` | 0.8.0 | SARIF 2.1.0 output |
| `serde` | 1.0.228 | Serialization |
| `serde_json` | 1.0.149 | JSON output |
| `owo-colors` | 4.3.0 | Terminal colors |
| `indicatif` | 0.18.4 | Progress bars |
| `rmcp` | 1.2.0 | MCP server (optional feature flag) |

Minimum Rust version: **1.85** (required by clap 4.6.0).

---

## 6. CLI Interface

```
pqaudit [OPTIONS] <TARGETS>...

ARGS:
  <TARGETS>...   Hosts to scan: example.com, example.com:8443,
                 smtp://mail.example.com, imap://mail.example.com:993

OPTIONS:
  # Scan behavior
  -f, --full-scan          Active cipher suite enumeration (default: passive only)
      --concurrency <N>    Parallel scan limit [default: 10]
      --timeout <MS>       Per-probe TCP timeout [default: 5000]
      --sni <HOST>         Override SNI (useful for IP scanning)
      --q-day <YEAR>       Estimated quantum threat year for HNDL scoring [default: 2030]

  # Compliance
      --compliance <MODE>  Scoring framework: nist (default), cnsa2, fips

  # Output
  -o, --output <FORMAT>    json (default), sarif, cbom, human
      --output-file <PATH> Write output to file (default: stdout)
      --fail-below <N>     Exit code 1 if any host scores below N [0–100]

  # Comparison & tracking
      --baseline <PATH>    Load prior JSON result; emit diff alongside new result
      --compare            Side-by-side multi-endpoint comparison table (human only)

  # Targets from file
      --targets-file <PATH> Newline-separated target list

  # Agent mode
      --mcp                Start MCP server over stdio (rmcp)
```

**Exit codes:**

| Code | Meaning |
|---|---|
| 0 | All hosts scanned, all passed `--fail-below` (or no threshold set) |
| 1 | One or more hosts failed `--fail-below` threshold |
| 2 | Scan error (all targets failed: connection refused, DNS failure, etc.) |
| 3 | Invalid arguments |

---

## 7. Probe Engine

### 7.1 Layer 1 — rustls PQC Handshake (`probe/pqc_probe.rs`)

Full TLS connection via `tokio-rustls` + `aws-lc-rs`. Establishes a real connection, extracts:
- Negotiated TLS version
- Negotiated cipher suite
- Negotiated key exchange group (NamedGroup code point)
- Whether a HelloRetryRequest was issued before PQC group agreed
- Full certificate chain (DER bytes, passed to `audit::cert_chain`)

### 7.2 Layer 2 — Raw Probe (`probe/handshake.rs`, `probe/cipher_enum.rs`)

Minimal TLS record layer over raw `tokio::net::TcpStream`. Sends a crafted `ClientHello`, reads response, classifies as: `ServerHello` (accepted), `HandshakeFailure` alert (rejected), timeout, or connection close. Never completes the handshake.

**Active cipher enumeration algorithm:**
1. Start with all ~400 IANA cipher suite IDs
2. Send `ClientHello` offering batches of 64 suites
3. On `ServerHello`: record selected suite, remove from candidate set, repeat
4. On `HandshakeFailure`: remove entire batch, try next
5. Continue until candidate set exhausted (~10–20 round trips for a typical server)

**Additional raw probes:**
- **Downgrade probe:** `ClientHello` with classical suites only + `max_version = TLS 1.2`. `ServerHello` response → downgrade accepted (critical finding).
- **Kyber draft probe:** `ClientHello` advertising only `0x6399` (X25519Kyber768Draft00). `ServerHello` → deprecated pre-FIPS implementation detected.

### 7.3 STARTTLS (`probe/starttls.rs`)

Protocol-specific upgrade before handing TCP stream to probe layers:

| Scheme | Port | Upgrade sequence |
|---|---|---|
| `smtp://` | 587/25 | `EHLO` → `STARTTLS` → await `220 Ready` |
| `imap://` | 143 | await `* OK` → `a001 STARTTLS` → await `a001 OK` |
| `pop3://` | 110 | `STLS` → await `+OK` |
| `ldap://` | 389 | StartTLS extended operation |

### 7.4 Concurrency Model

```rust
let semaphore = Arc::new(Semaphore::new(config.concurrency));
let results = futures::stream::iter(targets)
    .map(|target| {
        let sem = semaphore.clone();
        async move {
            let _permit = sem.acquire_owned().await;
            scan_single(target, &config).await
        }
    })
    .buffer_unordered(config.concurrency)
    .collect::<Vec<_>>()
    .await;
```

Per target: `pqc_probe` and `downgrade` run concurrently (independent TCP connections). `cipher_enum` runs only with `--full-scan`. Progress bar updates as each probe completes.

---

## 8. Scoring Engine

### 8.1 Architecture Principles

Three strict separations:
1. **Tables are data** — deadline/classification tables contain zero scoring logic
2. **Models are traits** — each scoring model implements `ScoringModel`; new frameworks = new file
3. **HNDL is independent** — separate trait, separate computation, separate output field

Adding a new compliance framework (e.g., BSI TR-02102, ANSSI) requires: one table file + optionally one model file + one enum variant. Nothing else changes.

### 8.2 Key Traits

```rust
pub trait DeadlineTable: Send + Sync {
    fn name(&self) -> &'static str;
    fn deadline_for(&self, alg: &AlgorithmId) -> Option<DeadlineInfo>;
    fn status_for(&self, alg: &AlgorithmId) -> AlgorithmStatus;
}

pub trait ScoringModel: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn score(&self, probe: &ProbeResults, table: &dyn DeadlineTable) -> ScoringResult;
    fn severity(&self, finding: &FindingKind) -> Severity;
}

pub trait HndlModel: Send + Sync {
    fn name(&self) -> &'static str;
    fn assess(&self, probe: &ProbeResults, config: &HndlConfig) -> HndlAssessment;
}
```

### 8.3 PQC Readiness Score (0–100)

Five weighted categories:

| Category | Max Points | What is checked |
|---|---|---|
| Key exchange | 50 | PQC group negotiated, which group, HRR required |
| TLS version | 15 | TLS 1.3 required |
| Cipher suite | 15 | Symmetric algorithm and key size |
| Certificate chain | 15 | Key type + size of leaf and each CA cert |
| Downgrade posture | 5 | Server rejects classical-only probe |

**Key exchange points:**

| Negotiated group | Points | Notes |
|---|---|---|
| X25519MLKEM768 (0x11EC), no HRR | 50 | Current standard, optimal |
| X25519MLKEM768 (0x11EC), HRR required | 40 | -10 performance/deployment penalty |
| SecP256r1MLKEM768 (0x11EB) | 45 | Weaker classical component |
| SecP384r1MLKEM1024 (0x11ED) | 50 | CNSA 2.0 level |
| Pure ML-KEM-1024 (0x0202) | 50 | CNSA 2.0 level, no classical fallback |
| Pure ML-KEM-768 (0x0201) | 48 | Forward-looking, no classical fallback |
| X25519Kyber768Draft00 (0x6399) | 20 | Deprecated pre-FIPS, flagged as finding |
| Classical only (x25519, P-256, etc.) | 0 | No PQC |

**TLS version points:**

| Version | Points |
|---|---|
| TLS 1.3 | 15 |
| TLS 1.2 | 5 |
| TLS 1.1 or older | 0 |

**Cipher suite points:**

| Cipher suite | Points |
|---|---|
| AES-256-GCM / ChaCha20-Poly1305 | 15 |
| AES-128-GCM | 8 |
| 3DES, RC4, export-grade | 0 |

**Timeline multiplier** (applied to cert chain and cipher suite categories):

| Years until disallowance | Multiplier | Zone |
|---|---|---|
| ≥ 9 years | 1.00 | Safe |
| 5–8 years | 0.75 | Warning |
| 2–4 years | 0.40 | Urgent |
| < 2 years | 0.10 | Critical |
| Past deadline | 0.00 | Non-compliant |

Example: RSA-2048 leaf in 2026 → deadline 2030 → 4 years → multiplier 0.40 → cert chain max = `15 × 0.40 = 6 pts`.

**Compliance mode adjustments:**

| Mode | Key difference |
|---|---|
| `nist` (default) | NIST IR 8547 deadlines; ML-KEM-768 = full key exchange score |
| `cnsa2` | ML-KEM-1024 required for full score; ML-KEM-768 = 35/50; AES-256 mandatory |
| `fips` | FIPS 140-3 approved only; ChaCha20 = 0 pts in cipher category |

### 8.4 HNDL Risk Rating

Independent of readiness score. Quantifies retrospective decryption risk.

```
hndl_risk = f(key_exchange_algorithm, cert_expiry, estimated_q_day)

estimated_q_day      = 2030 (default, overridable via --q-day)
data_exposure_window = min(cert_expiry_date, estimated_q_day) - today
```

| Condition | Rating |
|---|---|
| Pure PQC key exchange | NONE |
| Hybrid PQC + exposure window < 2 years | LOW |
| Hybrid PQC + exposure window 2–5 years | MEDIUM |
| Classical key exchange + exposure window < 2 years | MEDIUM |
| Classical key exchange + exposure window 2–5 years | HIGH |
| Classical key exchange + exposure window > 5 years | CRITICAL |

---

## 9. Algorithm Deadline Tables

Tables live in `audit/tables/` as pure data — no scoring logic.

### NIST IR 8547 Deadlines (key entries)

| Algorithm | Deprecated | Disallowed | Note |
|---|---|---|---|
| RSA < 2048-bit | Now | Now | Already disallowed |
| RSA-2048 | 2024 | 2030 | Primary hard wall |
| RSA-3072 | 2024 | 2030 | |
| RSA-4096 | 2024 | 2035 | Extended deadline |
| P-256 / secp256k1 | 2024 | 2030 | |
| P-384 | 2024 | 2030 | |
| P-521 | 2024 | 2035 | Extended deadline |
| X25519 / Ed25519 | 2024 | 2030 | |
| X448 / Ed448 | 2024 | 2035 | Extended deadline |
| DH < 2048-bit | Now | Now | Already disallowed |
| DH-2048 | 2024 | 2030 | |
| DH-3072+ | 2024 | 2035 | Extended deadline |

### CNSA 2.0 Requirements

| Algorithm | Requirement | Deadline |
|---|---|---|
| ML-KEM-1024 (FIPS 203) | Required for NSS key exchange | New systems from 2026 |
| ML-DSA-87 (FIPS 204) | Required for NSS signatures | New systems from 2026 |
| AES-256 | Required (AES-128 insufficient) | Now |
| SHA-384/SHA-512 | Required | Now |
| CNSA 1.0 (RSA, ECDH P-384) | Deprecated | Disallowed 2030 |
| Exclusive PQC (no classical fallback) | Mandatory | 2033 |

### IANA TLS NamedGroup Registry (PQC entries)

| Group Name | Code Point | Status |
|---|---|---|
| X25519MLKEM768 | 0x11EC (4588) | Current standard hybrid |
| SecP256r1MLKEM768 | 0x11EB (4587) | Alternative hybrid |
| SecP384r1MLKEM1024 | 0x11ED (4589) | CNSA 2.0 hybrid |
| ML-KEM-512 (pure) | 0x0200 | FIPS 203 Category 1 |
| ML-KEM-768 (pure) | 0x0201 | FIPS 203 Category 3 |
| ML-KEM-1024 (pure) | 0x0202 | FIPS 203 Category 5 (CNSA 2.0) |
| X25519Kyber768Draft00 | 0x6399 | Deprecated pre-FIPS (flag as finding) |

---

## 10. Finding Types

```rust
pub enum FindingKind {
    ClassicalKeyExchangeOnly { group: NamedGroup },
    HybridKeyExchangeHrrRequired { group: NamedGroup },
    DeprecatedPqcDraftCodepoint { code_point: u16 },
    WeakSymmetricCipher { suite: CipherSuite },
    ClassicalCertificate { position: ChainPosition, key: KeyInfo, deadline: u32 },
    DowngradeAccepted,
    TlsVersionInsufficient { max_version: TlsVersion },
    CertExpiresAfterDeadline { expiry: Date, deadline: u32, algorithm: AlgorithmId },
}
```

**SARIF Rule IDs:**

| Rule ID | Finding | Default Severity |
|---|---|---|
| PQA001 | classical-key-exchange-only | error |
| PQA002 | hybrid-key-exchange-hrr-required | warning |
| PQA003 | deprecated-pqc-draft-codepoint | error |
| PQA004 | weak-symmetric-cipher | warning |
| PQA005 | classical-certificate-pre-2030 | warning |
| PQA006 | classical-certificate-pre-2035 | note |
| PQA007 | downgrade-accepted | error |
| PQA008 | tls-version-insufficient | error |
| PQA009 | cert-expires-after-deadline | warning |

---

## 11. Output Formats

All four formats derived from a single `ScanReport` struct — one analysis pass, four renderers.

### JSON (default)
Native schema, schema-versioned (`"schema_version": "1.0"`). Full fidelity. Source of truth for baseline diffing.

### SARIF 2.1.0
Via `serde-sarif` 0.8.0. Findings map to `results` with stable rule IDs (PQA001–PQA009). Each result includes `helpUri` and `fixes` with remediation config snippet. Consumed by GitHub Advanced Security code scanning.

### CycloneDX 1.6 CBOM
Via `cyclonedx-bom` 0.8.0. One `cryptographic-asset` component per unique algorithm+keysize observed across all scanned targets. Aggregates occurrences (host:port + chain position) per component. Intended as supply chain compliance deliverable.

### Human
Colored terminal output via `owo-colors`. Progress bars via `indicatif`. Streaming output per target (results print as they complete). `--compare` mode: waits for all targets, renders side-by-side comparison table.

### Baseline Diff (`--baseline prev.json`)
Loads prior JSON scan, diffs against current, appends `baseline_diff` block to JSON output. Human mode renders change summary showing score deltas and resolved/new findings.

---

## 12. Agent Interface

### MCP Server (`--mcp`)

Single binary, started in MCP server mode over stdio using `rmcp` 1.2.0 (official Rust MCP SDK). Zero logic duplication — MCP tool calls route to the same `scanner::scan()` pipeline as the CLI.

**Tools exposed:**

| Tool | Inputs | Output |
|---|---|---|
| `scan_endpoint` | host, port, full_scan, compliance, protocol | `TargetReport` as JSON |
| `compare_endpoints` | hosts[], full_scan, compliance | `ComparisonTable` as JSON |
| `get_cbom` | hosts[], compliance | CycloneDX 1.6 CBOM JSON |

**Resource:**
- `pqaudit://findings/{host}` — cached findings for a previously scanned host (within session)

MCP is a Cargo feature (`--features mcp`), included in default binary. Users wanting a minimal binary can build without it.

### Claude Skill (`skills/pqaudit.md`)

Ships in repo root. Teaches Claude how to install pqaudit, invoke common scan patterns, interpret scores, and choose output formats. Trigger phrases include: "audit TLS", "check PQC readiness", "generate CBOM", "NIST IR 8547 compliance", "quantum risk".

---

## 13. Error Handling

Typed errors, no `unwrap()` in library code. Batch scans never abort on a single target failure — partial results always written. Exit code 2 only if all targets fail.

```rust
pub enum ProbeError {
    ConnectionRefused { host: String, port: u16 },
    DnsResolutionFailed { host: String },
    TlsHandshakeFailed { reason: String },
    Timeout { after_ms: u64 },
    StarttlsUpgradeFailed { protocol: StarttlsProtocol, reason: String },
    CertificateParseError { reason: String },
}
```

---

## 14. Testing Strategy

### Unit Tests
Pure functions only, no I/O. Cover: score calculation for all compliance modes, timeline multiplier math, HNDL rating logic, ClientHello serialization, ServerHello parsing, SARIF rule ID stability, CBOM schema validity, JSON round-trip.

### Integration Tests
Pre-recorded TLS handshake fixtures in `tests/fixtures/` (byte arrays) for: classical-only server, hybrid PQC server, HRR-requiring server, downgrade-accepting server, STARTTLS server. Replayed through probe parser — fast, deterministic, no network required.

Live-network tests behind `#[cfg(feature = "live-tests")]`: scans `cloudflare.com` (known PQC hybrid), `example.com` (known classical), verifies score ranges.

### Property Tests (`proptest`)
`audit/scoring/` only: score always 0–100, timeline multiplier always 0.0–1.0, adding PQC key exchange never decreases score.

### CI Matrix
```yaml
strategy:
  matrix:
    os: [ubuntu-latest, macos-latest, windows-latest]
    rust: [stable, beta]
```

Static binary build verified on each push:
```bash
RUSTFLAGS="-C target-feature=+crt-static" \
  cargo build --release --target x86_64-unknown-linux-musl
```

---

## 15. Adoption Pathway

- Publish on crates.io + Homebrew + Docker Hub + GitHub Releases (Linux/macOS/Windows binaries)
- GitHub Action on Marketplace — first PQC scanner as a native Action
- Launch post: scan Google, Cloudflare, AWS endpoints with live score output
- Target: r/netsec, r/cybersecurity, post-quantum-crypto mailing list
- MCP server mode enables direct agent consumption with zero setup

---

## 16. Future Compliance Frameworks (Post-v1)

Adding any of the following requires only one table file + optionally one model file:

- BSI TR-02102 (Germany)
- ANSSI (France)
- ISO/IEC 18033
- ETSI TS 103 744
- Custom enterprise policy via `--compliance-file policy.toml`
