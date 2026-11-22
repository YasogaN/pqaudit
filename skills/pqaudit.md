---
name: pqaudit
description: Audit TLS endpoints for post-quantum cryptography readiness
triggers:
  - audit TLS
  - check PQC readiness
  - generate CBOM
  - NIST IR 8547 compliance
  - quantum risk
---

# pqaudit

pqaudit scans TLS endpoints and scores PQC readiness against NIST IR 8547 (draft), CNSA 2.0, and FIPS 140-3. It completes a real rustls handshake, audits the certificate chain (including ML-DSA/ML-KEM/SLH-DSA), and reports classical fallback, downgrade, and legacy-TLS support.

## Install

```bash
# Linux x86_64 (static musl)
curl -sSfL https://github.com/YasogaN/pqaudit/releases/latest/download/pqaudit-linux-x86_64 -o pqaudit && chmod +x pqaudit

# Linux aarch64 (static musl)
curl -sSfL https://github.com/YasogaN/pqaudit/releases/latest/download/pqaudit-linux-aarch64 -o pqaudit && chmod +x pqaudit

# macOS Apple silicon
curl -sSfL https://github.com/YasogaN/pqaudit/releases/latest/download/pqaudit-macos-aarch64 -o pqaudit && chmod +x pqaudit

# macOS Intel
curl -sSfL https://github.com/YasogaN/pqaudit/releases/latest/download/pqaudit-macos-x86_64 -o pqaudit && chmod +x pqaudit

# Cargo (latest published release)
cargo install pqaudit
```

Windows users can download `pqaudit-windows-x86_64.exe` from the releases page.

## Quick scan

```bash
pqaudit example.com                         # JSON output, NIST scoring
pqaudit -o human example.com                # Colored terminal output
pqaudit --full-scan example.com             # Active cipher enumeration (~2min)
pqaudit --compliance cnsa2 example.com      # CNSA 2.0 scoring
pqaudit --fail-below 80 example.com         # CI/CD gate
pqaudit -o sarif example.com > scan.sarif   # For GitHub Advanced Security
pqaudit -o cbom example.com > cbom.json     # CycloneDX 1.6 CBOM
pqaudit --insecure staging.example.com      # Audit an untrusted/expired chain
pqaudit --ca-file internal-ca.pem internal.example.com  # Private CA
```

## Score interpretation

| Score | Meaning |
|-------|---------|
| 80–100 | PQC-ready or nearly ready |
| 60–79 | Hybrid PQC negotiated, but fallback or chain gaps remain |
| 40–59 | Classical TLS 1.3 negotiated; PQC may be available but was not selected |
| < 40  | Classical-only or no working TLS; significant risk |

`PQA016` means the server supports PQC but selected a classical group for the default offer. `PQA001` means no PQC group was negotiated even when only PQC groups were offered.

## MCP server mode

Add to your Claude config:
```json
{ "mcpServers": { "pqaudit": { "command": "pqaudit", "args": ["--mcp"] } } }
```
Then ask Claude: "Scan example.com for PQC readiness"
