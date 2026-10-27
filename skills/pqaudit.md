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
# Linux/macOS
curl -sSL https://github.com/YasogaN/pqaudit/releases/latest/download/pqaudit-$(uname -s | tr A-Z a-z)-$(uname -m) -o pqaudit && chmod +x pqaudit

# Cargo
cargo install pqaudit
```

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
| 40–59 | Classical TLS 1.3, no PQC |
| < 40  | Significant risk or no working TLS |

## MCP server mode

Add to your Claude config:
```json
{ "mcpServers": { "pqaudit": { "command": "pqaudit", "args": ["--mcp"] } } }
```
Then ask Claude: "Scan example.com for PQC readiness"
