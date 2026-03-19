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

pqaudit scans TLS endpoints and scores PQC readiness against NIST IR 8547 and CNSA 2.0.

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
pqaudit -o cbom example.com > cbom.json     # CycloneDX CBOM
```

## Score interpretation

| Score | Meaning |
|-------|---------|
| 80–100 | PQC-ready or nearly ready |
| 60–79 | Hybrid PQC negotiated, gaps remain |
| 40–59 | Classical TLS 1.3, no PQC |
| < 40  | Significant risk |

## MCP server mode

Add to your Claude config:
```json
{ "mcpServers": { "pqaudit": { "command": "pqaudit", "args": ["--mcp"] } } }
```
Then ask Claude: "Scan example.com for PQC readiness"
