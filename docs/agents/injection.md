# Injection Testing Agent

## Overview

The **Injection Testing Agent** performs active security testing by firing attack payloads at discovered endpoints. It tests 4 injection classes across all endpoints found by the Recon Agent (capped at 50 endpoints per scan).

**OWASP Coverage:** A03 - Injection

---

## Injection Types Tested

| Type | CVSS | Payload Count | Detection Method |
|---|---|---|---|
| SQL Injection (SQLi) | 9.8 (Critical) | 15 per param | SQL error strings in response body |
| XSS (Reflected) | 7.5 (High) | 15 per param | Payload reflected unescaped |
| Command Injection | 9.8 (Critical) | 10 per param | Command output (`uid=`, `root:`, etc.) |
| Path Traversal | 7.5 (High) | 10 × 3 target files | File content indicators |

---

## Payload Libraries

Payloads are defined in `packages/core/src/payloads/index.ts`:

- **SQLi:** Basic, UNION-based, time-based blind, error-based, polyglots
- **XSS:** Reflected, script tag variations, event handlers, encoded, DOM-based, polyglots
- **CmdI:** Unix operators, Windows operators, cross-platform polyglots
- **Path Traversal:** Unix/Windows relative paths up to 8 levels deep

---

## Parameter Discovery

For each endpoint, tested parameters come from:
1. Recon Agent's discovered `parameters` field (from form parsing)
2. Fallback defaults:
   - `GET` → `id`, `q`
   - `POST` → `cmd` (for command injection)
   - File params filtered by name keywords (`file`, `path`, `doc`, `page`)

---

## Vulnerability Detection Logic

```typescript
// SQLi: checks for DB error strings
if (body.includes('sql syntax') || body.includes('ora-') || body.includes('sqlite3')) {
  → vulnerable
}

// XSS: payload reflected without escaping
if (response.body.includes(payload)) {
  → vulnerable
}

// CmdI: command output indicators
if (body.includes('uid=') || body.includes('root:') || body.includes('drwx')) {
  → vulnerable
}
```

> **Note:** Time-based blind SQLi detection (via response timing) is not yet implemented.
