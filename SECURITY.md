# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities by emailing **security@guardiant.dev** with:

1. A description of the vulnerability and its potential impact
2. Steps to reproduce or a proof-of-concept
3. Any relevant logs or screenshots

We aim to acknowledge reports within **48 hours** and provide a timeline for a fix within **7 days**.

---

## Scope

| In Scope | Out of Scope |
|---|---|
| Guardiant core platform (`packages/core`) | Third-party dependencies |
| CLI application (`apps/cli`) | Intentional test payloads |
| Database operations (`packages/database`) | Social engineering |
| LLM prompt injection risks | DoS via resource exhaustion |

---

## Disclosure Policy

We follow **responsible disclosure**. Once a fix is available, we will:

1. Credit the reporter (with their permission)
2. Publish an advisory in GitHub Advisories
3. Update `CHANGELOG.md` with the fix

Thank you for keeping Guardiant and its users safe.
