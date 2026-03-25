# Changelog

All notable changes to Guardiant are documented here.

This project follows [Semantic Versioning](https://semver.org) and [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Added
- Phase 8: Testing infrastructure — Vitest unit tests for shared utilities, agents, analyzers, and queue
- Phase 8: Documentation — `docs/` folder with overview, architecture, configuration, and agent references
- Phase 8: Repository polish — `.env.example`, `SECURITY.md`, `CHANGELOG.md`
- Phase 8: Dockerfile — multi-stage build with non-root user
- Phase 8: GitHub Actions — CI, release, Docker, and Dependabot workflows

---

## [0.1.0] — 2026-03-20

### Added

#### Foundation (Phase 1)
- Turborepo monorepo setup with pnpm workspaces
- `@guardiant/shared` — TypeScript types, OWASP categories, VCVF pattern constants, crypto/format/logger utilities
- `@guardiant/database` — SQLite schema using Drizzle ORM (scans, findings, agent_runs, compound_chains, vcvf_fingerprints, trust_inversions, reports)
- `@guardiant/queue` — In-memory queue with BullMQ/Redis fallback

#### Agent Swarm (Phase 2)
- **Recon Agent** — Endpoint discovery, JS bundle analysis, tech stack fingerprinting, VCVF pattern detection
- **Injection Agent** — SQLi, XSS, Command Injection, Path Traversal with active payload library
- **BaaS Agent** — Supabase RLS, Firebase rules, service key exposure, storage permissions, SECURITY DEFINER
- **Secrets Agent** — API key and environment variable detection
- **Auth Agent** — IDOR and privilege escalation testing
- **Supply Chain Agent** — Dependency vulnerability scanning
- **Business Logic Agent** — Payment manipulation, rate limiting bypass detection
- **Race Condition Agent** — TOCTOU and double-spend vulnerability detection

#### Analysis Engine (Phase 3)
- **CVC Analyzer** — Compound Vulnerability Chain detection using OWASP category adjacency
- **VCVF Matcher** — Vibe Code Vulnerability Fingerprint pattern matching
- **TIEF Detector** — Trust Inversion Exploit Framework boundary analysis

#### Orchestrator (Phase 4)
- 5-phase scan execution: Recon → Agent Swarm → CVC → VCVF → TIEF
- Parallel agent execution with configurable concurrency

#### Report Generator (Phase 5)
- Three audiences: Executive, Developer, Security
- Three formats: JSON, Markdown, HTML
- Proof-of-concept generation for critical/high findings
- Remediation code diff generation

#### UI (Phase 6-7)
- CLI — `scan`, `report`, `config` commands via Commander.js
- Web dashboard — Static HTML with scan results visualization

[Unreleased]: https://github.com/guardiant/guardiant/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/guardiant/guardiant/releases/tag/v0.1.0
