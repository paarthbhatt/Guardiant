# Changelog

All notable changes to Guardiant will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.1] - 2026-04-05 (Latest)

### 🎉 Added

- **Windows Compatibility Fix** - CLI now works without Visual Studio Build Tools
  - Made `better-sqlite3` an optional dependency
  - Implemented dynamic import with graceful fallback
  - Scan execution works without database persistence on Windows
  - Clear warning messages when database unavailable
- **Enhanced CLI with ASCII Art** - Beautiful terminal experience
  - Colorful banner on startup
  - Enhanced version command with agent and framework details
  - Better help text with examples
  - JSON output option for version (`--json`)
- **Comprehensive README Rewrite** - 500+ lines of detailed documentation
  - OS-specific installation instructions (Windows/macOS/Linux)
  - WSL2 setup guide for Windows users
  - Docker support for all platforms
  - Extensive troubleshooting section
  - Complete CLI reference with examples
  - VCVF patterns explained in detail
- **PostHog Analytics Integration** - Product insights (opt-in)
  - Track scans, findings, errors
  - Anonymous user identification
  - URL sanitization for privacy
  - Setup guide: `.automation/POSTHOG_SETUP.md`
- **Automated Metrics Collection** - Growth tracking infrastructure
  - GitHub stats (stars, forks, watchers)
  - NPM downloads (daily, weekly, monthly)
  - CSV output for historical analysis
  - Script: `.automation/scripts/collect-metrics.cjs`
- **Marketing Infrastructure** - Complete growth toolkit
  - Blog Post #1: "What is VCVF?" (473 lines, SEO optimized)
  - 10+ pre-written tweets with strategy guide
  - 5-email welcome sequence for ConvertKit
  - 13 KPI monitoring dashboard setup
  - GitHub issue templates

### 🔧 Fixed

- **better-sqlite3 compilation errors on Windows** - now optional
- **TypeScript errors** - fixed unused variable warnings
- **CLI build** - report command updated for async database creation
- **Scan command** - proper error handling for missing database
- **Exit codes** - correctly return 0/1/2 based on severity

### 📚 Documentation

- Complete README.md rewrite with 500+ lines
- Added `.automation/POSTHOG_SETUP.md`
- Updated `.env.example` with PostHog configuration
- Created `IMPLEMENTATION_COMPLETE.md` summary
- `docs/blog/vcvf-framework-ai-code-security.md` (473 lines)

### 🚀 Infrastructure

- `.automation/` directory with complete marketing setup
  - `SETUP_GUIDE.md` - 4-week launch roadmap
  - `IMPLEMENTATION_COMPLETE.md` - Implementation summary
  - `MONITORING_DASHBOARD.md` - KPI tracking strategy
  - `POSTHOG_SETUP.md` - Analytics guide
  - `social-media/TWITTER_CONTENT.md` - 10+ tweets
  - `content/BLOG_POST_1_VCVF.md` - Full blog post
  - `email/EMAIL_STRATEGY.md` - Email marketing plan

---

## [0.2.0] - 2026-03-25

### Added

#### Type Stabilization (Phase 10)
- Complete TypeScript type safety across all packages
- Enhanced VCVF pattern matching with proper glob-to-regex conversion
- Auth/authz conflation detection for session-based authentication
- Risk assessment with 5-level severity system (critical/high/medium/low/info)

#### Testing Infrastructure (Phase 8)
- Comprehensive unit tests for all agents using Vitest
- Integration tests for analysis pipeline (CVC → VCVF → TIEF → Report)
- E2E tests for CLI commands (scan, report, config)
- Test coverage reporting configuration

#### Documentation (Phase 8)
- Complete `README.md` with Phase 7 completion status
- `CONTRIBUTING.md` with development setup, code style, and PR process
- `docs/` folder with overview, architecture, configuration, and agent references

#### CI/CD (Phase 8)
- GitHub Actions CI workflow for build, test, and typecheck
- GitHub Actions release workflow with NPM publishing
- Dependabot configuration for dependency updates

#### NPM Package Preparation (Phase 8)
- Proper `package.json` configuration for all packages
- `publishConfig` for public NPM publishing
- Repository, homepage, and bugs fields
- Proper `exports` field for ESM modules

### Changed

#### Type System Improvements (Phase 10)
- Resolved 230+ TypeScript errors across all packages
- Fixed module resolution in all package tsconfigs (emitDeclarationOnly: false)
- Updated glob pattern matching to properly handle `**/` in file patterns
- CLI tsconfig now excludes test files from compilation
- Added proper TypeScript type for discovered endpoints

#### Test Suite Enhancement (Phase 10)
- Fixed 6 test failures in orchestrator and pipeline integration tests
- Enhanced VCVF pattern matching tests with realistic code samples
- Updated risk assessment tests to handle empty findings correctly
- All 102 tests now passing (shared: 57, queue: 11, core: 34)

#### Previous Changes (Phase 8)
- Updated version from 0.1.0 to 0.2.0
- Improved integration test coverage for scan pipeline
- Enhanced E2E CLI tests with more validation scenarios

### Fixed

#### Phase 10 Type Stabilization
- **Glob pattern matching** — Fixed `**/` regex conversion in VCVFMatcher to properly match nested files
- **Risk assessment** — Added 'info' level to RiskAssessment type union and cascaded to all switch statements
- **Risk score calculation** — Now includes low-severity findings in composite risk score
- **Empty findings handling** — Reports now return 'info' level instead of 'low' when no vulnerabilities found
- **VCVF pattern detection** — Added session-based auth pattern to detect `req.session.userId` checks without authorization
- **TIEF detector tests** — Added missing `vcvfPattern` field to test data
- **CLI build** — Excluded test files from tsconfig compilation to prevent build errors
- **Unused parameters** — Removed unused imports and fixed parameter signatures across CLI and core packages

---

## [0.1.0] - 2026-03-20

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
- CLI — `scan`, `report`, `config`, `version` commands via Commander.js
- Web dashboard — Static HTML with scan results visualization

---

## Unreleased

### Planned
- Web dashboard (Next.js) for real-time scan monitoring
- VS Code extension for in-IDE security scanning
- Additional BaaS platform support (Appwrite, Amplify)
- Custom VCVF rule configuration

[0.2.1]: https://github.com/guardiant/guardiant/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/guardiant/guardiant/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/guardiant/guardiant/releases/tag/v0.1.0
