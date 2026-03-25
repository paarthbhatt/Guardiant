# Guardiant - Agentic Security Platform

**Version 0.1.0 - Phase 5 Complete**

This monorepo contains the Guardiant security platform for detecting vulnerabilities in AI-generated ("vibe-coded") applications.

## Project Structure

```
guardiant/
├── apps/
│   ├── cli/                    # Terminal UI (Command Line Interface)
│   │   ├── src/
│   │   │   ├── commands/        # CLI commands (scan, report, config, version)
│   │   │   └── index.ts         # Entry point
│   │   └── package.json
│   └── web/                     # Web Dashboard
│       └── index.html            # Static HTML dashboard
│
├── packages/
│   ├── core/                   # Core business logic
│   │   ├── src/
│   │   │   ├── agents/          # 8 Security agents
│   │   │   ├── analyzers/       # CVC, VCVF, TIEF analyzers
│   │   │   ├── config/          # Constants and configuration
│   │   │   ├── http/            # HTTP client and payloads
│   │   │   ├── llm/             # Multi-provider LLM client
│   │   │   ├── orchestrator/     # Scan orchestration
│   │   │   ├── payloads/         # Attack payload libraries
│   │   │   ├── report/           # Report generation
│   │   │   └── scanner/          # Web scanner
│   │   └── package.json
│   │
│   ├── database/               # SQLite schema & operations
│   │   ├── src/
│   │   │   ├── schema/          # Drizzle ORM schemas
│   │   │   └── operations/      # CRUD operations
│   │   └── package.json
│   │
│   ├── queue/                   # Job queue system
│   │   ├── src/
│   │   │   ├── jobs/            # Job definitions
│   │   │   └── queues/          # Queue implementations
│   │   └── package.json
│   │
│   └── shared/                 # Shared types & utilities
│       ├── src/
│       │   ├── types/           # TypeScript types
│       │   ├── constants/       # VCVF patterns, OWASP categories
│       │   └── utils/           # Logger, crypto, HTTP client
│       └── package.json
│
└── tools/
    └── payloads/                # Attack payload libraries
```

## Features

- **8 Specialized Security Agents** working in parallel
- **VCVF Detection** - Identifies patterns unique to AI-generated code
- **TIEF Analysis** - Detects trust inversion vulnerabilities
- **Compound Vulnerability Chains** - Links related vulnerabilities into exploit chains
- **BaaS Security** - Specialized detection for Supabase, Firebase, and other BaaS platforms
- **Multi-Format Reports** - JSON, Markdown, and HTML reports

## Installation

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test
```

## Usage

```bash
# Run a security scan
pnpm cli scan https://myapp.com

# View scan report
pnpm cli report <scan-id>

# Configure LLM providers
pnpm cli config set anthropicApiKey sk-ant-...

# Run the web dashboard
pnpm web
```

## Architecture

### Multi-Provider LLM Support
- **Primary**: Anthropic Claude (best for security reasoning)
- **Backup**: OpenRouter (multi-model aggregator)
- **Backup**: Google Gemini

### Security Agents (8 Total)
1. **Recon Agent** - Discovery and reconnaissance, endpoint enumeration
2. **BaaS Agent** - Supabase/Firebase security testing
3. **Secrets Agent** - API key and secrets detection
4. **Auth Agent** - Authentication/authorization testing
5. **Injection Agent** - SQLi, XSS, command injection
6. **Supply Chain Agent** - Dependency vulnerabilities
7. **Business Logic Agent** - Business logic flaws
8. **Race Condition Agent** - TOCTOU vulnerabilities

### Analysis Frameworks
- **CVC (Compound Vulnerability Chain)** - Links related vulnerabilities
- **VCVF (Vibe Code Vulnerability Fingerprint)** - AI-code detection
- **TIEF (Trust Inversion Exploit Framework)** - Architecture analysis

### Report Generation
- **Executive Report** - High-level risk assessment for stakeholders
- **Developer Report** - Technical details with remediation steps
- **Security Report** - Full analysis with PoCs and attack paths

## VCVF Patterns

Guardiant detects patterns common in AI-generated code:
- Symmetric CRUD Vulnerabilities
- Auth/Authz Conflation
- Optimistic Trust Patterns
- BaaS Bypass Architecture
- Over-Permissive Defaults

## Development Status

### Phase 1: Foundation ✅ COMPLETE
- ✅ Monorepo setup with Turborepo
- ✅ Shared types and constants
- ✅ Database schema (SQLite + Drizzle)
- ✅ Queue system (in-memory fallback)
- ✅ LLM client (Anthropic, OpenRouter, Gemini)
- ✅ Base agent interface

### Phase 2: Agent Swarm ✅ COMPLETE
- ✅ Recon Agent (HTTP fetching, bundle analysis, tech detection)
- ✅ Injection Agent (SQLi, XSS, Command Injection, Path Traversal)
- ✅ BaaS Agent (Supabase RLS, Firebase rules, storage permissions)
- ✅ Secrets Agent (API keys, tokens, .env exposure)
- ✅ Auth Agent (IDOR, privilege escalation)
- ✅ Supply Chain Agent (vulnerable dependencies)
- ✅ Business Logic Agent (payment manipulation, rate limiting)
- ✅ Race Condition Agent (TOCTOU, double-spend)

### Phase 3: Analysis Engine ✅ COMPLETE
- ✅ CVC Analyzer (compound vulnerability chains)
- ✅ VCVF Matcher (AI-generated code patterns)
- ✅ TIEF Detector (trust inversion detection)

### Phase 4: Orchestrator ✅ COMPLETE
- ✅ Agent coordination and scheduling
- ✅ Parallel execution
- ✅ Phase-based execution (Recon → Agents → Analysis)

### Phase 5: Report Generator ✅ COMPLETE
- ✅ Executive report template
- ✅ Developer report template
- ✅ Security report template
- ✅ JSON/Markdown/HTML formatters

### Phase 6-7: UI ✅ Mostly Complete
- ✅ CLI commands (scan, report, config)
- ✅ Web dashboard (static HTML)
- ✅ Unit tests for analyzers and report generator

### Phase 8: Polish & Ship ⏳
- ⏳ Integration tests
- ⏳ End-to-end tests

## License

MIT
