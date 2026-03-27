# Guardiant - Agentic Security Platform

**Version 0.2.0 - Phase 7 Complete**

An agentic security platform for detecting vulnerabilities in AI-generated ("vibe-coded") applications. Guardiant uses a swarm of 8 specialized security agents powered by LLM reasoning to find unique vulnerability patterns introduced by AI coding assistants.

## Why Guardiant?

AI-generated code has characteristic patterns that introduce systematic vulnerabilities:

| VCVF Pattern | Description |
|---|---|
| **Symmetric CRUD Vulnerabilities** | All CRUD routes share the same auth check with no per-action authz |
| **Auth/Authz Conflation** | Code checks *if* a user is logged in rather than *what* they are allowed to do |
| **Optimistic Trust Patterns** | Client-side validation with no server-side copy |
| **BaaS Bypass Architecture** | Direct Supabase/Firebase client access with exposed service role keys |
| **Over-Permissive Defaults** | CORS wildcards, public storage buckets, disabled RLS |
| **Missing Negative Cases** | Empty error handlers that silently succeed |

Guardiant detects these patterns using the **VCVF (Vibe Code Vulnerability Fingerprint)** framework, chains vulnerabilities together using **CVC (Compound Vulnerability Chain)** analysis, and identifies architectural misconfigurations via **TIEF (Trust Inversion Exploit Framework)**.

## Features

- **8 Specialized Security Agents** running in parallel
- **VCVF Detection** - Identifies patterns unique to AI-generated code
- **TIEF Analysis** - Detects trust inversion vulnerabilities
- **Compound Vulnerability Chains** - Links related vulnerabilities into exploit chains
- **BaaS Security** - Specialized detection for Supabase, Firebase, Appwrite
- **Multi-Provider LLM** - Anthropic Claude (primary), OpenRouter, Google Gemini
- **Three-Tier Reports** - Executive, Developer, Security formats
- **Local-First** - SQLite database, in-memory queue fallback, no external dependencies required

## Installation

```bash
# Clone the repository
git clone https://github.com/guardiant/guardiant.git
cd guardiant

# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test
```

## Quick Start

```bash
# Set up LLM provider (at least one required)
cp .env.example .env
# Edit .env and add your API key

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

```
┌─────────────────────────────────────────────────────────────┐
│                     Guardiant Platform                        │
├─────────────────────────────────────────────────────────────┤
│  CLI (Ink)     │  Web Dashboard   │  VS Code Extension     │
│  pnpm cli      │  pnpm web         │  (Planned)             │
└─────────────────────────────────────────────────────────────┘
                              │
                    ┌────────▼────────┐
                    │   Orchestrator   │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
    ┌────▼────┐        ┌─────▼─────┐       ┌─────▼─────┐
    │  Recon  │        │  Agents   │       │ Analyzers │
    │  Agent  │        │  (Swarm)  │       │ CVC/VCVF/ │
    │ (First) │        │  (7 more) │       │   TIEF    │
    └─────────┘        └───────────┘       └───────────┘
                             │
                    ┌────────▼────────┐
                    │ Report Generator │
                    │ Exec/Dev/Security│
                    └─────────────────┘
```

### Security Agents (8 Total)

| Agent | Priority | OWASP Coverage | Purpose |
|-------|----------|----------------|---------|
| **Recon** | First | A05 | Discovery, endpoint enumeration, tech stack |
| **BaaS** | Critical | A01, A05 | Supabase/Firebase security testing |
| **Secrets** | High | A07 | API key and secrets detection |
| **Auth** | High | A01 | IDOR, privilege escalation, session issues |
| **Injection** | High | A03 | SQLi, XSS, command injection, path traversal |
| **Supply Chain** | Medium | A06, A08 | Dependency vulnerabilities, hallucinated packages |
| **Business Logic** | Medium | A04 | Payment manipulation, rate limiting bypass |
| **Race Condition** | Low | A04 | TOCTOU, double-spend vulnerabilities |

### Analysis Frameworks

| Framework | Purpose |
|-----------|---------|
| **CVC (Compound Vulnerability Chain)** | Links related vulnerabilities into multi-step exploit chains |
| **VCVF (Vibe Code Vulnerability Fingerprint)** | Detects AI-generated code patterns |
| **TIEF (Trust Inversion Exploit Framework)** | Identifies architectural misconfigurations |

### Multi-Provider LLM Support

| Provider | Model | Role |
|----------|-------|------|
| **Anthropic** | Claude 3.5 Sonnet | Primary (best security reasoning) |
| **OpenRouter** | Multi-model aggregator | Backup |
| **Google** | Gemini 1.5 Pro | Backup |

## Project Structure

```
guardiant/
├── apps/
│   ├── cli/                    # Terminal UI (Commander + Ink)
│   │   ├── src/
│   │   │   ├── commands/        # CLI commands (scan, report, config, version)
│   │   │   └── index.ts         # Entry point
│   │   └── package.json
│   │
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
│   │   │   └── queues/          # In-memory & BullMQ implementations
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

### Phase 6-7: UI ✅ COMPLETE
- ✅ CLI commands (scan, report, config, version)
- ✅ Web dashboard (static HTML)
- ✅ CLI unit tests
- ✅ Integration tests foundation

### Phase 8: Polish & Ship ✅ COMPLETE
- ✅ Comprehensive test suite
- ✅ CI/CD GitHub Actions
- ✅ Documentation (README, CONTRIBUTING, API docs)
- ✅ NPM package configuration

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Recommended | Claude API key (primary provider) |
| `OPENROUTER_API_KEY` | Optional | OpenRouter API key (backup) |
| `GOOGLE_API_KEY` | Optional | Gemini API key (backup) |
| `DATABASE_PATH` | Optional | SQLite path (default: `~/.guardiant/guardiant.db`) |
| `LOG_LEVEL` | Optional | Log level: `error`, `warn`, `info`, `debug` |
| `REDIS_URL` | Optional | Redis URL for production queue |

See [docs/configuration.md](docs/configuration.md) for full configuration options.

## Documentation

- [Overview](docs/overview.md) - Platform introduction
- [Architecture](docs/architecture.md) - Technical architecture
- [Configuration](docs/configuration.md) - Configuration guide
- [Agents](docs/agents/) - Agent-specific documentation
  - [Recon Agent](docs/agents/recon.md)
  - [BaaS Agent](docs/agents/baas.md)
  - [Injection Agent](docs/agents/injection.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and PR process.

## Security

See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting.

## License

MIT

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.