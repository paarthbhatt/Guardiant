# Guardiant

<div align="center">

**Agentic Security Platform for AI-Generated Applications**

[![CI](https://github.com/paarthbhatt/Guardiant/actions/workflows/ci.yml/badge.svg)](https://github.com/paarthbhatt/Guardiant/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.2.0-blue.svg)](https://github.com/paarthbhatt/Guardiant/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)

[Features](#-key-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Architecture](#-architecture)

</div>

---

## 🎯 Overview

Guardiant is an autonomous security testing platform that detects vulnerabilities unique to AI-generated codebases. Using a swarm of 8 specialized security agents powered by LLM reasoning, Guardiant identifies systematic patterns introduced by AI coding assistants that traditional security tools miss.

### Why Guardiant?

AI-generated ("vibe-coded") applications exhibit characteristic vulnerability patterns:

- **Symmetric CRUD Vulnerabilities** - Identical auth checks across all CRUD operations without granular authorization
- **Auth/Authz Conflation** - Authentication checks without proper authorization logic
- **Optimistic Trust Patterns** - Client-side validation with missing server-side enforcement
- **BaaS Bypass Architecture** - Direct database access with exposed service credentials
- **Over-Permissive Defaults** - CORS wildcards, public storage, disabled security policies
- **Missing Negative Cases** - Empty error handlers that silently succeed

Guardiant uses three specialized frameworks to detect these issues:

| Framework | Purpose |
|-----------|---------|
| **VCVF** (Vibe Code Vulnerability Fingerprint) | Identifies AI-generated code patterns |
| **CVC** (Compound Vulnerability Chain) | Links vulnerabilities into exploit chains |
| **TIEF** (Trust Inversion Exploit Framework) | Detects architectural misconfigurations |

---

## 🚀 Key Features

### Security Agent Swarm

8 specialized agents running in parallel with intelligent orchestration:

| Agent | Focus | OWASP Coverage |
|-------|-------|----------------|
| **Recon** | Discovery, enumeration, tech stack detection | A05 |
| **BaaS** | Supabase/Firebase/Appwrite security | A01, A05 |
| **Secrets** | API keys, tokens, credential exposure | A07 |
| **Auth** | IDOR, privilege escalation, session management | A01 |
| **Injection** | SQLi, XSS, command injection, path traversal | A03 |
| **Supply Chain** | Dependency vulnerabilities, package risks | A06, A08 |
| **Business Logic** | Payment manipulation, rate limiting bypass | A04 |
| **Race Condition** | TOCTOU, double-spend vulnerabilities | A04 |

### Advanced Analysis

- **Compound Vulnerability Chains** - Automatically links related findings into multi-step exploit scenarios
- **AI Pattern Detection** - Recognizes 9 distinct VCVF patterns unique to AI-generated code
- **Trust Boundary Analysis** - Identifies architectural flaws in client-server trust models
- **Intelligent Prioritization** - Risk scoring based on exploitability and impact

### Multi-Provider LLM Support

- **Anthropic Claude 3.5 Sonnet** (Primary) - Superior security reasoning
- **OpenRouter** (Fallback) - Multi-model aggregation
- **Google Gemini 1.5 Pro** (Fallback) - High-speed analysis

### Flexible Reporting

Three specialized report formats for different audiences:

- **Executive Reports** - Risk summaries, business impact, compliance status
- **Developer Reports** - Technical details, code examples, remediation steps
- **Security Reports** - Proof-of-concept exploits, CVSS scores, chained attacks

Output formats: JSON, Markdown, HTML

### Local-First Architecture

- **SQLite Database** - No external database required
- **In-Memory Queue** - Instant job processing with optional Redis upgrade
- **Offline Capable** - Core functionality works without internet (after LLM API calls)

---

## 📦 Installation

### Prerequisites

- **Node.js** ≥ 20.0.0
- **pnpm** ≥ 9.0.0
- At least one LLM API key (Anthropic/OpenRouter/Google)

### From Source

```bash
# Clone the repository
git clone https://github.com/paarthbhatt/Guardiant.git
cd Guardiant

# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests (optional)
pnpm test
```

### Using Docker

```bash
# Pull the latest image
docker pull ghcr.io/paarthbhatt/guardiant:main

# Run a scan
docker run -e ANTHROPIC_API_KEY=your_key \
  ghcr.io/paarthbhatt/guardiant:main \
  guardiant scan https://myapp.com
```

---

## 🏃 Quick Start

### 1. Configure LLM Provider

```bash
# Set your API key (at least one required)
export ANTHROPIC_API_KEY="sk-ant-..."
# or
export OPENROUTER_API_KEY="sk-or-..."
# or
export GOOGLE_API_KEY="..."
```

### 2. Run Your First Scan

```bash
# Scan a web application
pnpm cli scan https://myapp.com

# Scan a specific directory
pnpm cli scan ./my-project --type directory

# Scan with specific agents only
pnpm cli scan https://myapp.com --agents baas,auth,injection
```

### 3. View Results

```bash
# List all scans
pnpm cli report list

# View latest scan report
pnpm cli report <scan-id>

# Export to different formats
pnpm cli report <scan-id> --format html --output report.html
pnpm cli report <scan-id> --format json --audience security
```

### 4. Configure Settings

```bash
# Store your API key permanently
pnpm cli config set anthropicApiKey sk-ant-...

# Set default report format
pnpm cli config set defaultFormat markdown
pnpm cli config set defaultAudience developer

# View all configuration
pnpm cli config list
```

---

## 🏗️ Architecture

### System Overview

```
┌─────────────────────────────────────────────┐
│            User Interfaces                  │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐ │
│  │   CLI    │  │   Web    │  │  VS Code  │ │
│  │  (Ink)   │  │Dashboard │  │ Extension │ │
│  └──────────┘  └──────────┘  └───────────┘ │
└─────────────────┬───────────────────────────┘
                  │
          ┌───────▼────────┐
          │  Orchestrator  │  ← Parallel Agent Coordination
          └───────┬────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
┌───▼───┐    ┌────▼────┐   ┌───▼────┐
│ Recon │    │ 7 More  │   │Analysis│
│ Agent │    │ Agents  │   │Engines │
│       │    │ (Swarm) │   │CVC/VCVF│
└───────┘    └─────────┘   └────┬───┘
                                │
                        ┌───────▼────────┐
                        │Report Generator│
                        │ 3 Formats x    │
                        │ 3 Audiences    │
                        └────────────────┘
```

### Technology Stack

| Layer | Technologies |
|-------|-------------|
| **Runtime** | Node.js 20+, TypeScript 5.7 |
| **Build** | Turborepo, pnpm workspaces |
| **Database** | SQLite, Drizzle ORM |
| **Queue** | In-memory (BullMQ optional) |
| **CLI** | Commander.js, Ink (React for CLI) |
| **HTTP** | axios with retry logic |
| **Testing** | Vitest, integration tests |
| **CI/CD** | GitHub Actions |

### Project Structure

```
guardiant/
├── apps/
│   ├── cli/           # Command-line interface
│   │   └── src/
│   │       ├── commands/     # scan, report, config, version
│   │       └── validation/   # Zod schemas
│   └── web/           # Static web dashboard
│
├── packages/
│   ├── core/          # Core security engine
│   │   └── src/
│   │       ├── agents/       # 8 security agents
│   │       ├── analyzers/    # CVC, VCVF, TIEF
│   │       ├── orchestrator/ # Parallel execution
│   │       ├── report/       # Report generation
│   │       ├── http/         # HTTP client + payloads
│   │       ├── llm/          # Multi-provider LLM
│   │       └── scanner/      # Web scanner
│   │
│   ├── database/      # SQLite + Drizzle ORM
│   ├── queue/         # Job queue system
│   └── shared/        # Types, constants, utilities
│
├── docs/              # Documentation
└── .github/           # CI/CD workflows
```

---

## 📚 Documentation

### User Guides

- [Configuration Guide](docs/configuration.md) - Environment setup, LLM providers, advanced options
- [CLI Reference](docs/cli-reference.md) - Complete command documentation
- [Report Guide](docs/reports.md) - Understanding scan results

### Developer Docs

- [Architecture Overview](docs/architecture.md) - System design and component interaction
- [Agent Development](docs/agents/README.md) - Creating custom security agents
- [Contributing Guide](CONTRIBUTING.md) - Development setup, code style, PR process

### Agent Documentation

- [Recon Agent](docs/agents/recon.md) - Endpoint discovery and tech stack detection
- [BaaS Agent](docs/agents/baas.md) - Backend-as-a-Service security testing
- [Injection Agent](docs/agents/injection.md) - SQL, XSS, command injection testing
- [Secrets Agent](docs/agents/secrets.md) - Credential and key exposure detection
- [Auth Agent](docs/agents/auth.md) - Authentication and authorization testing
- [Supply Chain Agent](docs/agents/supply-chain.md) - Dependency vulnerability scanning
- [Business Logic Agent](docs/agents/business-logic.md) - Logic flaw detection
- [Race Condition Agent](docs/agents/race-condition.md) - Concurrency issue detection

---

## 🔧 Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | Recommended | - | Claude API key (best accuracy) |
| `OPENROUTER_API_KEY` | Optional | - | OpenRouter API key (fallback) |
| `GOOGLE_API_KEY` | Optional | - | Gemini API key (fallback) |
| `DATABASE_PATH` | Optional | `~/.guardiant/guardiant.db` | SQLite database location |
| `LOG_LEVEL` | Optional | `info` | Logging level: error, warn, info, debug |
| `REDIS_URL` | Optional | - | Redis URL for production queue |
| `MAX_CONCURRENCY` | Optional | `4` | Maximum parallel agents (1-10) |
| `TIMEOUT` | Optional | `600000` | Scan timeout in milliseconds |

### CLI Configuration

```bash
# Persistent configuration storage
guardiant config set <key> <value>

# Available keys:
#   anthropicApiKey, openrouterApiKey, geminiApiKey
#   defaultFormat (json|markdown|html)
#   defaultAudience (executive|developer|security)
#   maxConcurrency (1-10)
#   timeout (milliseconds)

# View configuration
guardiant config list

# Reset to defaults
guardiant config reset
```

---

## 🧪 Development

### Running Tests

```bash
# Run all tests
pnpm test

# Run specific package tests
pnpm --filter @guardiant/core test
pnpm --filter @guardiant/cli test

# Run with coverage
pnpm test:coverage

# Watch mode
pnpm test:watch
```

### Local Development

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Watch mode for development
pnpm dev

# Run CLI in development
pnpm cli scan https://example.com

# Type checking
pnpm typecheck

# Linting (if configured)
pnpm lint
```

### Testing Against Your App

```bash
# Test a local development server
pnpm cli scan http://localhost:3000

# Test a directory
pnpm cli scan ./path/to/project --type directory

# Test with specific agents only
pnpm cli scan https://myapp.com --agents baas,injection,auth

# Generate detailed report
pnpm cli report <scan-id> --format html --audience security
```

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Quick Contribution Steps

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes and add tests
4. Run tests: `pnpm test`
5. Commit with conventional commits: `git commit -m "feat: add new feature"`
6. Push and create a Pull Request

### Development Setup

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/Guardiant.git
cd Guardiant

# Install dependencies
pnpm install

# Create feature branch
git checkout -b feature/my-feature

# Make changes and test
pnpm build
pnpm test

# Commit with conventional commits
git commit -m "feat: your feature"
git push origin feature/my-feature
```

---

## 📈 Roadmap

### Current Version: v0.2.0 ✅

- ✅ 8 security agents with parallel execution
- ✅ VCVF, CVC, TIEF analysis frameworks
- ✅ Multi-provider LLM support
- ✅ CLI with comprehensive commands
- ✅ Three-tier reporting system
- ✅ Complete test suite (102+ tests)
- ✅ CI/CD pipeline

### Upcoming Features

- 🔄 **v0.3.0** - Enhanced BaaS Coverage
  - Appwrite security testing
  - AWS Amplify detection
  - Expanded Firebase rule testing

- 🔄 **v0.4.0** - Advanced Analysis
  - Machine learning pattern detection
  - Historical vulnerability tracking
  - Automated fix suggestions

- 🔄 **v0.5.0** - Integration & Automation
  - VS Code extension
  - GitHub Actions integration
  - Continuous security monitoring

- 🔄 **v1.0.0** - Production Ready
  - SaaS offering
  - Team collaboration features
  - Compliance reporting (SOC 2, GDPR)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Anthropic** - Claude 3.5 Sonnet for superior security reasoning
- **OWASP** - Security categorization and best practices
- **Turborepo** - Monorepo build system
- **Drizzle ORM** - Type-safe database access
- **Vitest** - Lightning-fast testing framework

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/paarthbhatt/Guardiant/issues)
- **Discussions**: [GitHub Discussions](https://github.com/paarthbhatt/Guardiant/discussions)
- **Documentation**: [docs/](docs/)

---

## ⚡ Quick Links

- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Architecture](#-architecture)
- [Documentation](#-documentation)
- [Contributing](#-contributing)
- [License](#-license)

---

<div align="center">

**Made with ❤️ by the Guardiant Team**

[⭐ Star us on GitHub](https://github.com/paarthbhatt/Guardiant) • [🐛 Report a Bug](https://github.com/paarthbhatt/Guardiant/issues) • [💡 Request a Feature](https://github.com/paarthbhatt/Guardiant/issues)

</div>
