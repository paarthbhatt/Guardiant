<div align="center">

```
░██████╗░██╗░░░██╗░█████╗░██████╗░██████╗░██╗░█████╗░███╗░░██╗████████╗
██╔════╝░██║░░░██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗░██║╚══██╔══╝
██║░░██╗░██║░░░██║███████║██████╔╝██║░░██║██║███████║██╔██╗██║░░░██║░░░
██║░░╚██╗██║░░░██║██╔══██║██╔══██╗██║░░██║██║██╔══██║██║╚████║░░░██║░░░
╚██████╔╝╚██████╔╝██║░░██║██║░░██║██████╔╝██║██║░░██║██║░╚███║░░░██║░░░
░╚═════╝░░╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═════╝░╚═╝╚═╝░░╚═╝╚═╝░░╚══╝░░░╚═╝░░░
```

# Guardiant

**The first security scanner built for AI-generated code.**

[![CI](https://img.shields.io/github/actions/workflow/status/paarthbhatt/Guardiant/ci.yml?branch=main)](https://github.com/paarthbhatt/Guardiant/actions)
[![Version](https://img.shields.io/badge/version-0.2.0-blue)](https://github.com/paarthbhatt/Guardiant/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](https://opensource.org/licenses/MIT)
[![Node](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen)](https://nodejs.org)

Guardiant detects vulnerabilities **unique to AI-generated code** — the ones traditional scanners miss.
Built on original research frameworks (VCVF, CVC, TIEF) that find systematic patterns introduced by
Cursor, GitHub Copilot, Claude Code, and v0.dev.

[Quick Start](#quick-start) | [Agent Prompts](#agent-prompt-library) | [Installation](#installation) | [CLI Reference](#cli-reference) | [Architecture](#architecture) | [Contributing](#contributing)

</div>

---

## Why Guardiant

Traditional scanners find CVEs. Guardiant finds **structural flaws** that AI coding assistants introduce at scale.

| Vulnerability Pattern | Snyk / SonarQube | Guardiant |
|---|---|---|
| Symmetric CRUD (IDOR) | No | Yes |
| Missing Row Level Security | No | Yes |
| Client-side authority checks | No | Yes |
| Auth/authz conflation chains | No | Yes |
| Over-permissive defaults | No | Yes |
| BaaS direct database bypass | No | Yes |
| Trust boundary inversions | No | Yes |

Guardiant runs 8 specialized agents in parallel, chains related findings into compound vulnerability reports, and identifies where your app trusts the wrong boundary (client, BaaS SDK, frontend auth logic).

---

## Agent Prompt Library

Copy any prompt below into your coding agent (Cursor, GitHub Copilot, Claude Code, Windsurf, etc.) to install and run Guardiant automatically.

### Scan the current project

```
Clone https://github.com/paarthbhatt/Guardiant into a temporary directory,
install dependencies with pnpm, build the project, then run a full security
scan against the current working directory using:
  pnpm cli scan <current-directory> --type directory
Show me the complete scan results including all findings, severity levels,
and trust inversions.
```

### Scan a URL

```
Clone https://github.com/paarthbhatt/Guardiant, install with pnpm, build it,
then scan https://example.com by running:
  pnpm cli scan https://example.com
Report all findings grouped by severity. Include the trust inversion analysis.
```

### Scan with specific agents

```
Clone https://github.com/paarthbhatt/Guardiant, install with pnpm, build it,
then run a targeted scan against the current project:
  pnpm cli scan <current-directory> --type directory --agents auth,injection,baas,race_condition
Show me the results with remediation steps for each finding.
```

### Generate an HTML report

```
Clone https://github.com/paarthbhatt/Guardiant, install with pnpm, build it,
scan the current directory, and generate an HTML report:
  pnpm cli scan <current-directory> --type directory --format html --output security-report.html
Confirm the report was written successfully.
```

### Quick reconnaissance only

```
Clone https://github.com/paarthbhatt/Guardiant, install with pnpm, build it,
then run just the reconnaissance agent against the current project:
  pnpm cli scan <current-directory> --type directory --agents recon --skip-analysis
List all discovered endpoints, tech stack, and exposed configuration files.
```

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/paarthbhatt/Guardiant.git
cd Guardiant
pnpm install
pnpm build

# 2. Set your LLM API key (pick one)
export ANTHROPIC_API_KEY="sk-ant-..."
# or: export OPENROUTER_API_KEY="..."
# or: export GOOGLE_API_KEY="..."

# 3. Run a scan
pnpm cli scan https://example.com
```

For OS-specific instructions (Windows, macOS, Linux, Docker), see [Installation](#installation).

---

## Installation

### Windows

Windows requires native compilation tools for SQLite. Three options:

**Option A: Visual Studio Build Tools (recommended)**
1. Download from https://visualstudio.microsoft.com/visual-cpp-build-tools/
2. Select "Desktop development with C++" during installation
3. Restart terminal, then:
```powershell
git clone https://github.com/paarthbhatt/Guardiant.git
cd Guardiant
pnpm install
pnpm build
```

**Option B: WSL2 (easiest)**
```powershell
# In PowerShell as Administrator
wsl --install
# Restart, then in the Linux terminal:
git clone https://github.com/paarthbhatt/Guardiant.git
cd Guardiant
pnpm install
pnpm build
```

**Option C: No database (limited)**
```bash
pnpm install --no-optional
pnpm build
# Scans work, but results are not persisted
```

### macOS

```bash
xcode-select --install  # if not already installed
git clone https://github.com/paarthbhatt/Guardiant.git
cd Guardiant
pnpm install
pnpm build
```

### Linux

```bash
sudo apt-get update && sudo apt-get install -y build-essential python3
git clone https://github.com/paarthbhatt/Guardiant.git
cd Guardiant
pnpm install
pnpm build
```

### Docker

```bash
docker pull ghcr.io/paarthbhatt/guardiant:main

docker run --rm \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -v $(pwd):/workspace \
  ghcr.io/paarthbhatt/guardiant:main \
  guardiant scan https://example.com
```

---

## Configuration

### LLM Providers

Guardiant requires at least one LLM API key. Set it via environment variable, `.env` file, or CLI config.

| Provider | Get Key | Cost per Scan | Recommended |
|---|---|---|---|
| Anthropic | https://console.anthropic.com | ~$0.03 | Yes |
| OpenRouter | https://openrouter.ai | Variable | |
| Google AI | https://aistudio.google.com | ~$0.015 | |

```bash
# Environment variable
export ANTHROPIC_API_KEY="sk-ant-..."

# Or .env file
cp .env.example .env
# Edit .env with your key

# Or CLI config
pnpm cli config set anthropicApiKey sk-ant-...
```

### Performance Tuning

| Variable | Default | Description |
|---|---|---|
| `MAX_CONCURRENCY` | 4 | Parallel agent count (1-10) |
| `TIMEOUT` | 600000 | Scan timeout in ms (default: 10 min) |
| `LOG_LEVEL` | info | Logging verbosity: error, warn, info, debug |

---

## CLI Reference

```
guardiant scan <target> [options]

Arguments:
  <target>                    URL, directory path, or repository

Options:
  -t, --type <type>           url | directory | repository (default: url)
  -a, --agents <agents>       Comma-separated: recon, baas, secrets, auth,
                              injection, supply_chain, business_logic,
                              race_condition (default: all)
  --skip-recon                Skip reconnaissance phase
  --skip-analysis             Skip CVC/VCVF/TIEF analysis
  --max-concurrency <n>       Parallel agents: 1-10 (default: 4)
  --timeout <ms>              Timeout in ms (default: 600000)
  --stop-on-critical          Stop on first critical finding
  -f, --format <format>       json | markdown | html (default: markdown)
  -o, --output <path>         Write report to file

Examples:
  guardiant scan https://myapp.com
  guardiant scan ./project --type directory --agents auth,injection
  guardiant scan https://app.com --format html --output report.html
```

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | No critical or high vulnerabilities |
| 1 | High severity vulnerabilities found |
| 2 | Critical vulnerabilities found |
| 3 | Scan failed (error) |

Use in CI/CD pipelines to gate deployments on security findings.

---

## How It Works

Guardiant runs a 5-phase scan:

1. **Recon** — Discovers endpoints, tech stack, auth mechanisms, exposed configs
2. **Agent Swarm** — 8 specialized agents analyze the target in parallel
3. **CVC Analysis** — Chains related findings into compound vulnerability paths
4. **VCVF Matching** — Identifies AI-specific vulnerability patterns
5. **TIEF Detection** — Finds trust boundary inversions (where the app trusts the wrong layer)

### The 8 Agents

| Agent | What It Finds |
|---|---|
| `recon` | Endpoints, tech stack, source maps, exposed configs |
| `auth` | Authentication bypass, session fixation, JWT issues |
| `injection` | SQL injection, XSS, command injection, SSTI |
| `baas` | Supabase/Firebase misconfigs, missing RLS, direct DB access |
| `secrets` | Hardcoded credentials, exposed API keys, tokens in code |
| `supply_chain` | Dependency vulnerabilities, malicious packages |
| `business_logic` | IDOR, price manipulation, auth/authz conflation |
| `race_condition` | TOCTOU bugs, concurrent request abuse |

### VCVF Pattern Detection

Guardiant identifies 9 AI-specific vulnerability patterns:

1. **Symmetric CRUD** — Missing ownership checks in UPDATE/DELETE
2. **Auth Bypass** — Authentication without proper authorization
3. **Client-Side Authority** — Trust misplaced in client code
4. **Missing RLS** — Supabase tables without Row Level Security
5. **Service Key Exposure** — Service role keys in client code
6. **Over-Permissive CORS** — Wildcard CORS headers
7. **Empty Error Handlers** — Silent failures on security checks
8. **Parameter Pollution** — Missing validation on optional parameters
9. **Default Credentials** — Unchanged default passwords/keys

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Guardiant                            │
├─────────────────────────────────────────────────────────┤
│                                                          │
│   CLI / API ──▶ Orchestrator ──▶ 8 Security Agents      │
│                    │                    │                 │
│                    ▼                    ▼                 │
│              ┌──────────┐      ┌──────────────┐          │
│              │ Analysis  │      │  LLM Client  │          │
│              │ CVC/VCVF  │      │  (Multi-     │          │
│              │ /TIEF     │      │   Provider)  │          │
│              └──────────┘      └──────────────┘          │
│                    │                                     │
│                    ▼                                     │
│            SQLite Database                                │
│         (Scans, Findings, Reports)                        │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

**Packages:**
- `@guardiant/core` — Agents, orchestrator, analyzers, HTTP client
- `@guardiant/shared` — Types, utilities, logger, analytics
- `@guardiant/database` — SQLite via Drizzle ORM
- `@guardiant/queue` — In-memory job queue
- `@guardiant/cli` — Command-line interface

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

```bash
git clone https://github.com/YOUR_USERNAME/Guardiant.git
cd Guardiant
git checkout -b feature/my-feature
pnpm install
pnpm build
pnpm test
git commit -m "feat: add new security agent"
git push origin feature/my-feature
```

---

## Roadmap

- **v0.3.0** — Appwrite/Amplify coverage, Firebase rules testing, scan caching
- **v0.4.0** — ML pattern detection, historical tracking, VS Code extension
- **v1.0.0** — Cloud platform, team collaboration, compliance reporting

---

## License

MIT License. See [LICENSE](LICENSE).

---

## Support

- **Bug reports** — [GitHub Issues](https://github.com/paarthbhatt/Guardiant/issues)
- **Feature requests** — [GitHub Discussions](https://github.com/paarthbhatt/Guardiant/discussions/categories/ideas)
- **Questions** — [GitHub Discussions](https://github.com/paarthbhatt/Guardiant/discussions)
- **Security vulnerabilities** — Email security@guardiant.dev (do not open public issues)

---

<div align="center">

**Built for the AI coding revolution.**

[![GitHub stars](https://img.shields.io/github/stars/paarthbhatt/Guardiant?style=social)](https://github.com/paarthbhatt/Guardiant/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/paarthbhatt/Guardiant?style=social)](https://github.com/paarthbhatt/Guardiant/network)

</div>
