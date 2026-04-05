**THE WORLD'S FIRST SECURITY SCANNER DESIGNED SPECIFICALLY FOR AI-GENERATED CODE**


░██████╗░██╗░░░██╗░█████╗░██████╗░██████╗░██╗░█████╗░███╗░░██╗████████╗
██╔════╝░██║░░░██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗░██║╚══██╔══╝
██║░░██╗░██║░░░██║███████║██████╔╝██║░░██║██║███████║██╔██╗██║░░░██║░░░
██║░░╚██╗██║░░░██║██╔══██║██╔══██╗██║░░██║██║██╔══██║██║╚████║░░░██║░░░
╚██████╔╝╚██████╔╝██║░░██║██║░░██║██████╔╝██║██║░░██║██║░╚███║░░░██║░░░
░╚═════╝░░╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═════╝░╚═╝╚═╝░░╚═╝╚═╝░░╚══╝░░░╚═╝░░░

[![CI](https://img.shields.io/github/actions/workflow/status/paarthbhatt/Guardiant/ci.yml?branch=main)](https://github.com/paarthbhatt/Guardiant/actions)
[![Version](https://img.shields.io/badge/version-0.2.0-blue)](https://github.com/paarthbhatt/Guardiant/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](https://opensource.org/licenses/MIT)
[![Node](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue)](https://www.typescriptlang.org/)

**🚀 Quick Start · 📖 Documentation · 🐛 Report Bug · 💡 Request Feature**

</div>

---

## ⚠️  **CRITICAL: Read This First!**

### **What Makes Guardiant Different**

Guardiant is **NOT** another generic security scanner. It's the **first and only** tool that detects vulnerabilities **unique to AI-generated code** from Cursor, GitHub Copilot, v0.dev, and Claude Code.

Traditional scanners find CVEs (library vulnerabilities). Guardiant finds **systematic patterns** that AI coding assistants introduce:

| AI-Generated Vulnerability | Traditional Scanner? | Guardiant? |
|--------------------------|---------------------|------------|
| Symmetric CRUD (IDOR) | ❌ No | ✅ YES |
| Missing RLS Policies | ❌ No | ✅ YES |
| Client-Side Authority | ❌ No | ✅ YES |
| Auth Bypass Chains | ❌ No | ✅ YES |
| Over-Permissive Defaults | ❌ No | ✅ YES |

**Research-Backed:** Built on original VCVF/CVC/TIEF frameworks - publishable research capable of discovering zero-day vulnerability classes.

---

## 📋 **Table of Contents**

- [🚀 Quick Start (3 Minutes)](#-quick-start-3-minutes)
- [💻 OS-Specific Installation](#-os-specific-installation)
  - [Windows](#windows-⚠️-critical)
  - [macOS](#macos)
  - [Linux](#linux)
  - [Docker (All Platforms)](#docker-all-platforms)
- [🔧 Detailed Configuration](#-detailed-configuration)
- [🚨 Troubleshooting](#-troubleshooting)
- [📖 Full CLI Reference](#-full-cli-reference)
- [🎯 Example Scans](#-example-scans)
- [🔬 Understanding Results](#-understanding-results)
- [📚 Documentation](#-documentation)

---

## 🚀 **Quick Start (3 Minutes)**

### **1. Prerequisites Check**

```bash
# Check Node.js version (need ≥ 20.0.0)
node --version

# If not installed, download: https://nodejs.org/
```

### **2. Install Guardiant**

```bash
# Clone repository
git clone https://github.com/paarthbhatt/Guardiant.git
cd Guardiant

# Install dependencies (⚠️ see OS-specific section below for Windows!)
pnpm install

# Build the project
pnpm build
```

### **3. Configure API Key**

```bash
# Option A: Set environment variable (recommended)
export ANTHROPIC_API_KEY="sk-ant-..."  # or OPENROUTER_API_KEY, GOOGLE_API_KEY

# Option B: Use .env file
cp .env.example .env
# Edit .env and add your API key
```

### **4. Run Your First Scan**

```bash
# Scan a website
pnpm cli scan https://example.com

# Scan a local directory
pnpm cli scan ./my-app --type directory

# See all options
pnpm cli scan --help
```

**That's it!** 🎉

---

## 💻 **OS-Specific Installation**

### **Windows ⚠️ CRITICAL**

Windows requires **Visual Studio Build Tools** for native SQLite compilation. There are **two options**:

#### **Option A: Install Visual Studio Build Tools** (Recommended for Development)

**Step 1:** Download and install Visual Studio Build Tools
- URL: https://visualstudio.microsoft.com/visual-cpp-build-tools/
- During installation, select **"Desktop development with C++"** workload
- Installation size: ~2GB, time: 15-30 minutes

**Step 2:** Verify installation
```powershell
# Open new PowerShell/Command Prompt
where cl
# Should show: C:\Program Files (x86)\Microsoft Visual Studio\... \bin\Hostx64\x64\cl.exe
```

**Step 3:** Install Guardiant
```powershell
cd C:\path\to\Guardiant
pnpm install
pnpm build
```

#### **Option B: Use WSL2 (Windows Subsystem for Linux)** (Easier)

WSL2 provides a native Linux environment on Windows without compilation issues.

**Step 1:** Install WSL2 (if not already installed)
```powershell
# Run in PowerShell as Administrator
wsl --install
# Restart when prompted
```

**Step 2:** Update WSL to WSL2
```powershell
wsl --set-default-version 2
```

**Step 3:** Open Linux terminal (Ubuntu by default)
```bash
# Navigate to your project (adjust path)
cd /mnt/c/Users/Parth/OneDrive/Desktop/test/Guardiant

# Install and build (no issues!)
pnpm install
pnpm build
```

**WSL2 Advantages:**
- ✅ No Visual Studio required
- ✅ Full Linux compatibility
- ✅ Faster installation
- ✅ Production-like environment

#### **Option C: Run Without Database** (Limited Functionality)

If you cannot install build tools or WSL2, Guardiant will still **run scans** but **without persistence**:

```bash
pnpm install --no-optional  # Skips better-sqlite3
# OR
# Let pnpm install fail on better-sqlite3 but continue

pnpm build  # Will build successfully

# Run scan (will show warning but still works)
pnpm cli scan https://example.com
# ⚠️  Database unavailable - scan will proceed without persistence
```

**Limitations:**
- ❌ Cannot save scan history
- ❌ Cannot generate reports from previous scans
- ❌ Cannot query database for results
- ✅ Live scanning and output **still works**

---

### **macOS**

macOS typically has all required tools pre-installed or easily available.

#### **Prerequisites**

```bash
# Install Xcode Command Line Tools (if not already)
xcode-select --install

# Verify: should show Apple clang version
clang --version
```

#### **Installation**

```bash
# Clone and setup
git clone https://github.com/paarthbhatt/Guardiant.git
cd Guardiant

# Install dependencies
pnpm install

# Build
pnpm build

# Test
pnpm cli scan --help
```

**No special steps needed!** 🎉

---

### **Linux**

Linux distributions typically have build tools pre-installed.

#### **Ubuntu/Debian**

```bash
# Install build tools (if not already)
sudo apt-get update
sudo apt-get install -y build-essential python3

# Clone and setup
git clone https://github.com/paarthbhatt/Guardiant.git
cd Guardiant

# Install dependencies
pnpm install

# Build
pnpm build
```

#### **Fedora/RHEL/CentOS**

```bash
# Install build tools
sudo dnf groupinstall "Development Tools"
sudo dnf install python3

# Then follow same steps as Ubuntu
```

---

### **Docker (All Platforms)**

Docker bypasses all OS-specific issues. **Recommended for production use.**

```bash
# Pull Docker image
docker pull ghcr.io/paarthbhatt/guardiant:main

# Run scan (mount local directory for context)
docker run --rm \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -v $(pwd):/workspace \
  ghcr.io/paarthbhatt/guardiant:main \
  guardiant scan https://example.com

# Or build locally
docker build -t guardiant .
docker run --rm -e ANTHROPIC_API_KEY=your_key guardiant scan https://example.com
```

---

## 🔧 **Detailed Configuration**

### **LLM Providers (Choose One)**

Guardiant requires **at least one** LLM API key. We recommend Anthropic Claude for best results.

| Provider | API Key URL | Cost | Quality | Rate Limits |
|----------|-------------|------|---------|-------------|
| **Anthropic** | https://console.anthropic.com | ~$0.03/scan | ⭐⭐⭐⭐⭐ | 10K req/day |
| **OpenRouter** | https://openrouter.ai | Variable | ⭐⭐⭐⭐ | Varies |
| **Google** | https://aistudio.google.com | ~$0.015/scan | ⭐⭐⭐⭐ | 60 req/min |

#### **Configure API Key**

**Method 1: Environment Variable** (Recommended)
```bash
# Linux/macOS
export ANTHROPIC_API_KEY="sk-ant-..."

# Windows PowerShell
$env:ANTHROPIC_API_KEY="sk-ant-..."

# Windows Command Prompt
set ANTHROPIC_API_KEY=sk-ant-...
```

**Method 2: .env File** (Persistent)
```bash
# Create .env file in project root
cp .env.example .env
# Edit .env and add:
ANTHROPIC_API_KEY=sk-ant-...
```

**Method 3: CLI Config** (Built-in)
```bash
pnpm cli config set anthropicApiKey sk-ant-...
```

### **Database Configuration**

Guardiant uses SQLite by default. No configuration needed!

**Custom database location:**
```bash
export DATABASE_PATH="/custom/path/guardiant.db"
# or
pnpm cli config set databasePath /custom/path/guardiant.db
```

### **Performance Tuning**

```bash
# Parallel agent execution (default: 4)
export MAX_CONCURRENCY=8  # Increase for faster scans (requires more LLM tokens)

# Scan timeout (default: 10 minutes)
export TIMEOUT=1800000  # 30 minutes

# Logging verbosity
export LOG_LEVEL=debug  # Options: error, warn, info, debug
```

---

## 🚨 **Troubleshooting**

### **"better-sqlite3" Installation Fails (Windows)**

**Error:** `gyp ERR! find VS` or `Could not locate the bindings file`

**Solution:**

1. **Install Visual Studio Build Tools** (see Windows section above)
   OR
2. **Use WSL2** (recommended, see Windows section)
   OR
3. **Skip optional dependencies** (limited functionality):
   ```bash
   pnpm install --no-optional
   # Scan will work but without database persistence
   ```

### **"PostHog not initialized" Warnings**

**Cause:** `POSTHOG_API_KEY` not set (optional)

**Solution:** Ignore or set the key:
```bash
export POSTHOG_API_KEY=phc_your_key_here  # Get from https://app.posthog.com
```

### **"No LLM provider configured" Error**

**Cause:** No API key set for any LLM provider

**Solution:** Set at least one API key (see Configuration section)

### **TypeScript Errors During Build**

**Cause:** Node.js version mismatch or missing dependencies

**Solution:**
```bash
# Clear cache and reinstall
rm -rf node_modules pnpm-lock.yaml
pnpm install
pnpm build
```

**Note:** Requires Node.js ≥ 20.0.0

### **Authentication Errors with LLM APIs**

**Cause:** Invalid or expired API key

**Solution:**
1. Verify API key at provider's website
2. Check API key has sufficient credits
3. Check rate limits haven't been exceeded
4. Regenerate key if compromised

### **Database Locked / Permission Errors**

**Cause:** Another process holding database lock or insufficient permissions

**Solution:**
```bash
# Ensure no other Guardiant instance is running
# Check for lock file
rm -f guardiant.db-shm guardiant.db-wal

# Or use different database path
export DATABASE_PATH="/tmp/guardiant-$(date +%s).db"
```

---

## 📖 **Full CLI Reference**

```
╔═══════════════════════════════════════════════════════════════╗
║                     GUARDIANT CLI v0.2.0                     ║
╚═══════════════════════════════════════════════════════════════╝

Usage: guardiant <command> [options]

Commands:
  scan <target>              Run security scan on target
  report <scan-id>           Generate/view scan report
  config                     Manage configuration
  version                    Show version information

Global Options:
  --verbose, -v              Enable debug logging
  --help, -h                 Show help for command
  --version, -V              Show version

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SCAN COMMAND
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Usage: guardiant scan <target> [options]

Arguments:
  <target>                   URL, directory path, or repository

Options:
  -t, --type <type>          Scan type: url | directory | repository
                            Default: url

  -a, --agents <agents>      Comma-separated agents (default: all)
                            Available: recon, baas, secrets, auth,
                                      injection, supply_chain,
                                      business_logic, race_condition

  --skip-recon               Skip reconnaissance phase
                            Default: false

  --skip-analysis            Skip CVC/VCVF/TIEF analysis
                            Default: false

  --max-concurrency <n>      Maximum parallel agents (1-10)
                            Default: 4

  --timeout <ms>             Scan timeout in milliseconds
                            Default: 600000 (10 minutes)

  --stop-on-critical         Stop scan immediately on critical finding
                            Default: false

  -o, --output <path>        Write report to file (JSON/Markdown/HTML)
                            Default: stdout

  -f, --format <format>      Report format: json | markdown | html
                            Default: markdown

  -h, --help                 Show this help message

Examples:
  guardiant scan https://myapp.com
  guardiant scan ./project --type directory --agents auth,injection
  guardiant scan https://test.com --format html --output report.html
  guardiant scan https://app.com --skip-recon --max-concurrency 8

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

REPORT COMMAND
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Usage: guardiant report <scan-id> [options]

Arguments:
  <scan-id>                 ID of scan to generate report for
                          (from previous scan output)

Options:
  -f, --format <format>     Output format: json | markdown | html
                            Default: markdown

  -a, --audience <audience> Report audience: executive | developer | security
                            Default: developer

  -o, --output <path>       Write report to file
                            Default: stdout

  --findings-only           Show only findings without full report
                            Default: false

  -h, --help                Show this help message

Examples:
  guardiant report scan-1234567890
  guardiant report scan-123 --format html --output report.html
  guardiant report scan-123 --audience security --findings-only

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CONFIG COMMAND
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Usage: guardiant config <action> [key] [value]

Actions:
  set <key> <value>         Set configuration value
  get <key>                Get configuration value
  unset <key>              Remove configuration value
  list                     Show all configuration
  reset                    Reset to defaults

Configuration Keys:
  anthropicApiKey          Anthropic API key
  openrouterApiKey         OpenRouter API key
  geminiApiKey             Google Gemini API key
  defaultFormat            Default report format (json|markdown|html)
  defaultAudience          Default report audience (executive|developer|security)
  maxConcurrency           Max parallel agents (1-10)
  timeout                  Default timeout (milliseconds)
  databasePath             SQLite database location
  logLevel                 Logging level (error|warn|info|debug)

Examples:
  guardiant config set anthropicApiKey sk-ant-...
  guardiant config get defaultFormat
  guardiant config list
  guardiant config reset

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VERSION COMMAND
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Usage: guardiant version [options]

Options:
  --full, -f              Show full version info (including dependencies)
  --json                  Output as JSON
  -h, --help              Show this help message

Examples:
  guardiant version
  guardiant version --full
  guardiant version --json
```

---

## 🎯 **Example Scans**

### **Scan a Production Web App**

```bash
guardiant scan https://myapp.com \
  --agents auth,injection,baas \
  --max-concurrency 4 \
  --timeout 600000 \
  --format html \
  --output security-report.html
```

### **Scan Local Development Server**

```bash
guardiant scan http://localhost:3000 \
  --type url \
  --agents all \
  --stop-on-critical
```

### **Deep Scan of Codebase**

```bash
guardiant scan ./my-project \
  --type directory \
  --agents recon,auth,business_logic,race_condition \
  --max-concurrency 8 \
  --format markdown \
  --output detailed-report.md
```

### **Quick Reconnaissance**

```bash
guardiant scan https://target.com \
  --agents recon \
  --skip-analysis \
  --timeout 120000
```

---

## 🔬 **Understanding Results**

### **Exit Codes**

| Code | Meaning |
|------|---------|
| `0`  | ✅ Success - No critical or high vulnerabilities |
| `1`  | ⚠️  High severity vulnerabilities found |
| `2`  | 🚨 Critical vulnerabilities found |
| `3`  | ❌ Scan failed (error) |

**Use in CI/CD:**
```bash
guardiant scan https://myapp.com
if [ $? -eq 0 ]; then
  echo "✅ Security scan passed"
else
  echo "❌ Security scan failed - review findings"
fi
```

### **Findings Severity**

```
CRITICAL   🔴 Immediate action required. Active exploitation likely.
HIGH       🟡 Prioritize within current sprint.
MEDIUM     🔵 Plan remediation in next development cycle.
LOW        🟢 Document, fix when convenient.
INFO       ⚪ Informational, no action needed.
```

### **VCVF Patterns Detected**

Guardiant identifies 9 AI-specific vulnerability patterns:

1. **Symmetric CRUD** - Missing ownership checks in UPDATE/DELETE
2. **Auth Bypass** - Authentication without proper authorization
3. **Client-Side Authority** - Trust misplaced in client code (TIEF)
4. **Missing RLS** - Supabase tables without Row Level Security
5. **Service Key Exposure** - Service role keys in client code
6. **Over-Permissive CORS** - Wildcard CORS headers
7. **Empty Error Handlers** - Silent failures on security checks
8. **Parameter Pollution** - Missing validation on optional parameters
9. **Default Credentials** - Unchanged default passwords/keys

---

## 📚 **Documentation**

- **[Configuration Guide](docs/configuration.md)** - Complete setup instructions
- **[CLI Reference](docs/cli-reference.md)** - Detailed command documentation
- **[Report Guide](docs/reports.md)** - Understanding scan results and output formats
- **[Architecture](docs/architecture.md)** - System design and agent architecture
- **[Agent Development](docs/agents/README.md)** - Create custom security agents
- **[Contributing](CONTRIBUTING.md)** - Development setup and PR guidelines

---

## 🔧 **Development**

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test

# Watch mode (auto-rebuild on changes)
pnpm dev

# Run CLI directly
pnpm cli scan https://example.com

# Type checking
pnpm typecheck

# Linting (if configured)
pnpm lint
```

---

## 🏗️ **Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                     Guardiant Architecture                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐  │
│  │   CLI /     │────▶│ Orchestrator│────▶│  8 Security │  │
│  │   Web API   │     │  (Swarm)    │     │   Agents    │  │
│  └─────────────┘     └─────────────┘     └─────────────┘  │
│         │                   │                     │        │
│         │              ┌────┴────┐                │        │
│         │              │ Analysis│◀───────────────┘        │
│         │              │ Engines │                         │
│         │              │(VCVF/CVC│                         │
│         │              │ /TIEF)  │                         │
│         │              └────┬────┘                         │
│         │                   │                               │
│         └───────────────────┼───────────────────────────────┘
│                               │                             │
│                    ┌──────────▼──────────┐                │
│                    │   SQLite Database    │                │
│                    │  (Scans, Findings,  │                │
│                    │   Reports, History) │                │
│                    └─────────────────────┘                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Key Components:**

- **Orchestrator**: Parallel agent coordination with dependency resolution
- **8 Security Agents**: Specialized scanners for different vulnerability classes
- **VCVF/CVC/TIEF**: Research frameworks for AI-specific patterns
- **LLM Abstraction**: Multi-provider support (Anthropic, OpenRouter, Google)
- **Report Generator**: 3 formats × 3 audiences = 9 output variants
- **Database Layer**: SQLite with Drizzle ORM, optional Redis queue

---

## 🤝 **Contributing**

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### **Quick Start for Contributors**

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/Guardiant.git
cd Guardiant

# Create feature branch
git checkout -b feature/my-feature

# Install and build
pnpm install
pnpm build

# Make changes and test
pnpm test

# Commit with conventional commits
git commit -m "feat: add new security agent"

# Push and open PR
git push origin feature/my-feature
```

---

## 📈 **Roadmap**

### **v0.2.0 (Current) ✅**
- ✅ 8 security agents with parallel execution
- ✅ VCVF, CVC, TIEF analysis frameworks
- ✅ Multi-provider LLM support
- ✅ CLI with comprehensive commands
- ✅ Three-tier reporting system
- ✅ Complete test suite (102+ tests)

### **v0.3.0 (Next) 🔄**
- Enhanced BaaS coverage (Appwrite, AWS Amplify)
- Expanded Firebase security rules testing
- Performance optimizations (caching, incremental scans)

### **v0.4.0 🔄**
- Machine learning pattern detection
- Historical vulnerability tracking
- Automated fix suggestions with AI
- VS Code extension

### **v1.0.0 (Production) 🔄**
- SaaS offering with team collaboration
- Compliance reporting (SOC 2, GDPR)
- Continuous security monitoring
- Enterprise integrations

---

## 📄 **License**

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 **Acknowledgments**

- **Anthropic** - Claude 3.5 Sonnet for superior security reasoning
- **OWASP** - Security categorization and best practices
- **Turborepo** - Monorepo build system
- **Drizzle ORM** - Type-safe database access
- **Vitest** - Lightning-fast testing framework
- **The open-source community** - For inspiration and tools

---

## 📞 **Support**

- **🐛 Bug Reports**: [GitHub Issues](https://github.com/paarthbhatt/Guardiant/issues)
- **💡 Feature Requests**: [GitHub Discussions](https://github.com/paarthbhatt/Guardiant/discussions/categories/ideas)
- **❓ Questions**: [GitHub Discussions](https://github.com/paarthbhatt/Guardiant/discussions)
- **📖 Documentation**: [docs/](docs/)
- **📧 Email**: security@guardiant.dev (private security reports only)

---

## ⚡ **Quick Links**

| Resource | Link |
|----------|------|
| Installation Guide | [Readme](#-installation) |
| CLI Documentation | [docs/cli-reference.md](docs/cli-reference.md) |
| Agent Documentation | [docs/agents/](docs/agents/) |
| Configuration | [docs/configuration.md](docs/configuration.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Research Paper (VCVF) | [docs/ZERO_DAY_POTENTIAL.md](docs/ZERO_DAY_POTENTIAL.md) |
| Competitive Analysis | [COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) |
| Marketing Strategy | [MARKETING_PRODUCT_STRATEGY.md](MARKETING_PRODUCT_STRATEGY.md) |

---

<div align="center">

**🛡️ Built for the AI coding revolution**

**⭐ Star us on GitHub** • **🐛 Report bugs** • **💡 Request features**

[![GitHub stars](https://img.shields.io/github/stars/paarthbhatt/Guardiant?style=social)](https://github.com/paarthbhatt/Guardiant/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/paarthbhatt/Guardiant?style=social)](https://github.com/paarthbhatt/Guardiant/network)

**Made with ❤️ by the Guardiant Team**

</div>

---

## 🔒 **Security Policy**

**For security vulnerabilities in Guardiant itself**, please email: **security@guardiant.dev**

Do not open GitHub issues for security vulnerabilities. This is a private disclosure channel.

---

## 📊 **Analytics & Privacy**

Guardiant optionally sends anonymized usage statistics to PostHog to improve the product. No source code or sensitive data is transmitted.

**What we track:**
- ✅ Scan count and duration
- ✅ Agents used
- ✅ Severity distribution
- ✅ Error occurrences
- ❌ **NOT** your source code
- ❌ **NOT** specific vulnerabilities found
- ❌ **NOT** full URLs (sanitized)

**Opt-out:** Simply don't set `POSTHOG_API_KEY` environment variable.

See [.automation/POSTHOG_SETUP.md](.automation/POSTHOG_SETUP.md) for details.

---

**© 2026 Guardiant. MIT License.**
