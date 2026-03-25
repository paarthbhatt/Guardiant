# Guardiant — Architecture

## Monorepo Structure

```
guardiant/
├── apps/
│   ├── cli/            @guardiant/cli      — Commander-based CLI (scan, report, config)
│   └── web/            @guardiant/web      — Static HTML dashboard
│
├── packages/
│   ├── core/           @guardiant/core     — Agents, analyzers, orchestrator, LLM, report
│   ├── shared/         @guardiant/shared   — Types, constants, crypto/format/logger utils
│   ├── database/       @guardiant/database — Drizzle ORM + SQLite schema
│   └── queue/          @guardiant/queue    — In-memory & BullMQ/Redis job queues
│
└── tools/payloads/     — Attack payload libraries
```

## Dependency Graph

```
cli → core → shared
cli → database
cli → queue
core → shared
core → database
core → queue
database → shared
queue → shared
```

## Core Package Deep Dive

### Agents (`packages/core/src/agents/`)

All 8 agents extend `AbstractAgent`. The key lifecycle methods are:

| Method | Purpose |
|---|---|
| `execute(context)` | Main entry point, returns `AgentResult` |
| `getSystemPrompt()` | LLM system prompt for this agent |
| `buildUserPrompt(context)` | Builds the LLM user message |
| `parseResponse(response, context)` | Parses LLM JSON into `Finding[]` |
| `validateFinding(finding)` | Caps confidence, checks evidence |
| `setup?(context)` | Optional pre-execution hook |
| `teardown?(context)` | Optional post-execution hook |

### Analyzers (`packages/core/src/analyzers/`)

Run **after** the agent swarm completes, operating over the aggregated `Finding[]`:

- **CVCAnalyzer** — Builds an adjacency list of chainable OWASP category pairs and performs BFS to find multi-vulnerability exploit chains. Compound CVSS = max + 10% contribution from each additional.
- **VCVFMatcher** — Matches code snippets against 6 VCVF pattern definitions (regex-based). Outputs fingerprints with predicted vulnerabilities.
- **TIEFDetector** — Classifies trust inversions based on finding categories and VCVF patterns.

### Orchestrator (`packages/core/src/orchestrator/`)

`Orchestrator.runScan(config)` executes the full 5-phase pipeline:

```typescript
// Phase 1: Recon (serial)
const reconResult = await reconAgent.execute(context);

// Phase 2: Swarm (parallel)
const results = await Promise.all(agents.map(a => a.execute(context)));

// Phase 3-5: Analysis (serial, but fast)
const chains = await cvcAnalyzer.findChains(allFindings);
const vcvfFingerprints = reconData.vcvfPatterns.map(toFingerprint);
const trustInversions = await tiefDetector.detect(allFindings);
```

### Report Generator (`packages/core/src/report/`)

Three audience modes:

| Audience | Sections |
|---|---|
| `executive` | Headline, risk score, business impact, immediate actions |
| `developer` | All findings grouped by severity/category, affected files, priority queue |
| `security` | Full technical details + PoCs + attack surface map + remediation code diffs |

Three output formats: `json`, `markdown`, `html`.

## Database Schema (`packages/database/src/schema/`)

Drizzle ORM with SQLite. Key tables:

| Table | Purpose |
|---|---|
| `scans` | One row per scan run |
| `findings` | Individual vulnerability findings, FK to scans |
| `agent_runs` | Per-agent execution metrics, FK to scans |
| `compound_chains` | CVC chains with attack steps |
| `vcvf_fingerprints` | Detected VCVF patterns with predicted vulns |
| `trust_inversions` | TIEF detections |
| `reports` | Generated report content |

## LLM Integration (`packages/core/src/llm/`)

Multi-provider with fallback:

| Provider | Model | Role |
|---|---|---|
| Anthropic | Claude 3.5 Sonnet | Primary (best security reasoning) |
| OpenRouter | Aggregated | Backup |
| Google | Gemini 1.5 Pro | Backup |
