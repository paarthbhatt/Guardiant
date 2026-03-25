# Guardiant — Configuration Guide

## Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

### LLM Providers

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Recommended | Claude 3.5 Sonnet (best for security reasoning) |
| `OPENROUTER_API_KEY` | Optional | Fallback multi-model provider |
| `GOOGLE_API_KEY` | Optional | Gemini backup provider |

> At least one of the three must be set for AI-assisted analysis to work.

### Storage & Runtime

| Variable | Default | Description |
|---|---|---|
| `DATABASE_PATH` | `~/.guardiant/guardiant.db` | SQLite database file location |
| `LOG_LEVEL` | `info` | One of: `error`, `warn`, `info`, `debug` |
| `GUARDIANT_MAX_CONCURRENCY` | `3` | Max concurrent agents per scan |
| `GUARDIANT_TIMEOUT_MS` | `30000` | Per-agent HTTP request timeout (ms) |

### Redis (optional, for production queue)

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | — | Redis connection URL (e.g. `redis://localhost:6379`) |

If `REDIS_URL` is not set, Guardiant uses the in-memory queue (suitable for single-machine use).

---

## CLI Configuration File

The CLI stores persistent config at `~/.guardiant/config.json` (managed by the `conf` package):

```bash
# Set an LLM provider key
guardiant config set anthropicApiKey sk-ant-...

# Set default scan concurrency
guardiant config set maxConcurrency 5

# View all config
guardiant config list
```

---

## Agent Configuration

Agents can be individually enabled/disabled and tuned in a scan config:

```typescript
const config: ScanConfig = {
  target: 'https://myapp.com',
  type: 'url',
  agentConfigs: {
    injection: { enabled: true, timeout: 60000 },
    baas: { enabled: true },
    race: { enabled: false }, // too noisy for this target
  },
};
```

---

## LLM Provider Setup

### Anthropic (Recommended)

1. Create an account at [console.anthropic.com](https://console.anthropic.com)
2. Navigate to API Keys and create a new key
3. Set `ANTHROPIC_API_KEY=sk-ant-...` in your `.env`

### OpenRouter

1. Sign up at [openrouter.ai](https://openrouter.ai)
2. Create an API key from the dashboard
3. Set `OPENROUTER_API_KEY=sk-or-...`

### Google Gemini

1. Visit [aistudio.google.com](https://aistudio.google.com)
2. Create an API key
3. Set `GOOGLE_API_KEY=AIza...`
