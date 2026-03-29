# PostHog Analytics Setup Guide

Quick guide to enable product analytics in Guardiant.

## 📋 Prerequisites

- PostHog account (free at https://app.posthog.com)
- Access to your PostHog project settings

---

## 🔑 Step 1: Get Your Project API Key

1. Log in to PostHog: https://app.posthog.com
2. Go to **Project Settings** (gear icon in bottom-left)
3. Look for **Project API Key** or **Project Token** section
4. Copy the key (starts with `phc_...`)

---

## ⚙️ Step 2: Add to Environment

### Option A: Local Development (.env file)

```bash
# Create .env file if it doesn't exist
cd /path/to/guardiant
cp .env.example .env

# Add PostHog key
echo "POSTHOG_API_KEY=phc_your_key_here" >> .env
```

### Option B: System Environment Variable

**Windows (PowerShell):**
```powershell
# Temporary (current session only)
$env:POSTHOG_API_KEY = "phc_your_key_here"

# Permanent (user-level)
[System.Environment]::SetEnvironmentVariable('POSTHOG_API_KEY', 'phc_your_key_here', 'User')
```

**macOS/Linux (Bash/Zsh):**
```bash
# Temporary (current session only)
export POSTHOG_API_KEY=phc_your_key_here

# Permanent (add to ~/.bashrc or ~/.zshrc)
echo 'export POSTHOG_API_KEY=phc_your_key_here' >> ~/.bashrc
source ~/.bashrc
```

### Option C: CI/CD (GitHub Actions)

Add to **Repository Secrets** (Settings → Secrets and variables → Actions):
- Name: `POSTHOG_API_KEY`
- Value: `phc_your_key_here`

Then use in workflow:
```yaml
env:
  POSTHOG_API_KEY: ${{ secrets.POSTHOG_API_KEY }}
```

---

## ✅ Step 3: Verify Setup

Run a test scan to verify analytics are working:

```bash
# Make sure you're in the guardiant directory
cd /path/to/guardiant

# Run a quick scan
pnpm guardiant scan ./packages/core --agents recon

# Check PostHog dashboard (may take 1-2 minutes to appear)
# Go to: PostHog → Activity → Live events
# Look for: scan_started, scan_completed events
```

---

## 📊 What Gets Tracked

Guardiant tracks these events:

### `cli_installed`
- When: First CLI installation
- Data: Platform, Node version, CLI version

### `scan_started`
- When: Scan begins
- Data: Target (sanitized), agents used, agent count

### `scan_completed`
- When: Scan finishes
- Data: Findings count (by severity), duration, agents used

### `scan_error`
- When: Scan fails
- Data: Error message, target

### `report_generated`
- When: Report exported
- Data: Format (JSON/Markdown/HTML), findings count

### `feature_used`
- When: Specific features used
- Data: Feature name, custom metadata

---

## 🔒 Privacy & Security

### What We Track:
- ✅ Anonymous usage (hashed machine ID)
- ✅ Scan statistics (findings count, severity)
- ✅ Agents used
- ✅ Error messages

### What We DON'T Track:
- ❌ Your source code
- ❌ File contents
- ❌ Specific vulnerabilities found
- ❌ Full URLs (sanitized to remove sensitive data)
- ❌ Personal information

### Opt-Out:
Analytics are **opt-in by default**. Simply don't set `POSTHOG_API_KEY` and no data will be sent.

---

## 🐛 Troubleshooting

### Events not appearing in PostHog?

1. **Check the API key is set:**
   ```bash
   # Windows (PowerShell)
   echo $env:POSTHOG_API_KEY
   
   # macOS/Linux
   echo $POSTHOG_API_KEY
   ```

2. **Verify the key format:**
   - Should start with `phc_`
   - No quotes or spaces
   - Full key copied

3. **Check PostHog Live Events:**
   - Go to PostHog → Activity → Live events
   - Events may take 1-2 minutes to appear
   - Check for any error messages

4. **Test with verbose logging:**
   ```bash
   LOG_LEVEL=debug pnpm guardiant scan ./test-project
   ```

### "PostHog not initialized" errors?

This means `POSTHOG_API_KEY` is not set. This is expected and safe — analytics will be silently disabled.

### Want to disable analytics temporarily?

```bash
# Windows
$env:POSTHOG_API_KEY = ""

# macOS/Linux
unset POSTHOG_API_KEY
```

---

## 📈 Using PostHog Dashboard

Once events are flowing, explore your data:

### Dashboards (Recommended Setup)

Create a "Guardiant Usage" dashboard with these insights:

1. **Total Scans** (Trends)
   - Event: `scan_completed`
   - Chart: Line graph (7/30 days)

2. **Active Users** (Trends)
   - Event: `scan_started`
   - Unique users (by `distinct_id`)

3. **Findings Distribution** (Breakdown)
   - Event: `scan_completed`
   - Breakdown by: `critical_count`, `high_count`, `medium_count`, `low_count`

4. **Popular Agents** (Breakdown)
   - Event: `scan_started`
   - Breakdown by: `agents`

5. **Error Rate** (Funnels)
   - Step 1: `scan_started`
   - Step 2: `scan_completed`
   - Drop-off shows error rate

6. **Average Scan Duration** (Trends)
   - Event: `scan_completed`
   - Average of: `duration_seconds`

### Session Recording

PostHog supports session recording for web apps, but **not applicable** for CLI tools.

### Feature Flags

You can use PostHog feature flags to:
- Roll out new agents gradually (e.g., enable `baas-agent` for 10% of users)
- A/B test different vulnerability detection algorithms
- Enable experimental features for beta users

---

## 🎯 Next Steps

1. ✅ Set up PostHog API key (you are here)
2. Create Guardiant dashboard in PostHog
3. Set up weekly email reports (PostHog → Subscriptions)
4. Monitor key metrics:
   - Active users (DAU/WAU/MAU)
   - Scans per user
   - Findings per scan
   - Agent usage distribution

---

## 📚 Resources

- **PostHog Docs**: https://posthog.com/docs
- **PostHog API**: https://posthog.com/docs/api
- **Guardiant Analytics Code**: `packages/shared/src/analytics/index.ts`
- **CLI Integration**: `apps/cli/src/commands/scan.ts`

---

## 💡 Pro Tips

### Test Events Locally

```bash
# Enable analytics locally with your key
export POSTHOG_API_KEY=phc_your_key_here

# Run test scan
pnpm guardiant scan ./test-project

# Check PostHog Live Events immediately
```

### Multiple Environments

Use different PostHog projects for dev/staging/prod:

```bash
# Development
POSTHOG_API_KEY=phc_dev_key_here

# Production (in CI/CD)
POSTHOG_API_KEY=phc_prod_key_here
```

### Privacy-First Development

If building features that track new data:
1. Update `packages/shared/src/analytics/index.ts`
2. Document in this guide
3. Ensure no PII (Personally Identifiable Information)
4. Always sanitize URLs/paths

---

**Need Help?** Open an issue: https://github.com/paarthbhatt/Guardiant/issues
