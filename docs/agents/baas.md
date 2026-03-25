# BaaS Security Agent

## Overview

The **BaaS Security Agent** targets Backend-as-a-Service platforms — the primary building block of vibe-coded apps. It is marked `priority: critical` because BaaS misconfigurations are the most common and impactful vulnerability class in AI-generated code.

**OWASP Coverage:** A01 - Broken Access Control, A05 - Security Misconfiguration

---

## Supported Providers

### Supabase

| Check | Severity | Description |
|---|---|---|
| Service role key in client code | Critical (10.0) | Bypasses all RLS policies |
| Tables accessible without auth | Critical (9.8) | No RLS or permissive policies |
| Overly broad RLS policies | High (8.5) | `USING (true)` policies |
| Public storage buckets | High (7.5) | Unauthenticated file listing |
| SECURITY DEFINER RPC calls | Medium (6.5) | Functions that bypass RLS |

### Firebase

| Check | Severity | Description |
|---|---|---|
| Test mode rules | Critical | `allow read, write: if true` |
| Public read/write access | High | No auth requirement |
| Storage rules missing auth | High | Anyone can upload/read |
| Service account in client code | Critical (10.0) | Admin SDK key exposure |

---

## Provider Detection

The agent determines the BaaS provider from (in priority order):
1. `context.target.baasProvider` — explicit config
2. `context.reconData.techStack.baas.provider` — from Recon Agent
3. `context.reconData.externalServices` — service name scan
4. Falls back to `unknown` — agent skips all tests

---

## Key Security Pattern: Service Key Exposure

The most critical pattern the BaaS agent looks for is the **Supabase service role key in client-side JavaScript**:

```javascript
// ❌ Critical vulnerability — never do this
const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)

// ✅ Use anon key on client
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY)
```

A found service role key receives CVSS 10.0 and immediate priority 1 remediation.
