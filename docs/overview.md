# Guardiant — Platform Overview

## What is Guardiant?

Guardiant is an **agentic security platform** built to find vulnerabilities in "vibe-coded" (AI-generated) applications. It targets the unique failure modes that emerge when LLMs generate code — from pattern-level issues like Auth/Authz Conflation to architectural risks like BaaS Bypass.

---

## Why Vibe-Code Security?

AI-generated code has characteristic patterns that introduce systematic vulnerability classes:

| VCVF Pattern | Description |
|---|---|
| **Symmetric CRUD Vulnerabilities** | All CRUD routes share the same auth check with no per-action authz |
| **Auth/Authz Conflation** | Code checks *if* a user is logged in rather than *what* they are allowed to do |
| **Optimistic Trust Patterns** | Client-side validation with no server-side copy |
| **BaaS Bypass Architecture** | Direct Supabase/Firebase client access with an exposed service role key |
| **Over-Permissive Defaults** | CORS wildcards, public storage buckets, disabled RLS |
| **Missing Negative Cases** | Empty error handlers that silently succeed |

---

## The 5-Phase Scan Lifecycle

```
Target URL
   │
   ▼
Phase 1: RECON          — Discover endpoints, JS bundles, tech stack, BaaS provider
   │
   ▼
Phase 2: AGENT SWARM    — 7 agents run in parallel (Injection, BaaS, Secrets, Auth, ...)
   │
   ▼
Phase 3: CVC ANALYSIS   — Link related findings into Compound Vulnerability Chains
   │
   ▼
Phase 4: VCVF MATCHING  — Fingerprint AI-generated code patterns
   │
   ▼
Phase 5: TIEF DETECTION — Detect trust boundary inversions (frontend auth logic, etc.)
   │
   ▼
Report  — Executive / Developer / Security formats (JSON, Markdown, HTML)
```

---

## Quick Start

```bash
# Install
pnpm install

# Build all packages
pnpm build

# Run a scan
pnpm cli scan https://myapp.com

# Generate a report
pnpm cli report <scan-id> --format markdown

# Launch the web dashboard
pnpm web
```

---

## Supported BaaS Platforms

- **Supabase** — RLS configuration, service key exposure, storage bucket permissions, SECURITY DEFINER functions
- **Firebase** — Test mode rules, public read/write, Firestore security rules, storage rules
