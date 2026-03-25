# Recon Agent

## Overview

The **Reconnaissance Agent** is the first agent to run in every scan. Its output — endpoints, tech stack, authentication mechanisms, and detected BaaS provider — is shared with all subsequent agents as `AgentContext.reconData`.

**OWASP Coverage:** A05 - Security Misconfiguration

---

## What It Discovers

### Endpoints
- HTML links (`href`, `src`, `action`)
- Form targets and HTTP methods
- Inline API paths (`/api/...`)
- Common paths probed actively (`/graphql`, `/swagger`, `/api-docs`, etc.)

### JavaScript Bundle Analysis
- Extracts `.js` URLs from `<script>` tags and Next.js chunk paths
- Fetches up to 10 bundles for deep analysis
- Checks for `.map` source map availability

### Tech Stack Fingerprinting
- **Frameworks:** React, Vue, Angular, Next.js, Nuxt, SvelteKit, Remix, Astro
- **BaaS providers:** Supabase, Firebase, Appwrite, Amplify
- **Auth providers:** Auth0, Clerk, NextAuth, Lucia, Better Auth
- **Response headers:** `Server`, `X-Powered-By`

### Authentication Mechanisms

| Type | Detection Signal |
|---|---|
| JWT | `jwt`, `bearer`, `localStorage.setItem.*token` |
| Session cookie | `session`, `connect.sid`, `PHPSESSID` |
| OAuth | `oauth`, `signin.*google/github/facebook` |
| BaaS auth | `supabase.*auth`, `firebase.*auth` |

### Security Findings Generated

| Finding | Severity | CVSS |
|---|---|---|
| Source maps exposed in production | Medium | 5.3 |
| Accessible sensitive config file (`.env`, `firebase.json`) | High | 7.5 |

### VCVF Pattern Detection
Runs 5 VCVF checks using client-side code heuristics:
- `auth_authz_conflation`
- `baas_bypass_architecture`
- `optimistic_trust_patterns`
- `missing_negative_cases`
- `over_permissive_defaults`
