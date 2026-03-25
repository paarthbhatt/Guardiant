# Guardiant: Platform Analysis & Walkthrough

## 1. Executive Summary
Guardiant is a next-generation, AI-native Application Security Testing (AST) platform designed specifically to detect, analyze, and remediate vulnerabilities in modern, API-driven, and AI-generated codebases. Unlike legacy static (SAST) or dynamic (DAST) scanners that rely on rigid regex rules, Guardiant utilizes an orchestrated swarm of specialized Large Language Model (LLM) agents to analyze context, understand business logic, and detect complex attack vectors.

## 2. Core Architecture: The 5-Phase Scan Engine
Guardiant abandons the traditional linear scan approach in favor of a dynamic, 5-phase execution pipeline orchestrated by the `@guardiant/core` engine.

### Phase 1: Reconnaissance (Recon Agent)
The scan begins with a comprehensive mapping of the target's attack surface. 
* **Endpoints:** Discovers REST, GraphQL, and RPC endpoints.
* **Tech Stack:** Fingerprints frameworks (Next.js, Express) and BaaS providers (Supabase, Firebase).
* **Auth & Inputs:** Identifies authentication mechanisms and input boundaries. Results are cached via `ReconCache` to optimize performance across multiple runs.

### Phase 2: Autonomous Agent Swarm
Based on the Recon phase, Guardiant dynamically dispatches a swarm of specialized security agents. These agents run concurrently via a BullMQ-backed queueing system, analyzing the target simultaneously from different attack perspectives.

### Phase 3: VCVF (Vibe Code Vulnerability Fingerprinting)
Guardiant introduces a novel heuristic approach targeting code written by AI assistants (like Copilot, Cursor, or Claude). AI often writes code that *looks* correct but contains subtle logical flaws. The `VCVFMatcher` analyzes source code structure to detect:
* **Symmetric CRUD:** Applying identical authentication checks to safe (GET) and destructive (DELETE) operations.
* **Auth/Authz Conflation:** Checking if a user is logged in, but failing to check if they have permission to access a specific resource.
* **Missing Negative Cases:** Empty catch blocks or implicit trust in client-side validation.

### Phase 4: CVC (Compound Vulnerability Chaining)
Low-severity vulnerabilities are often dismissed as "informational" by legacy scanners. The `CVCAnalyzer` algorithmically evaluates all isolated findings and checks if they can be sequenced. For example, a low-severity "Information Disclosure" combined with a medium-severity "Missing Rate Limit" and a medium-severity "Misconfigured CORS" might form a Critical "Account Takeover" chain.

### Phase 5: TIEF (Trust Inversion Edge Finding)
The `TIEFDetector` maps data boundaries to identify where a system improperly places trust. It specifically looks for architectures where client applications handle sensitive logic (e.g., frontend JWT decoding for access control, or direct BaaS database mutations without Row-Level Security).

---

## 3. The Agent Swarm
Guardiant deploys 8 specialized agents, configurable via `config/default-agents.yaml`.

1. **Recon Agent:** Attack surface mapping.
2. **BaaS Agent:** Specialized checks for Firebase and Supabase (e.g., exposed anon keys, missing RLS policies).
3. **Secrets Agent:** Deep scanning for leaked credentials, API keys, and asymmetric private keys.
4. **Auth Agent:** IDOR (Insecure Direct Object Reference), privilege escalation, and token weakness detection.
5. **Injection Agent:** SQLi, XSS, Command Injection, and Path Traversal testing.
6. **Supply Chain Agent:** Lockfile tampering, npm audit aggregation, and dependency confusion checks.
7. **Business Logic Agent:** Payment flow manipulation, rate limit testing, and state transition flaws.
8. **Race Condition Agent:** Concurrent request testing to exploit Time-of-Check to Time-of-Use (TOCTOU) flaws.

---

## 4. Platform Modularity & Tech Stack
The platform is built as a highly scalable TypeScript monorepo powered by Turbo.

* **Trigger Interfaces:** A robust Commander-based CLI (`@guardiant/cli`) with Zod-validated inputs. (Future-proofed for a Web UI).
* **State Management:** Drizzle ORM paired with SQLite (`@guardiant/database`) ensures fast, portable state management for scans, findings, and complex CVC chain relationships.
* **Task Queuing:** BullMQ/Redis (`@guardiant/queue`) enables massive horizontal scalability for agent execution.
* **Reporting:** Generates Markdown, JSON, and HTML reports tailored for three distinct audiences: Executives (risk-focused), Security (chain-focused), and Developers (remediation-focused), featuring zero-memory-cost streaming for massive outputs.

## 5. Primary Use Cases

1. **AI-Assisted Development Guardrails:** As developers increasingly rely on AI to generate boilerplates, Guardiant specifically hunts the exact classes of logical flaws AI commonly produces (VCVF). 
2. **DevSecOps CI/CD Blocking:** The CLI is designed to run in GitHub Actions. With granular configurations (`--stop-on-critical`), it can break the build if a severe trust inversion or compound chain is detected.
3. **Continuous Attack Surface Monitoring:** For dynamic targets, the automated agent swarm provides a persistent, intelligent penetration testing layer that adapts to the application's evolving tech stack.
