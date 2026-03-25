# Guardiant: Commercialization & Business Model

## 1. Executive Summary
Guardiant occupies a unique niche in the rapidly expanding Application Security Testing (AST) market. While traditional tools (SonarQube, Snyk) rely on static pattern matching, Guardiant is specifically engineered for the **AI Code Generation Era**. By targeting the unique logical flaws introduced by AI coding assistants (VCVF) and utilizing an LLM-powered agent swarm to chain low-level vulnerabilities together (CVC), Guardiant provides penetration-tester-level insights at software speed.

The proposed business model leverages a **Product-Led Growth (PLG) Open-Core** strategy, transitioning users from a free local CLI to a robust, scalable Enterprise cloud platform.

---

## 2. Value Proposition
* **The Problem:** AI coding assistants (Copilot, Cursor) dramatically increase developer velocity but introduce unique, subtle security vulnerabilities—such as conflating authentication with authorization, or generating overly permissive Firebase/Supabase queries. Legacy static scanners cannot detect these context-dependent logical flaws.
* **The Solution:** Guardiant's LLM-driven agents analyze the *intent* of the code. The platform reduces alert fatigue by grouping false-positive-prone lower-severity alerts into actionable, high-severity Compound Vulnerability Chains (CVC).

---

## 3. Target Audiences
1. **Modern Dev Tools Startups / SMBs:** Companies building heavily on BaaS (Supabase/Firebase) and utilizing AI-assisted development.
2. **DevSecOps Teams:** Engineers needing scriptable, native CI/CD security controls that focus on exploit chains rather than raw vulnerability counts.
3. **Enterprise Compliance Teams:** Organizations that require automated, auditor-ready reporting (SOC2, ISO27001) for applications built by augmented engineering teams.

---

## 4. Monetization Strategy: The Open-Core Model

### Tier 1: Guardiant Community (Free / Open Source)
* **Delivery:** Local CLI (`npm i -g @guardiant/cli`), Docker container.
* **Features:** Standard agent swarm, basic Recon, SQLite database, Markdown/JSON reporting.
* **LLM Dependency:** Bring-Your-Own-Key (BYOK) for OpenAI/Anthropic.
* **Goal:** Drive adoption, developer love, and virality. Engineers test it locally, realize the value of the findings, and advocate for team adoption.

### Tier 2: Guardiant Cloud Team ($99 / user / month)
* **Delivery:** Managed SaaS platform + CI/CD Native Integrations (GitHub App, GitLab).
* **Features:** 
  * Cloud-hosted execution (no local configuration required).
  * Centralized dashboard for managing Findings over time.
  * Baseline diffs: Only alert on *new* vulnerabilities introduced in a specific Pull Request.
  * Deep BaaS integration (automatically scanning Supabase instances).
  * Included LLM costs (fair use thresholds).
* **Goal:** Monetize companies seamlessly integrating Guardiant into their GitHub Action workflows.

### Tier 3: Guardiant Enterprise (Custom Pricing, starting at $15,000 / year)
* **Delivery:** Dedicated tenant or VPC/On-Premise deployment.
* **Features:**
  * Custom VCVF Rule creation (enforcing internal corporate security standards).
  * SAML / SSO Integration.
  * Exportable Compliance Reports (Executive mapping to SOC2/HIPAA).
  * Dedicated high-concurrency BullMQ worker pools for massive microservice architectures.
  * Triage and JIRA two-way syncing.
* **Goal:** Land large-scale organizational contracts with strict compliance and data sovereignty requirements.

---

## 5. Go-To-Market (GTM) Strategy

### Phase 1: Developer Advocacy & Open Source Traction
* **Launch:** Product Hunt, HackerNews, and Reddit (r/netsec, r/programming) focusing on the angle: *"AI is writing your code. Who is securing it?"*
* **Content Marketing:** Publish deep-dive blog posts on the "Top 5 vulnerabilities introduced by GitHub Copilot" using Guardiant findings as proof.
* **IDE Extensions:** Build a lightweight VSCode/Cursor extension that runs Guardiant's VCVF matcher locally as the developer types.

### Phase 2: Strategic Partnerships
* **BaaS Providers:** Partner with Supabase, Vercel, and Firebase as an officially recommended security auditing tool for their platforms.
* **Marketplaces:** Publish the Guardiant GitHub Action to the GitHub Marketplace to minimize friction for Tier 2 onboarding.

### Phase 3: Enterprise Sales
* **Top-Down Sales:** Target Director of AppSec / CISO roles leveraging the premise that engineering output is scaling 10x due to AI, but AppSec headcount remains flat. Guardiant is the force multiplier.

---

## 6. Unit Economics & Cost Structure
The primary variable cost for the SaaS tier is LLM inference.
* **Optimization:** Guardiant heavily utilizes the `ReconCache` to prevent redundant network and LLM calls.
* **Model Routing:** Routine tasks (Recon) can be routed to cheaper, faster models (e.g., GPT-4o-mini or Claude 3 Haiku), while complex reasoning tasks (CVC Analyzers, Business Logic) are routed to frontier models (Claude 3.5 Sonnet).
* **Infrastructure:** The `@guardiant/queue` architecture using BullMQ and Redis allows dynamic auto-scaling of agent workers based on scan volume, keeping infrastructure costs highly elastic.
