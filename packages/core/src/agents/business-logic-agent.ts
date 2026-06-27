import { AbstractAgent } from './base.js';
import { createFinding } from './types.js';
import type { AgentContext, AgentResult, Finding } from '@guardiant/shared';
import { OWASP_CATEGORIES } from '@guardiant/shared';
import { readFileSync, existsSync, statSync, readdirSync } from 'fs';
import { join, relative, extname } from 'path';

/**
 * Business Logic Agent
 *
 * Tests business logic vulnerabilities including:
 * - Payment amount manipulation
 * - Rate limiting absence
 * - Feature flag bypass
 * - Workflow step skipping
 * - Coupon/discount stacking
 * - Quantity manipulation
 *
 * FINDINGS ARE ONLY EMITTED when:
 *   1. The app context confirms the feature exists (e.g., hasPayments)
 *   2. Concrete code evidence shows the vulnerability
 *   VCVF pattern presence alone is NOT sufficient.
 */
export class BusinessLogicAgent extends AbstractAgent {
  readonly id = 'business_logic' as const;
  readonly name = 'Business Logic Agent';
  readonly description = 'Tests business logic vulnerabilities (payment manipulation, rate limits, workflow bypass).';
  readonly categories = [
    OWASP_CATEGORIES.A04_INSECURE_DESIGN.code,
  ];
  readonly priority = 'medium' as const;

  async execute(context: AgentContext): Promise<AgentResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];

    try {
      await this.setup?.(context);

      // Phase 1: Test payment/price manipulation (requires hasPayments)
      const paymentFindings = await this.testPaymentManipulation(context);
      findings.push(...paymentFindings);

      // Phase 2: Test rate limiting (requires auth endpoints)
      const rateLimitFindings = await this.testRateLimiting(context);
      findings.push(...rateLimitFindings);

      // Phase 3: Test feature flags (requires feature-gated code)
      const featureFlagFindings = await this.testFeatureFlags(context);
      findings.push(...featureFlagFindings);

      // Phase 4: Test workflow bypass (requires multi-step workflows)
      const workflowFindings = await this.testWorkflowBypass(context);
      findings.push(...workflowFindings);

      // Phase 5: Test coupon/discount logic (requires payment flows)
      const couponFindings = await this.testCouponLogic(context);
      findings.push(...couponFindings);

      // Phase 6: Test quantity manipulation (requires cart/order flows)
      const quantityFindings = await this.testQuantityManipulation(context);
      findings.push(...quantityFindings);

      await this.teardown?.(context);

      return this.createSuccessResult(findings, {
        endpointsTested: context.reconData?.endpoints.length ?? 0,
        custom: {
          businessLogicTests: findings.length,
        },
      }, this.getDuration(startTime));
    } catch (error) {
      return this.createErrorResult(
        error instanceof Error ? error : new Error('Unknown error'),
        this.getDuration(startTime)
      );
    }
  }

  getSystemPrompt(): string {
    return `You are a business logic security testing expert.

Your job is to test business logic vulnerabilities that automated scanners miss:

1. Payment Amount Manipulation - Can users modify prices/amounts?
2. Rate Limiting - Are rate limits properly enforced?
3. Feature Flags - Can users enable premium features?
4. Workflow Bypass - Can users skip steps in workflows?
5. Coupon/Discount Stacking - Can discounts be combined?
6. Quantity Manipulation - Can negative quantities be used?

Business logic flaws are common in vibe-coded apps because:
- LLMs don't inherently understand business constraints
- Client-side validation without server-side verification
- Missing negative case handling

Provide detailed test cases and reproduction steps.`;
  }

  buildUserPrompt(context: AgentContext): string {
    const endpoints = context.reconData?.endpoints ?? [];
    return `Test business logic vulnerabilities on the following target:

Target: ${context.target.url}

Endpoints discovered:
${endpoints.map(e => `- ${e.method} ${e.path}`).join('\\n')}

Look for:
1. Payment/checkout endpoints - test amount manipulation
2. Rate-limited endpoints - test limit enforcement
3. Feature-gated endpoints - test bypass attempts
4. Multi-step workflows - test step skipping
5. Coupon/discount endpoints - test stacking and application
6. Order/cart endpoints - test quantity manipulation`;
  }

  async parseResponse(_response: string, _context: AgentContext): Promise<Finding[]> {
    return [];
  }

  // ─── Code Evidence Search ──────────────────────────────────────────

  private findCodeEvidence(
    context: AgentContext,
    pattern: RegExp
  ): { file: string; line: number; snippet: string } | null {
    if (context.target.type !== 'directory') return null;
    const rootPath = context.target.url;
    if (!existsSync(rootPath)) return null;

    const textExtensions = new Set(['.ts', '.tsx', '.js', '.jsx', '.vue', '.svelte']);
    const excludeDirs = new Set(['node_modules', '.git', '.next', 'dist', 'build', '.cache', 'coverage']);

    let result: { file: string; line: number; snippet: string } | null = null;

    const walkDir = (dir: string): void => {
      if (result) return;
      let entries: string[];
      try { entries = readdirSync(dir); } catch { return; }

      for (const entry of entries) {
        if (result) return;
        if (excludeDirs.has(entry)) continue;
        const fullPath = join(dir, entry);
        try {
          const stats = statSync(fullPath);
          if (stats.isDirectory()) {
            walkDir(fullPath);
          } else if (stats.isFile() && textExtensions.has(extname(fullPath).toLowerCase())) {
            const content = readFileSync(fullPath, 'utf-8');
            const match = pattern.exec(content);
            if (match) {
              const line = content.substring(0, match.index).split('\n').length;
              result = { file: relative(rootPath, fullPath), line, snippet: match[0].substring(0, 200) };
            }
          }
        } catch { /* skip */ }
      }
    };

    walkDir(rootPath);
    return result;
  }

  private hasEndpointPattern(context: AgentContext, pattern: RegExp): boolean {
    return context.reconData?.endpoints.some(e => pattern.test(e.path)) ?? false;
  }

  // ─── Payment Manipulation ─────────────────────────────────────────

  private async testPaymentManipulation(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // GUARD: Only run if app has payment flows
    if (context.appContext && !context.appContext.hasPayments) return findings;

    // Need concrete evidence: code shows client-sent price used directly
    const evidence = this.findCodeEvidence(
      context,
      /(?:req\.body\.(?:price|amount|total|cost|subtotal)|req\.body\[.*(?:price|amount|total).*\])(?!.*\.(?:getPrice|calculate|fetch|lookup))/i
    );

    if (evidence) {
      findings.push(
        createFinding(this.id)
          .title('Payment Amount Manipulation')
          .description(
            `Found client-supplied price/amount data used directly in ${evidence.file}:${evidence.line}. ` +
            'The server trusts the client to send correct prices instead of fetching them from the database. ' +
            'Attackers can modify payment amounts in transit to purchase items for free or at discounted prices.'
          )
          .severity('critical')
          .cvssScore(9.1)
          .category('A04_INSECURE_DESIGN')
          .confidence(0.9)
          .vcvfPattern('optimistic_trust_patterns')
          .evidence({
            file: evidence.file,
            line: evidence.line,
            snippet: evidence.snippet,
          })
          .remediation({
            summary: 'Always validate prices and amounts on the server side.',
            steps: [
              'Never trust client-side price data',
              'Fetch prices from database on the server',
              'Verify amounts before processing payment',
              'Use server-side order validation',
            ],
            codeExample: `// ❌ Trusting client-side price
app.post('/api/checkout', async (req, res) => {
  const { items, total } = req.body; // User can modify total!
  await processPayment(total);
});

// ✅ Server-side price calculation
app.post('/api/checkout', async (req, res) => {
  const { itemIds } = req.body;
  const items = await db.getItems(itemIds);
  const total = items.reduce((sum, item) => sum + item.price, 0);
  await processPayment(total);
});`,
            effort: 'medium',
            priority: 1,
          })
          .tags(['business-logic', 'payment', 'price-manipulation'])
          .build()
      );
    }

    return findings;
  }

  // ─── Rate Limiting ────────────────────────────────────────────────

  private async testRateLimiting(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // GUARD: Need auth endpoints to check for rate limiting
    const hasAuthEndpoints = this.hasEndpointPattern(context, /\/(?:auth|login|register|signup|signin)/i);
    if (!hasAuthEndpoints && context.appContext && !context.appContext.hasAuth) return findings;

    // Check for absence of rate limiting middleware in code
    const hasRateLimiter = this.findCodeEvidence(
      context,
      /(?:rateLimit|rate.?limit|express.?rate.?limit|throttle|limiter|slowDown|expressSlowDown)/i
    );

    // Only flag if auth endpoints exist AND no rate limiter found
    if (!hasRateLimiter) {
      const hasAuthCode = this.findCodeEvidence(
        context,
        /(?:login|signin|signup|register|authenticate)\s*\(/
      );

      if (hasAuthCode || hasAuthEndpoints) {
        findings.push(
          createFinding(this.id)
            .title('Missing Rate Limiting on Authentication')
            .description(
              'Authentication endpoints found without rate limiting middleware. ' +
              'This allows brute force attacks, credential stuffing, or automated account enumeration.'
            )
            .severity('medium')
            .cvssScore(6.5)
            .category('A04_INSECURE_DESIGN')
            .confidence(0.75)
            .evidence({
              context: { pattern: 'missing_rate_limit', hasAuthEndpoints },
            })
            .remediation({
              summary: 'Implement server-side rate limiting for authentication endpoints.',
              steps: [
                'Add rate limiting middleware (e.g., express-rate-limit)',
                'Use stricter limits on login/register endpoints (5-10 per 15 min)',
                'Return 429 status code when limits exceeded',
                'Consider adding CAPTCHA after repeated failures',
              ],
              effort: 'low',
              priority: 3,
            })
            .tags(['business-logic', 'rate-limiting', 'brute-force'])
            .build()
        );
      }
    }

    return findings;
  }

  // ─── Feature Flags ────────────────────────────────────────────────

  private async testFeatureFlags(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for feature flags stored client-side or in accessible endpoints
    const evidence = this.findCodeEvidence(
      context,
      /(?:featureFlags?|FEATURE_FLAGS?|features?)\s*[:=]\s*(?:req\.body|localStorage|sessionStorage|window\.|process\.env\.NEXT_PUBLIC)/i
    );

    if (evidence) {
      findings.push(
        createFinding(this.id)
          .title('Client-Side Feature Flag Configuration')
          .description(
            `Found feature flags controlled client-side in ${evidence.file}:${evidence.line}. ` +
            'Feature flags stored in localStorage, env vars, or client-side state can be ' +
            'modified by users to access premium or hidden features.'
          )
          .severity('medium')
          .cvssScore(6.5)
          .category('A04_INSECURE_DESIGN')
          .confidence(0.8)
          .evidence({
            file: evidence.file,
            line: evidence.line,
            snippet: evidence.snippet,
          })
          .remediation({
            summary: 'Evaluate feature flags server-side and gate features at the API level.',
            steps: [
              'Move feature flag evaluation to the server',
              'Gate feature-dependent API endpoints server-side',
              'Use a feature flag service with server SDKs',
            ],
            effort: 'medium',
            priority: 4,
          })
          .tags(['business-logic', 'feature-flags', 'bypass'])
          .build()
      );
    }

    return findings;
  }

  // ─── Workflow Bypass ──────────────────────────────────────────────

  private async testWorkflowBypass(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Look for multi-step workflow patterns where steps can be skipped
    const evidence = this.findCodeEvidence(
      context,
      /(?:step|stage|wizard|onboarding|checkout.*step)\s*(?:===?|>=?|<=?)\s*(?:\d|req\.body\.step|req\.query\.step)/i
    );

    if (evidence) {
      // Verify there's no server-side step validation
      const hasStepValidation = this.findCodeEvidence(
        context,
        /(?:validateStep|checkStep|currentStep|completedSteps|stepHistory)/i
      );

      if (!hasStepValidation) {
        findings.push(
          createFinding(this.id)
            .title('Potential Workflow Step Bypass')
            .description(
              `Found workflow step control via client-provided step number in ${evidence.file}:${evidence.line} ` +
              'without server-side validation of step completion. Users may skip steps by manipulating the step parameter.'
            )
            .severity('medium')
            .cvssScore(5.3)
            .category('A04_INSECURE_DESIGN')
            .confidence(0.7)
            .evidence({
              file: evidence.file,
              line: evidence.line,
              snippet: evidence.snippet,
            })
            .remediation({
              summary: 'Validate workflow step completion on the server.',
              steps: [
                'Track workflow state on the server',
                'Validate each step before allowing progression',
                'Prevent skipping steps via direct API calls',
              ],
              effort: 'medium',
              priority: 4,
            })
            .tags(['business-logic', 'workflow', 'bypass'])
            .build()
        );
      }
    }

    return findings;
  }

  // ─── Coupon Logic ─────────────────────────────────────────────────

  private async testCouponLogic(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // GUARD: Only run if app has payment flows
    if (context.appContext && !context.appContext.hasPayments) return findings;

    // Check for coupon application without usage tracking
    const evidence = this.findCodeEvidence(
      context,
      /(?:applyCoupon|redeemCoupon|useDiscount|applyDiscount)\s*\([^)]*\)\s*{(?![^}]*(?:usedCount|usageCount|redeemed|maxUses|limit))/i
    );

    if (evidence) {
      findings.push(
        createFinding(this.id)
          .title('Potential Coupon/Discount Abuse')
        .description(
          `Found coupon/discount application without usage tracking in ${evidence.file}:${evidence.line}. ` +
          'Without tracking redemption counts and enforcing limits, coupons can be reused indefinitely ' +
          'or stacked to reduce prices to zero.'
        )
        .severity('medium')
        .cvssScore(5.3)
        .category('A04_INSECURE_DESIGN')
        .confidence(0.75)
        .evidence({
          file: evidence.file,
          line: evidence.line,
          snippet: evidence.snippet,
        })
        .remediation({
          summary: 'Implement strict coupon validation with usage limits.',
          steps: [
            'Track coupon usage per user in the database',
            'Enforce single-use or limited-use constraints',
            'Validate coupon expiration server-side',
            'Prevent stacking unless explicitly allowed',
          ],
          effort: 'low',
          priority: 4,
        })
        .tags(['business-logic', 'coupon', 'pricing'])
        .build()
      );
    }

    return findings;
  }

  // ─── Quantity Manipulation ────────────────────────────────────────

  private async testQuantityManipulation(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // GUARD: Only run if app has payment flows (cart/order)
    if (context.appContext && !context.appContext.hasPayments) return findings;

    // Check for quantity used without validation
    const evidence = this.findCodeEvidence(
      context,
      /(?:req\.body\.quantity|req\.body\.qty|quantity.*req\.body)(?![^;]*(?:Math\.|parseInt|Number\(|> ?0|< ?0|isPositive|validate))/i
    );

    if (evidence) {
      findings.push(
        createFinding(this.id)
          .title('Potential Quantity Manipulation')
          .description(
            `Found quantity from request body used without validation in ${evidence.file}:${evidence.line}. ` +
            'Without server-side validation, users can submit negative, zero, or decimal quantities ' +
            'to manipulate order totals or exploit business logic.'
          )
          .severity('medium')
          .cvssScore(5.3)
          .category('A04_INSECURE_DESIGN')
          .confidence(0.8)
          .evidence({
            file: evidence.file,
            line: evidence.line,
            snippet: evidence.snippet,
          })
          .remediation({
            summary: 'Validate quantity server-side as a positive integer within bounds.',
            steps: [
              'Validate quantity is a positive integer',
              'Check against available inventory',
              'Cap maximum quantity per order',
            ],
            effort: 'low',
            priority: 3,
          })
          .tags(['business-logic', 'quantity', 'manipulation'])
          .build()
      );
    }

    return findings;
  }
}
