import { AbstractAgent } from './base.js';
import { createFinding } from './types.js';
import type { AgentContext, AgentResult, Finding } from '@guardiant/shared';
import { OWASP_CATEGORIES } from '@guardiant/shared';

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

      // Phase 1: Test payment/price manipulation
      const paymentFindings = await this.testPaymentManipulation(context);
      findings.push(...paymentFindings);

      // Phase 2: Test rate limiting
      const rateLimitFindings = await this.testRateLimiting(context);
      findings.push(...rateLimitFindings);

      // Phase 3: Test feature flags
      const featureFlagFindings = await this.testFeatureFlags(context);
      findings.push(...featureFlagFindings);

      // Phase 4: Test workflow bypass
      const workflowFindings = await this.testWorkflowBypass(context);
      findings.push(...workflowFindings);

      // Phase 5: Test coupon/discount logic
      const couponFindings = await this.testCouponLogic(context);
      findings.push(...couponFindings);

      // Phase 6: Test quantity manipulation
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

  /**
   * Test payment amount manipulation
   */
  private async testPaymentManipulation(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for VCVF pattern: optimistic trust
    const hasOptimisticTrust = context.reconData?.vcvfPatterns.some(
      p => p.type === 'optimistic_trust_patterns'
    );

    if (hasOptimisticTrust) {
      // Higher likelihood of payment manipulation
      findings.push(
        createFinding(this.id)
          .title('Potential Payment Amount Manipulation')
          .description(
            'The application appears to trust client-side price/amount data. ' +
            'This is a common vulnerability in vibe-coded applications where ' +
            'developers trust the frontend to send correct prices instead of ' +
            'fetching prices from the server. Attackers can modify payment ' +
            'amounts in transit, potentially purchasing items for free or ' +
            'at heavily discounted prices.'
          )
          .severity('high')
          .cvssScore(8.1)
          .category('A04_INSECURE_DESIGN')
          .confidence(0.75)
          .vcvfPattern('optimistic_trust_patterns')
          .evidence({
            context: { pattern: 'optimistic_trust_patterns' },
          })
          .remediation({
            summary: 'Always validate prices and amounts on the server side.',
            steps: [
              'Never trust client-side price data',
              'Fetch prices from database on the server',
              'Verify amounts before processing payment',
              'Use server-side order validation',
              'Log all price modifications for audit',
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
            priority: 3,
          })
          .tags(['business-logic', 'payment', 'price-manipulation'])
          .build()
      );
    }

    return findings;
  }

  /**
   * Test rate limiting
   */
  private async testRateLimiting(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for VCVF pattern: missing negative cases / over-permissive defaults
    const hasMissingRateLimit = context.reconData?.vcvfPatterns.some(
      p => p.type === 'missing_negative_cases' || p.type === 'over_permissive_defaults'
    );

    if (hasMissingRateLimit) {
      findings.push(
        createFinding(this.id)
          .title('Missing or Ineffective Rate Limiting')
          .description(
            'Rate limiting appears to be missing or easily bypassable. ' +
            'This allows attackers to perform brute force attacks, ' +
            'credential stuffing, or automated scraping without restriction.'
          )
          .severity('medium')
          .cvssScore(6.5)
          .category('A04_INSECURE_DESIGN')
          .confidence(0.7)
          .vcvfPattern('missing_negative_cases')
          .evidence({
            context: { pattern: 'missing_negative_cases' },
          })
          .remediation({
            summary: 'Implement server-side rate limiting for all sensitive endpoints.',
            steps: [
              'Implement rate limiting at the API gateway or middleware level',
              'Use rate limiting based on IP, user ID, and API key',
              'Apply stricter limits on authentication endpoints',
              'Return 429 status code when limits exceeded',
              'Consider using token bucket or sliding window algorithms',
            ],
            codeExample: `// Express rate limiting middleware
import rateLimit from 'express-rate-limit';

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests' }
});

// Stricter limits for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // 5 attempts per 15 minutes
});

app.use('/api/', limiter);
app.use('/api/auth/', authLimiter);`,
            effort: 'low',
            priority: 5,
          })
          .tags(['business-logic', 'rate-limiting', 'brute-force'])
          .build()
      );
    }

    return findings;
  }

  /**
   * Test feature flags
   */
  private async testFeatureFlags(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for VCVF pattern: optimistic trust patterns
    const hasOptimisticTrust = context.reconData?.vcvfPatterns.some(
      p => p.type === 'optimistic_trust_patterns'
    );

    if (hasOptimisticTrust) {
      findings.push(
        createFinding(this.id)
          .title('Potential Feature Flag Bypass')
          .description(
            'The application uses optimistic trust patterns for feature flags. ' +
            'This may allow users to bypass feature restrictions by modifying ' +
            'client-side configuration or accessing hidden endpoints.'
          )
          .severity('medium')
          .cvssScore(6.5)
          .category('A04_INSECURE_DESIGN')
          .confidence(0.7)
          .vcvfPattern('optimistic_trust_patterns')
          .evidence({
            context: { pattern: 'optimistic_trust_patterns' },
          })
          .remediation({
            summary: 'Implement server-side feature flag evaluation.',
            steps: [
              'Move all feature flag logic to the server side',
              'Validate feature access before returning feature-dependent data',
              'Use a dedicated feature flag service with server SDKs',
              'Audit all client-side feature checks',
            ],
            effort: 'medium',
            priority: 5,
          })
          .tags(['business-logic', 'feature-flags', 'bypass'])
          .build()
      );
    }

    return findings;
  }

  /**
   * Test workflow bypass
   */
  private async testWorkflowBypass(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for VCVF pattern: optimistic trust patterns
    const hasOptimisticTrust = context.reconData?.vcvfPatterns.some(
      p => p.type === 'optimistic_trust_patterns'
    );

    if (hasOptimisticTrust) {
      findings.push(
        createFinding(this.id)
          .title('Potential Workflow Step Bypass')
          .description(
            'The application may allow users to skip workflow steps. ' +
            'This is a common vulnerability in vibe-coded applications where ' +
            'client-side routing controls workflow progression without ' +
            'server-side validation of step completion.'
          )
          .severity('medium')
          .cvssScore(5.3)
          .category('A04_INSECURE_DESIGN')
          .confidence(0.65)
          .vcvfPattern('optimistic_trust_patterns')
          .evidence({
            context: { pattern: 'optimistic_trust_patterns' },
          })
          .remediation({
            summary: 'Implement server-side workflow state validation.',
            steps: [
              'Track workflow state on the server',
              'Validate each step before allowing progression',
              'Prevent skipping steps via direct API calls',
              'Use workflow engines for complex multi-step processes',
            ],
            effort: 'medium',
            priority: 4,
          })
          .tags(['business-logic', 'workflow', 'bypass'])
          .build()
      );
    }

    return findings;
  }

  /**
   * Test coupon/discount logic
   */
  private async testCouponLogic(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for VCVF pattern: missing negative cases
    const hasMissingNegatives = context.reconData?.vcvfPatterns.some(
      p => p.type === 'missing_negative_cases'
    );

    if (hasMissingNegatives) {
      findings.push(
        createFinding(this.id)
          .title('Potential Coupon/Discount Abuse')
          .description(
            'The application may be vulnerable to coupon or discount abuse. ' +
            'Lack of proper negative case handling in business logic allows ' +
            'users to stack coupons, apply expired discounts, or manipulate ' +
            'pricing calculations.'
          )
          .severity('medium')
          .cvssScore(5.3)
          .category('A04_INSECURE_DESIGN')
          .confidence(0.6)
          .vcvfPattern('missing_negative_cases')
          .evidence({
            context: { pattern: 'missing_negative_cases' },
          })
          .remediation({
            summary: 'Implement strict coupon validation and business rules.',
            steps: [
              'Validate coupon expiration dates server-side',
              'Prevent coupon stacking without explicit rules',
              'Check minimum purchase requirements',
              'Limit coupon usage per user',
              'Log all coupon redemptions for audit',
            ],
            effort: 'low',
            priority: 5,
          })
          .tags(['business-logic', 'coupon', 'pricing'])
          .build()
      );
    }

    return findings;
  }

  /**
   * Test quantity manipulation
   */
  private async testQuantityManipulation(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for VCVF pattern: optimistic trust patterns
    const hasOptimisticTrust = context.reconData?.vcvfPatterns.some(
      p => p.type === 'optimistic_trust_patterns'
    );

    if (hasOptimisticTrust) {
      findings.push(
        createFinding(this.id)
          .title('Potential Quantity Manipulation')
          .description(
            'The application may allow quantity manipulation attacks. ' +
            'Without server-side quantity validation, users can enter ' +
            'negative quantities, decimal quantities for integer items, ' +
            'or extremely large quantities to cause overflow issues.'
          )
          .severity('medium')
          .cvssScore(5.3)
          .category('A04_INSECURE_DESIGN')
          .confidence(0.65)
          .vcvfPattern('optimistic_trust_patterns')
          .evidence({
            context: { pattern: 'optimistic_trust_patterns' },
          })
          .remediation({
            summary: 'Implement strict quantity validation on the server.',
            steps: [
              'Validate quantity is a positive integer',
              'Check against available inventory',
              'Prevent negative or zero quantities',
              'Cap maximum quantity per order',
              'Log quantity modifications for audit',
            ],
            effort: 'low',
            priority: 4,
          })
          .tags(['business-logic', 'quantity', 'manipulation'])
          .build()
      );
    }

    return findings;
  }
}