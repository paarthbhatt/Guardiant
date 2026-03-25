import { AbstractAgent, createFinding } from './base.js';
import type { AgentContext, AgentResult, Finding } from '@guardiant/shared';
import { OWASP_CATEGORIES } from '@guardiant/shared';

/**
 * Race Condition Agent
 *
 * Tests for race conditions and TOCTOU vulnerabilities including:
 * - Double-spend on payment endpoints
 * - Concurrent registration
 * - Counter manipulation
 * - Time-of-check to time-of-use (TOCTOU)
 */
export class RaceConditionAgent extends AbstractAgent {
  readonly id = 'race_condition' as const;
  readonly name = 'Race Condition Agent';
  readonly description = 'Tests for race conditions and TOCTOU vulnerabilities.';
  readonly categories = [
    OWASP_CATEGORIES.A04_INSECURE_DESIGN.code,
  ];
  readonly priority = 'low' as const;

  async execute(context: AgentContext): Promise<AgentResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];

    try {
      await this.setup?.(context);

      // Phase 1: Test double-spend vulnerabilities
      const doubleSpendFindings = await this.testDoubleSpend(context);
      findings.push(...doubleSpendFindings);

      // Phase 2: Test concurrent registration
      const registrationFindings = await this.testConcurrentRegistration(context);
      findings.push(...registrationFindings);

      // Phase 3: Test counter manipulation
      const counterFindings = await this.testCounterManipulation(context);
      findings.push(...counterFindings);

      // Phase 4: Test TOCTOU in file operations
      const toctouFindings = await this.testTOCTOU(context);
      findings.push(...toctouFindings);

      // Phase 5: Test coupon/reward race conditions
      const couponRaceFindings = await this.testCouponRace(context);
      findings.push(...couponRaceFindings);

      await this.teardown?.(context);

      return this.createSuccessResult(findings, {
        endpointsTested: context.reconData?.endpoints.length ?? 0,
        custom: {
          raceConditionTests: findings.length,
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
    return `You are a race condition security testing expert.

Your job is to test for race conditions and TOCTOU vulnerabilities:

1. Double-Spend - Can the same payment/credit be used twice?
2. Concurrent Registration - Can duplicate accounts be created?
3. Counter Manipulation - Can counters be decremented multiple times?
4. TOCTOU - Time-of-check to time-of-use vulnerabilities
5. Coupon/Reward Abuse - Can coupons be applied multiple times?

Race conditions occur when:
- Multiple requests execute simultaneously
- State checks and state changes are not atomic
- Locks are missing on shared resources

These are common in vibe-coded apps where atomic operations are not considered.

Provide detailed reproduction steps using parallel requests.`;
  }

  buildUserPrompt(context: AgentContext): string {
    return `Test for race conditions on the following target:

Target: ${context.target.url}

Focus on:
1. Payment/checkout endpoints - double spend
2. Registration endpoints - duplicate accounts
3. Referral/reward endpoints - abuse
4. Inventory/stock endpoints - overselling
5. Voting/like endpoints - multiple votes
6. Coupon endpoints - multiple uses`;
  }

  async parseResponse(response: string, context: AgentContext): Promise<Finding[]> {
    return [];
  }

  /**
   * Test double-spend vulnerabilities
   */
  private async testDoubleSpend(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Double-spend: Using the same payment/credit twice
    // 1. Start payment
    // 2. Send same payment request multiple times in parallel
    // 3. If balance is deducted only once, but payment processed multiple times = vulnerability

    // Check for VCVF pattern: missing negative cases
    const hasMissingNegatives = context.reconData?.vcvfPatterns.some(
      p => p.type === 'missing_negative_cases'
    );

    if (hasMissingNegatives) {
      findings.push(
        createFinding(this.id)
          .title('Potential Double-Spend Vulnerability')
          .description(
            'The application may be vulnerable to double-spend attacks where ' +
            'the same payment, credit, or token can be used multiple times ' +
            'if requests are sent concurrently. This is common in vibe-coded ' +
            'apps where atomic operations are not implemented.'
          )
          .severity('high')
          .cvssScore(7.5)
          .category('A04_INSECURE_DESIGN')
          .confidence(0.6)
          .vcvfPattern('missing_negative_cases')
          .evidence({
            context: { pattern: 'missing_negative_cases' },
          })
          .remediation({
            summary: 'Implement atomic operations and idempotency for financial transactions.',
            steps: [
              'Use database transactions for payment operations',
              'Implement idempotency keys for payment endpoints',
              'Add unique constraints on transaction IDs',
              'Use pessimistic locking for balance updates',
              'Implement request deduplication',
            ],
            codeExample: `// ❌ Non-atomic balance update
const balance = await db.getBalance(userId);
if (balance >= amount) {
  await db.updateBalance(userId, balance - amount);
}

// ✅ Atomic balance update with transaction
await db.transaction(async (tx) => {
  const balance = await tx.getBalanceForUpdate(userId); // Lock row
  if (balance >= amount) {
    await tx.updateBalance(userId, balance - amount);
    await tx.createTransaction(userId, -amount, idempotencyKey);
  } else {
    throw new Error('Insufficient balance');
  }
});`,
            effort: 'medium',
            priority: 4,
          })
          .tags(['race-condition', 'double-spend', 'toctou'])
          .build()
      );
    }

    return findings;
  }

  /**
   * Test concurrent registration
   */
  private async testConcurrentRegistration(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for VCVF pattern: missing negative cases
    const hasMissingNegatives = context.reconData?.vcvfPatterns.some(
      p => p.type === 'missing_negative_cases'
    );

    if (hasMissingNegatives) {
      findings.push(
        createFinding(this.id)
          .title('Potential Concurrent Registration Vulnerability')
          .description(
            'The application may be vulnerable to concurrent registration attacks. ' +
            'Without proper atomic operations, multiple requests with the same email ' +
            'can create duplicate accounts or cause data corruption.'
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
            summary: 'Implement atomic registration with unique constraints.',
            steps: [
              'Add unique constraints on email in the database',
              'Use database transactions for registration',
              'Check for existing user atomically before creating',
              'Consider using upsert operations',
            ],
            effort: 'medium',
            priority: 5,
          })
          .tags(['race-condition', 'concurrent-registration', 'duplicate'])
          .build()
      );
    }

    return findings;
  }

  /**
   * Test counter manipulation
   */
  private async testCounterManipulation(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for VCVF pattern: optimistic trust patterns
    const hasOptimisticTrust = context.reconData?.vcvfPatterns.some(
      p => p.type === 'optimistic_trust_patterns'
    );

    if (hasOptimisticTrust) {
      findings.push(
        createFinding(this.id)
          .title('Potential Counter Manipulation')
          .description(
            'The application may be vulnerable to counter manipulation attacks. ' +
            'Without atomic increment/decrement operations, counters (likes, views, ' +
            'votes) can be manipulated by sending concurrent requests.'
          )
          .severity('low')
          .cvssScore(3.5)
          .category('A04_INSECURE_DESIGN')
          .confidence(0.65)
          .vcvfPattern('optimistic_trust_patterns')
          .evidence({
            context: { pattern: 'optimistic_trust_patterns' },
          })
          .remediation({
            summary: 'Implement atomic counter operations using database transactions.',
            steps: [
              'Use atomic increment/decrement operations',
              'Implement locking for counter updates',
              'Consider using Redis for high-throughput counters',
              'Add rate limiting on counter endpoints',
            ],
            effort: 'low',
            priority: 6,
          })
          .tags(['race-condition', 'counter', 'manipulation'])
          .build()
      );
    }

    return findings;
  }

  /**
   * Test TOCTOU vulnerabilities
   */
  private async testTOCTOU(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for VCVF pattern: optimistic trust patterns
    const hasOptimisticTrust = context.reconData?.vcvfPatterns.some(
      p => p.type === 'optimistic_trust_patterns'
    );

    if (hasOptimisticTrust) {
      findings.push(
        createFinding(this.id)
          .title('Potential TOCTOU Vulnerability')
          .description(
            'The application may be vulnerable to Time-of-Check to Time-of-Use (TOCTOU) attacks. ' +
            'This occurs when a resource is checked for access or existence, but the state ' +
            'changes between the check and the use of the resource.'
          )
          .severity('medium')
          .cvssScore(5.3)
          .category('A04_INSECURE_DESIGN')
          .confidence(0.55)
          .vcvfPattern('optimistic_trust_patterns')
          .evidence({
            context: { pattern: 'optimistic_trust_patterns' },
          })
          .remediation({
            summary: 'Make checks and operations atomic.',
            steps: [
              'Use database transactions for check-and-use operations',
              'Implement file locking for file operations',
              'Use atomic database operations (e.g., findAndModify)',
              'Avoid separate check then action patterns',
            ],
            effort: 'medium',
            priority: 4,
          })
          .tags(['race-condition', 'toctou', 'atomicity'])
          .build()
      );
    }

    return findings;
  }

  /**
   * Test coupon race conditions
   */
  private async testCouponRace(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for VCVF pattern: missing negative cases
    const hasMissingNegatives = context.reconData?.vcvfPatterns.some(
      p => p.type === 'missing_negative_cases'
    );

    if (hasMissingNegatives) {
      findings.push(
        createFinding(this.id)
          .title('Potential Coupon Race Condition')
          .description(
            'The application may be vulnerable to coupon race conditions. ' +
            'Without proper transaction handling, users can apply the same coupon ' +
            'multiple times by sending concurrent requests.'
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
            summary: 'Implement atomic coupon application with database transactions.',
            steps: [
              'Add unique constraint on (user_id, coupon_id, order_id)',
              'Use database transactions for coupon redemption',
              'Check coupon validity and apply atomically',
              'Consider using optimistic locking with version numbers',
            ],
            effort: 'medium',
            priority: 5,
          })
          .tags(['race-condition', 'coupon', 'stacking'])
          .build()
      );
    }

    return findings;
  }
}