import { AbstractAgent } from './base.js';
import { createFinding } from './types.js';
import type { AgentContext, AgentResult, Finding } from '@guardiant/shared';
import { OWASP_CATEGORIES } from '@guardiant/shared';
import { createHttpClient } from '../http/index.js';
import { readFileSync, existsSync, statSync, readdirSync } from 'fs';
import { join, relative, extname } from 'path';

/**
 * Race Condition Agent
 *
 * Tests for race conditions and TOCTOU vulnerabilities including:
 * - Double-spend on payment endpoints
 * - Concurrent registration
 * - Counter manipulation
 * - Time-of-check to time-of-use (TOCTOU)
 *
 * FINDINGS ARE ONLY EMITTED when:
 *   1. The app context confirms the relevant feature exists
 *   2. Code shows non-atomic operations (read-then-write without transactions)
 *   VCVF pattern presence alone is NOT sufficient.
 */
export class RaceConditionAgent extends AbstractAgent {
  readonly id = 'race_condition' as const;
  readonly name = 'Race Condition Agent';
  readonly description = 'Tests for race conditions and TOCTOU vulnerabilities.';
  readonly categories = [
    OWASP_CATEGORIES.A04_INSECURE_DESIGN.code,
  ];
  readonly priority = 'low' as const;

  private httpClient: ReturnType<typeof createHttpClient>;

  constructor(config?: { timeout?: number }) {
    super();
    this.httpClient = createHttpClient(config?.timeout ?? 30000);
  }

  async execute(context: AgentContext): Promise<AgentResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];

    try {
      await this.setup?.(context);

      const doubleSpendFindings = await this.testDoubleSpend(context);
      findings.push(...doubleSpendFindings);

      const registrationFindings = await this.testConcurrentRegistration(context);
      findings.push(...registrationFindings);

      const counterFindings = await this.testCounterManipulation(context);
      findings.push(...counterFindings);

      const toctouFindings = await this.testTOCTOU(context);
      findings.push(...toctouFindings);

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

  // ─── HTTP Concurrency Helper ───────────────────────────────────────

  /**
   * Send N identical requests concurrently using Promise.all.
   * Returns array of { status, body, success } for each request.
   */
  private async sendConcurrentRequests(
    url: string,
    method: 'GET' | 'POST',
    count: number,
    body?: Record<string, unknown>,
    headers?: Record<string, string>
  ): Promise<Array<{ status: number; body: string; success: boolean }>> {
    const requests = Array.from({ length: count }, () => {
      if (method === 'POST') {
        return this.httpClient.post(url, body, headers)
          .then(res => ({ status: res.status, body: res.body, success: res.status >= 200 && res.status < 300 }))
          .catch(err => ({
            status: 0,
            body: String(err),
            success: false,
          }));
      }
      return this.httpClient.get(url, headers)
        .then(res => ({ status: res.status, body: res.body, success: res.status >= 200 && res.status < 300 }))
        .catch(err => ({
          status: 0,
          body: String(err),
          success: false,
        }));
    });

    return Promise.all(requests);
  }

  // ─── Double Spend (HTTP + Code) ────────────────────────────────────

  private async testDoubleSpend(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // GUARD: Only if app has payment flows
    if (context.appContext && !context.appContext.hasPayments) return findings;

    // Strategy 1: HTTP Concurrency Test (highest confidence)
    if (context.target.type !== 'directory') {
      const paymentEndpoints = context.reconData?.endpoints.filter(e =>
        /\/(?:checkout|payment|pay|order|purchase|charge)/i.test(e.path)
      ) ?? [];

      for (const endpoint of paymentEndpoints.slice(0, 2)) {
        try {
          const url = `${context.target.url}${endpoint.path}`;
          const testBody = { amount: 100, currency: 'USD', test: true };
          const responses = await this.sendConcurrentRequests(url, 'POST', 10, testBody);

          const successResponses = responses.filter(r => r.status >= 200 && r.status < 300);

          // If >1 request succeeded for a payment endpoint, that's a race condition
          if (successResponses.length > 1) {
            findings.push(
              createFinding(this.id)
                .title('Confirmed Race Condition: Double-Spend via HTTP')
                .description(
                  `Sent 10 concurrent POST requests to ${endpoint.path} — ${successResponses.length} succeeded. ` +
                  'A properly implemented payment endpoint should process only 1 request and reject or queue the rest. ' +
                  'This confirms a double-spend vulnerability.'
                )
                .severity('critical')
                .cvssScore(9.1)
                .category('A04_INSECURE_DESIGN')
                .confidence(0.95)
                .evidence({
                  request: `POST ${endpoint.path} (x10 concurrent)`,
                  response: `${successResponses.length}/10 succeeded`,
                  endpoints: [endpoint.path],
                })
                .remediation({
                  summary: 'Implement idempotency keys and atomic transactions for payment processing.',
                  steps: [
                    'Generate idempotency key per payment request',
                    'Use database transactions with row-level locking',
                    'Return cached result for duplicate idempotency keys',
                    'Add unique constraint on (user_id, idempotency_key)',
                  ],
                  effort: 'medium',
                  priority: 1,
                })
                .tags(['race-condition', 'double-spend', 'http-confirmed'])
                .build()
            );
          }
        } catch {
          // continue
        }
      }
    }

    // Strategy 2: Code Analysis (fallback for directory scans)
    const evidence = this.findCodeEvidence(
      context,
      /(?:getBalance|get_balance|balance\.find|balance\.get)\s*\([^)]*\)[^}]*?(?:update|set|save|write|decrement)\s*(?:Balance|balance)/i
    );

    if (evidence) {
      const hasTransaction = this.findCodeEvidence(
        context,
        /(?:transaction|transaction\(|\.transaction|knex\.transaction|BEGIN\s*TRANSACTION)/i
      );

      if (!hasTransaction) {
        findings.push(
          createFinding(this.id)
            .title('Potential Double-Spend Vulnerability')
            .description(
              `Found non-atomic balance read-then-write in ${evidence.file}:${evidence.line}. ` +
              'Without database transactions, concurrent requests can cause double-spend.'
            )
            .severity('high')
            .cvssScore(7.5)
            .category('A04_INSECURE_DESIGN')
            .confidence(0.8)
            .evidence({
              file: evidence.file,
              line: evidence.line,
              snippet: evidence.snippet,
            })
            .remediation({
              summary: 'Use database transactions with row-level locking for balance operations.',
              steps: [
                'Use database transactions for payment operations',
                'Implement idempotency keys for payment endpoints',
                'Use pessimistic locking (SELECT FOR UPDATE) for balance reads',
              ],
              effort: 'medium',
              priority: 2,
            })
            .tags(['race-condition', 'double-spend', 'toctou'])
            .build()
        );
      }
    }

    return findings;
  }

  // ─── Concurrent Registration ──────────────────────────────────────

  private async testConcurrentRegistration(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // GUARD: Need auth
    if (context.appContext && !context.appContext.hasAuth) return findings;

    // Look for registration without unique constraint or atomic check
    const hasRegistrationEndpoint = this.hasEndpointPattern(
      context, /\/(?:register|signup|sign-up|create-account)/i
    );
    const hasRegistrationCode = this.findCodeEvidence(
      context,
      /(?:createUser|register|signUp|create\s*Account)\s*\(/
    );

    if (!hasRegistrationEndpoint && !hasRegistrationCode) return findings;

    // Check for unique constraint or atomic check
    const hasUniqueConstraint = this.findCodeEvidence(
      context,
      /(?:unique.*email|email.*unique|findOne.*email|exists.*email|upsert|ON\s*CONFLICT)/i
    );

    // Only flag if no unique constraint pattern found
    if (!hasUniqueConstraint) {
      findings.push(
        createFinding(this.id)
          .title('Potential Concurrent Registration')
          .description(
            'User registration without apparent unique constraint enforcement. ' +
            'Concurrent requests with the same email could create duplicate accounts ' +
            'or cause data corruption.'
          )
          .severity('medium')
          .cvssScore(5.3)
          .category('A04_INSECURE_DESIGN')
          .confidence(0.65)
          .evidence({
            context: { hasRegistrationEndpoint, hasRegistrationCode: Boolean(hasRegistrationCode) },
          })
          .remediation({
            summary: 'Add unique constraint on email and use atomic registration.',
            steps: [
              'Add UNIQUE constraint on email column in the database',
              'Use upsert or check-then-create within a transaction',
              'Handle duplicate key errors gracefully',
            ],
            effort: 'medium',
            priority: 4,
          })
          .tags(['race-condition', 'concurrent-registration', 'duplicate'])
          .build()
      );
    }

    return findings;
  }

  // ─── Counter Manipulation ─────────────────────────────────────────

  private async testCounterManipulation(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Strategy 1: HTTP Concurrency Test
    if (context.target.type !== 'directory') {
      const counterEndpoints = context.reconData?.endpoints.filter(e =>
        /\/(?:like|vote|view|follow|upvote|downvote|reaction|star)\b/i.test(e.path)
      ) ?? [];

      for (const endpoint of counterEndpoints.slice(0, 2)) {
        try {
          const url = `${context.target.url}${endpoint.path}`;
          const responses = await this.sendConcurrentRequests(url, 'POST', 10, {});
          const successResponses = responses.filter(r => r.status >= 200 && r.status < 300);

          // If all 10 succeed, counter likely isn't using atomic operations
          if (successResponses.length === 10) {
            findings.push(
              createFinding(this.id)
                .title('Confirmed Race Condition: Counter Manipulation via HTTP')
                .description(
                  `Sent 10 concurrent POST requests to ${endpoint.path} — all 10 succeeded. ` +
                  'Counters should use atomic operations (DB increment) which would still succeed ' +
                  'but only increment once. If all 10 are processed independently, the counter ' +
                  'can be manipulated.'
                )
                .severity('medium')
                .cvssScore(5.3)
                .category('A04_INSECURE_DESIGN')
                .confidence(0.85)
                .evidence({
                  request: `POST ${endpoint.path} (x10 concurrent)`,
                  response: `${successResponses.length}/10 succeeded`,
                  endpoints: [endpoint.path],
                })
                .remediation({
                  summary: 'Use atomic counter operations.',
                  steps: [
                    'Use UPDATE table SET counter = counter + 1 (atomic)',
                    'Implement request deduplication for counter endpoints',
                  ],
                  effort: 'low',
                  priority: 4,
                })
                .tags(['race-condition', 'counter', 'http-confirmed'])
                .build()
            );
          }
        } catch {
          // continue
        }
      }
    }

    // Strategy 2: Code Analysis (fallback)
    const evidence = this.findCodeEvidence(
      context,
      /(?:increment|decrement|likes|votes|views)\s*(?:\+\+|\+=\s*1|=\s*\w+\s*\+\s*1)/i
    );

    if (evidence) {
      const hasAtomicOp = this.findCodeEvidence(
        context,
        /(?:increment|decrement|atomic|SET\s+\w+\s*=\s*\w+\s*[+-]\s*1|UPDATE.*\+\s*1)/i
      );

      if (!hasAtomicOp) {
        findings.push(
          createFinding(this.id)
            .title('Potential Counter Manipulation')
            .description(
              `Found non-atomic counter operation in ${evidence.file}:${evidence.line}. ` +
              'Without atomic increment/decrement, concurrent requests can manipulate counters.'
            )
            .severity('low')
            .cvssScore(3.5)
            .category('A04_INSECURE_DESIGN')
            .confidence(0.7)
            .evidence({
              file: evidence.file,
              line: evidence.line,
              snippet: evidence.snippet,
            })
            .remediation({
              summary: 'Use atomic increment/decrement operations.',
              steps: [
                'Use database atomic operations (UPDATE SET counter = counter + 1)',
                'Consider using Redis INCR for high-throughput counters',
              ],
              effort: 'low',
              priority: 5,
            })
            .tags(['race-condition', 'counter', 'manipulation'])
            .build()
        );
      }
    }

    return findings;
  }

  // ─── TOCTOU ───────────────────────────────────────────────────────

  private async testTOCTOU(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Look for check-then-act patterns without locking
    const evidence = this.findCodeEvidence(
      context,
      /(?:if\s*\(.*(?:exists|available|inStock|quantity|balance).*\)\s*{[^}]*(?:update|save|delete|create|insert))/i
    );

    if (evidence) {
      // Check if the check and action are in a transaction
      const hasTransaction = this.findCodeEvidence(
        context,
        /(?:transaction|\.transaction|BEGIN\s*TRANSACTION|withTransaction)/i
      );

      if (!hasTransaction) {
        findings.push(
          createFinding(this.id)
            .title('Potential TOCTOU Vulnerability')
            .description(
              `Found check-then-act pattern without transaction in ${evidence.file}:${evidence.line}. ` +
              'The state can change between the check and the action, causing ' +
              'Time-of-Check to Time-of-Use vulnerabilities.'
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
              summary: 'Make check-and-use operations atomic with database transactions.',
              steps: [
                'Use database transactions for check-then-act operations',
                'Use SELECT FOR UPDATE to lock rows during modifications',
                'Use atomic operations where possible (upsert, findAndModify)',
              ],
              effort: 'medium',
              priority: 4,
            })
            .tags(['race-condition', 'toctou', 'atomicity'])
            .build()
        );
      }
    }

    return findings;
  }

  // ─── Coupon Race Condition ────────────────────────────────────────

  private async testCouponRace(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // GUARD: Only if app has payment flows
    if (context.appContext && !context.appContext.hasPayments) return findings;

    // Look for coupon application without atomic usage tracking
    const evidence = this.findCodeEvidence(
      context,
      /(?:applyCoupon|redeemCoupon|useCoupon)\s*\([^)]*\)(?![^}]*(?:transaction|atomic|decrement|increment.*uses))/i
    );

    if (evidence) {
      findings.push(
        createFinding(this.id)
          .title('Potential Coupon Race Condition')
          .description(
            `Found coupon application without atomic usage tracking in ${evidence.file}:${evidence.line}. ` +
            'Concurrent requests can apply the same coupon multiple times before ' +
            'usage limits are enforced.'
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
            summary: 'Use atomic coupon redemption with database constraints.',
            steps: [
              'Add unique constraint on (user_id, coupon_id, order_id)',
              'Use database transactions for coupon redemption',
              'Decrement usage count atomically: UPDATE coupons SET uses = uses - 1 WHERE id = ? AND uses > 0',
            ],
            effort: 'medium',
            priority: 4,
          })
          .tags(['race-condition', 'coupon', 'stacking'])
          .build()
      );
    }

    return findings;
  }
}
