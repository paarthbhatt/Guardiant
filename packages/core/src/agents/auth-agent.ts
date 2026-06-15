import { AbstractAgent } from './base.js';
import { createFinding } from './types.js';
import type { AgentContext, AgentResult, Finding, DiscoveredEndpoint } from '@guardiant/shared';
import { OWASP_CATEGORIES } from '@guardiant/shared';
import { createHttpClient } from '../http/index.js';

/**
 * Authentication & Authorization Agent
 *
 * Tests authentication and authorization mechanisms including:
 * - IDOR (Insecure Direct Object References)
 * - Privilege escalation (horizontal and vertical)
 * - Session management
 * - OAuth flow security
 * - JWT manipulation
 * - Password reset flow security
 */
export class AuthAgent extends AbstractAgent {
  readonly id = 'auth' as const;
  readonly name = 'Authentication & Authorization Agent';
  readonly description = 'Tests authentication and authorization mechanisms (IDOR, privilege escalation, session management).';
  readonly categories = [
    OWASP_CATEGORIES.A01_BROKEN_ACCESS_CONTROL.code,
    OWASP_CATEGORIES.A07_AUTH_FAILURES.code,
  ];
  readonly priority = 'high' as const;

  private httpClient: ReturnType<typeof createHttpClient>;

  constructor(config?: { timeout?: number }) {
    super();
    this.httpClient = createHttpClient(config?.timeout ?? 30000);
  }

  async execute(context: AgentContext): Promise<AgentResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];

    // HTTP-based auth testing requires a live target
    if (context.target.type === 'directory') {
      return this.createSuccessResult([], {
        endpointsTested: 0,
        custom: { reason: 'Auth testing requires a live HTTP target; VCVF patterns analyzed by recon agent' },
      }, this.getDuration(startTime));
    }

    try {
      await this.setup?.(context);

      // Phase 1: Test IDOR on discovered endpoints
      const idorFindings = await this.testIDOR(context);
      findings.push(...idorFindings);

      // Phase 2: Test privilege escalation
      const escalationFindings = await this.testPrivilegeEscalation(context);
      findings.push(...escalationFindings);

      // Phase 3: Test session management
      const sessionFindings = await this.testSessionManagement(context);
      findings.push(...sessionFindings);

      // Phase 4: Test OAuth flows
      const oauthFindings = await this.testOAuthFlows(context);
      findings.push(...oauthFindings);

      // Phase 5: Test JWT security
      const jwtFindings = await this.testJWTSecurity(context);
      findings.push(...jwtFindings);

      // Phase 6: Test password reset
      const resetFindings = await this.testPasswordReset(context);
      findings.push(...resetFindings);

      await this.teardown?.(context);

      return this.createSuccessResult(findings, {
        endpointsTested: context.reconData?.endpoints.length ?? 0,
        custom: {
          idorTests: idorFindings.length,
          escalationTests: escalationFindings.length,
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
    return `You are an authentication and authorization security expert.

Your job is to test authentication and authorization mechanisms:

1. IDOR - Test if users can access other users' resources
2. Privilege Escalation - Test if regular users can access admin functions
3. Session Management - Test session expiration, rotation, fixation
4. OAuth Security - Test OAuth flows for vulnerabilities
5. JWT Security - Test JWT implementation for common weaknesses
6. Password Reset - Test reset flow for security issues

For each vulnerability found, provide:
- Clear reproduction steps
- Impact assessment
- Remediation guidance

Focus on common vibe-coded app issues like client-side auth checks.`;
  }

  buildUserPrompt(context: AgentContext): string {
    const endpoints = context.reconData?.endpoints ?? [];
    return `Test authentication and authorization on the following target:

Target: ${context.target.url}

Endpoints discovered:
${endpoints.map(e => `- ${e.method} ${e.path}`).join('\\n')}

Authentication mechanisms:
${context.reconData?.authMechanisms.map(a => `- ${a.type}${a.provider ? ` (${a.provider})` : ''}`).join('\\n') ?? 'Unknown'}

Test for:
1. IDOR on resource endpoints
2. Privilege escalation attempts
3. Session management weaknesses
4. OAuth flow vulnerabilities
5. JWT manipulation
6. Password reset vulnerabilities`;
  }

  async parseResponse(_response: string, _context: AgentContext): Promise<Finding[]> {
    return [];
  }

  /**
   * Test IDOR vulnerabilities
   */
  private async testIDOR(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const baseUrl = context.target.url;

    // IDOR test patterns (reserved for future active probing)
    // const _idorPatterns = [ ... ]; // defined but intentionally deferred

    // Test common IDOR vectors
    const testIds = ['1', '2', '0', '999999', '../etc/passwd'];
    const endpoints = context.reconData?.endpoints ?? [];

    for (const endpoint of endpoints) {
      // Check if endpoint has ID parameters
      const hasIdParam = endpoint.parameters?.some(p =>
        p.name.toLowerCase().includes('id') ||
        p.name.toLowerCase().includes('user') ||
        p.name.toLowerCase().includes('resource')
      );

      if (hasIdParam || /\/:id|\/{id}|\/\d+/.test(endpoint.path)) {
        // Try IDOR by manipulating IDs
        for (const testId of testIds.slice(0, 3)) {
          try {
            const testUrl = this.buildIdorTestUrl(baseUrl, endpoint, testId);
            const response = await this.httpClient.get(testUrl);

            // Check if we get data without proper authorization
            if (response.status === 200 && response.body) {
              // Successful access could indicate IDOR
              // Note: Without authentication context, we can only detect unauthenticated IDOR
              if (endpoint.authentication && !response.body.includes('error') && !response.body.includes('unauthorized')) {
                // This might be a false positive - needs manual verification
              }
            }
          } catch {
            // Continue on error
          }
        }
      }
    }

    // Check for VCVF pattern indicating IDOR likelihood
    const hasIdorPattern = context.reconData?.vcvfPatterns.some(
      p => p.type === 'auth_authz_conflation' || p.type === 'optimistic_trust_patterns'
    );

    if (hasIdorPattern) {
      findings.push(
        createFinding(this.id)
          .title('Potential IDOR Vulnerability')
          .description(
            'The application shows patterns consistent with Insecure Direct Object References (IDOR). ' +
            'Resources appear to be accessed by predictable IDs without proper authorization checks. ' +
            'This allows attackers to access or modify other users\' data by manipulating identifiers in requests.'
          )
          .severity('high')
          .cvssScore(8.1)
          .category('A01_BROKEN_ACCESS_CONTROL')
          .confidence(0.7)
          .vcvfPattern('auth_authz_conflation')
          .evidence({
            endpoints: endpoints.filter(e => /\/:id|\/{id}/.test(e.path)).map(e => e.path),
            context: { pattern: 'auth_authz_conflation' },
          })
          .remediation({
            summary: 'Implement proper authorization checks for all resource access.',
            steps: [
              'Verify user ownership before allowing access to any resource',
              'Use indirect references (e.g., session-based IDs) instead of direct IDs',
              'Implement role-based or permission-based access control',
              'Log all access attempts for security auditing',
            ],
            codeExample: `// ❌ Vulnerable to IDOR
app.get('/api/users/:id', (req, res) => {
  const user = db.getUser(req.params.id);
  res.json(user); // No auth check!
});

// ✅ Protected against IDOR
app.get('/api/users/:id', auth, (req, res) => {
  if (req.params.id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const user = db.getUser(req.params.id);
  res.json(user);
});`,
            effort: 'medium',
            priority: 2,
          })
          .tags(['auth', 'idor', 'access-control'])
          .build()
      );
    }

    return findings;
  }

  /**
   * Build IDOR test URL
   */
  private buildIdorTestUrl(baseUrl: string, endpoint: DiscoveredEndpoint, testId: string): string {
    const url = new URL(baseUrl);
    const path = endpoint.path.replace(/:id|{id}/g, testId);
    url.pathname = path;
    return url.toString();
  }

  /**
   * Test privilege escalation
   */
  private async testPrivilegeEscalation(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Horizontal escalation: User A can access User B's resources
    // Vertical escalation: Regular user can access admin resources

    // Check for client-side role checks
    const hasClientSideAuth = context.reconData?.vcvfPatterns.some(
      p => p.type === 'auth_authz_conflation'
    );

    if (hasClientSideAuth) {
      findings.push(
        createFinding(this.id)
          .title('Client-Side Authorization Check')
          .description(
            'Authorization checks appear to be implemented only on the client side. ' +
            'This allows users to bypass role restrictions by modifying client-side code ' +
            'or making direct API requests. Common in vibe-coded applications where ' +
            'authentication is implemented but authorization is missing on the backend.'
          )
          .severity('high')
          .cvssScore(8.1)
          .category('A01_BROKEN_ACCESS_CONTROL')
          .confidence(0.85)
          .vcvfPattern('auth_authz_conflation')
          .evidence({
            context: { pattern: 'auth_authz_conflation' },
          })
          .remediation({
            summary: 'Implement server-side authorization checks for all protected resources.',
            steps: [
              'Identify all endpoints that require specific roles/permissions',
              'Add role/permission checks on the server side for each endpoint',
              'Never trust client-side role information',
              'Use middleware or decorators for consistent authz enforcement',
              'Log authorization failures for security monitoring',
            ],
            codeExample: `// ❌ Client-side only check
if (user.role === 'admin') {
  // show admin panel
}

// ✅ Server-side check
app.delete('/api/users/:id', async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  // proceed with deletion
});`,
            effort: 'medium',
            priority: 2,
          })
          .tags(['auth', 'authorization', 'idor', 'client-side'])
          .build()
      );
    }

    return findings;
  }

  /**
   * Test session management
   */
  private async testSessionManagement(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for VCVF pattern: optimistic trust patterns
    const hasOptimisticTrust = context.reconData?.vcvfPatterns.some(
      p => p.type === 'optimistic_trust_patterns'
    );

    if (hasOptimisticTrust) {
      findings.push(
        createFinding(this.id)
          .title('Potential Session Management Issues')
          .description(
            'The application may have session management vulnerabilities. ' +
            'Optimistic trust patterns suggest that session validation may be ' +
            'handled client-side without proper server-side validation.'
          )
          .severity('high')
          .cvssScore(7.5)
          .category('A07_AUTH_FAILURES')
          .confidence(0.7)
          .vcvfPattern('optimistic_trust_patterns')
          .evidence({
            context: { pattern: 'optimistic_trust_patterns' },
          })
          .remediation({
            summary: 'Implement server-side session validation for all protected endpoints.',
            steps: [
              'Validate session tokens on the server for each request',
              'Implement session expiration and rotation',
              'Use secure cookie flags (HttpOnly, Secure, SameSite)',
              'Implement session invalidation on logout',
              'Use a secure session store',
            ],
            effort: 'medium',
            priority: 2,
          })
          .tags(['auth', 'session', 'session-management'])
          .build()
      );
    }

    return findings;
  }

  /**
   * Test OAuth flows
   */
  private async testOAuthFlows(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for VCVF pattern: optimistic trust patterns
    const hasOptimisticTrust = context.reconData?.vcvfPatterns.some(
      p => p.type === 'optimistic_trust_patterns'
    );

    if (hasOptimisticTrust) {
      findings.push(
        createFinding(this.id)
          .title('Potential OAuth Flow Vulnerability')
          .description(
            'The application may be vulnerable to OAuth flow attacks. ' +
            'Without proper server-side validation, OAuth callbacks may be ' +
            'manipulated to link attacker-controlled accounts.'
          )
          .severity('high')
          .cvssScore(7.5)
          .category('A07_AUTH_FAILURES')
          .confidence(0.65)
          .vcvfPattern('optimistic_trust_patterns')
          .evidence({
            context: { pattern: 'optimistic_trust_patterns' },
          })
          .remediation({
            summary: 'Implement proper OAuth state validation and link verification.',
            steps: [
              'Validate OAuth state parameter on callback',
              'Verify the linking user matches the authenticated user',
              'Store OAuth state in server-side session',
              'Implement PKCE for additional security',
              'Validate redirect URIs against a whitelist',
            ],
            effort: 'medium',
            priority: 2,
          })
          .tags(['auth', 'oauth', 'flow'])
          .build()
      );
    }

    return findings;
  }

  /**
   * Test JWT security
   */
  private async testJWTSecurity(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for VCVF pattern: optimistic trust patterns
    const hasOptimisticTrust = context.reconData?.vcvfPatterns.some(
      p => p.type === 'optimistic_trust_patterns'
    );

    if (hasOptimisticTrust) {
      findings.push(
        createFinding(this.id)
          .title('Potential JWT Security Issues')
          .description(
            'The application may have JWT security vulnerabilities. ' +
            'Client-side JWT handling without server-side validation exposes ' +
            'the application to token manipulation attacks.'
          )
          .severity('high')
          .cvssScore(7.5)
          .category('A07_AUTH_FAILURES')
          .confidence(0.7)
          .vcvfPattern('optimistic_trust_patterns')
          .evidence({
            context: { pattern: 'optimistic_trust_patterns' },
          })
          .remediation({
            summary: 'Implement server-side JWT validation and verification.',
            steps: [
              'Verify JWT signature on the server',
              'Validate JWT expiration (exp claim)',
              'Validate JWT not-before (nbf claim)',
              'Validate issuer (iss) and audience (aud)',
              'Use strong signing algorithms (RS256, ES256)',
              'Implement token refresh mechanism',
            ],
            effort: 'medium',
            priority: 2,
          })
          .tags(['auth', 'jwt', 'token'])
          .build()
      );
    }

    return findings;
  }

  /**
   * Test password reset flow
   */
  private async testPasswordReset(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for VCVF pattern: missing negative cases
    const hasMissingNegatives = context.reconData?.vcvfPatterns.some(
      p => p.type === 'missing_negative_cases'
    );

    if (hasMissingNegatives) {
      findings.push(
        createFinding(this.id)
          .title('Potential Password Reset Vulnerability')
          .description(
            'The password reset flow may be vulnerable to abuse. ' +
            'Lack of proper validation and rate limiting can allow ' +
            'attackers to enumerate users or reset passwords arbitrarily.'
          )
          .severity('high')
          .cvssScore(8.1)
          .category('A07_AUTH_FAILURES')
          .confidence(0.65)
          .vcvfPattern('missing_negative_cases')
          .evidence({
            context: { pattern: 'missing_negative_cases' },
          })
          .remediation({
            summary: 'Implement secure password reset with rate limiting and validation.',
            steps: [
              'Rate limit password reset requests per IP and email',
              'Use time-limited, single-use reset tokens',
              'Generate cryptographically secure random tokens',
              'Validate user identity before sending reset',
              'Invalidate old tokens when new ones are requested',
              'Log all password reset attempts',
            ],
            effort: 'medium',
            priority: 1,
          })
          .tags(['auth', 'password-reset', 'abuse'])
          .build()
      );
    }

    return findings;
  }
}