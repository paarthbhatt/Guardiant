import { AbstractAgent } from './base.js';
import { createFinding } from './types.js';
import type { AgentContext, AgentResult, Finding, DiscoveredEndpoint } from '@guardiant/shared';
import { OWASP_CATEGORIES } from '@guardiant/shared';
import { createHttpClient } from '../http/index.js';
import { readFileSync, existsSync, statSync, readdirSync } from 'fs';
import { join, relative, extname } from 'path';

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
 *
 * FINDINGS ARE ONLY EMITTED when concrete evidence exists:
 *   - HTTP test confirms the vulnerability (200 + data without auth)
 *   - Source code shows specific vulnerable pattern (file/line/snippet)
 *   VCVF pattern presence alone is NOT sufficient.
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

    try {
      await this.setup?.(context);

      // Phase 1: Test IDOR on discovered endpoints (HTTP or directory)
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

  // ─── Code Evidence Search ──────────────────────────────────────────

  /**
   * Search source code for a specific vulnerability pattern.
   * Returns file/line/snippet evidence if found, null otherwise.
   */
  private findCodeEvidence(
    context: AgentContext,
    pattern: RegExp
  ): { file: string; line: number; snippet: string } | null {
    if (context.target.type !== 'directory') return null;
    const rootPath = context.target.url;
    if (!existsSync(rootPath)) return null;

    const textExtensions = new Set([
      '.ts', '.tsx', '.js', '.jsx', '.vue', '.svelte',
    ]);
    const excludeDirs = new Set([
      'node_modules', '.git', '.next', 'dist', 'build',
      '.cache', 'coverage', 'target',
    ]);

    let result: { file: string; line: number; snippet: string } | null = null;

    const walkDir = (dir: string): void => {
      if (result) return;
      let entries: string[];
      try {
        entries = readdirSync(dir);
      } catch {
        return;
      }

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
              result = {
                file: relative(rootPath, fullPath),
                line,
                snippet: match[0].substring(0, 200),
              };
            }
          }
        } catch {
          // skip
        }
      }
    };

    walkDir(rootPath);
    return result;
  }

  /**
   * Search for multiple patterns — returns evidence for the first match.
   */
  private findAnyCodeEvidence(
    context: AgentContext,
    patterns: Array<{ pattern: RegExp; description: string }>
  ): { file: string; line: number; snippet: string; description: string } | null {
    for (const { pattern, description } of patterns) {
      const evidence = this.findCodeEvidence(context, pattern);
      if (evidence) return { ...evidence, description };
    }
    return null;
  }

  // ─── IDOR Test ────────────────────────────────────────────────────

  private async testIDOR(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Guard: skip if app doesn't have auth
    if (context.appContext && !context.appContext.hasAuth) return findings;

    // Strategy 1: HTTP-based IDOR test (highest confidence)
    if (context.target.type !== 'directory') {
      const httpFindings = await this.testIDORViaHTTP(context);
      findings.push(...httpFindings);
    }

    // Strategy 2: AST-based IDOR detection (medium confidence)
    const codeIndex = (context as any).metadata?.codeIndex;
    if (context.target.type === 'directory' && codeIndex) {
      try {
        const { IDORDetector } = await import('../detectors/idor-detector.js');
        const detector = new IDORDetector(codeIndex);
        
        for (const handler of codeIndex.routeHandlers) {
          const result = detector.detect(handler);
          if (result) {
            findings.push(
              createFinding(this.id)
                .title(result.type === 'idor' ? 'Potential IDOR Vulnerability' : 'Broken Access Control')
                .description(
                  `${result.evidence.reasoning} found in ${result.evidence.file}:${result.evidence.line}. ` +
                  'Resources accessed by predictable IDs without proper authorization checks may allow ' +
                  'attackers to access or modify other users\' data by manipulating identifiers.'
                )
                .severity(result.severity)
                .cvssScore(result.severity === 'critical' ? 9.1 : 8.1)
                .category('A01_BROKEN_ACCESS_CONTROL')
                .confidence(result.confidence)
                .vcvfPattern('auth_authz_conflation')
                .evidence({
                  file: result.evidence.file,
                  line: result.evidence.line,
                  endLine: result.evidence.endLine,
                  snippet: result.evidence.snippet,
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
        }

        // Run ScopingGapDetector
        const { ScopingGapDetector } = await import('../detectors/scoping-gap-detector.js');
        const gapDetector = new ScopingGapDetector(codeIndex);
        const gaps = gapDetector.detectGaps();
        for (const gap of gaps) {
          findings.push(
            createFinding(this.id)
              .title('Vertical Scoping Gap / Broken Access Control')
              .description(
                `${gap.evidence.reasoning} in ${gap.evidence.file}:${gap.evidence.line}. ` +
                'Endpoints that do not enforce the same vertical scoping checks as sibling routes ' +
                'can be exploited to exfiltrate or modify records belonging to other departments.'
              )
              .severity(gap.severity)
              .cvssScore(8.1)
              .category('A01_BROKEN_ACCESS_CONTROL')
              .confidence(gap.confidence)
              .evidence({
                file: gap.evidence.file,
                line: gap.evidence.line,
                endLine: gap.evidence.endLine,
                snippet: gap.evidence.snippet,
              })
              .remediation({
                summary: 'Apply consistent scoping middleware to all endpoints in the controller.',
                steps: [
                  'Add vertical scoping middleware (e.g. scopeInventoryQuery) to the endpoint',
                  'Ensure all import/export/list/search routes have the same access policies',
                  'Implement role-based vertical scoping on the database level'
                ],
                effort: 'low',
                priority: 2,
              })
              .tags(['auth', 'scoping', 'access-control'])
              .build()
          );
        }
      } catch (e) {
        // AST detector error
      }
    }

    return findings;
  }

  /**
   * HTTP-based IDOR testing on live endpoints.
   * Only emits a finding if we get 200 + data without auth.
   */
  private async testIDORViaHTTP(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const baseUrl = context.target.url;
    const endpoints = context.reconData?.endpoints ?? [];
    const testIds = ['1', '2', '0'];

    for (const endpoint of endpoints) {
      const hasIdParam = endpoint.parameters?.some(p =>
        p.name.toLowerCase().includes('id') ||
        p.name.toLowerCase().includes('user')
      );

      if (hasIdParam || /\/:id|\/{id}|\/\d+/.test(endpoint.path)) {
        for (const testId of testIds.slice(0, 2)) {
          try {
            const testUrl = this.buildIdorTestUrl(baseUrl, endpoint, testId);
            const response = await this.httpClient.get(testUrl);

            // Only flag if we get actual data without auth
            if (response.status === 200 && response.body &&
                !response.body.includes('error') &&
                !response.body.includes('unauthorized') &&
                !response.body.includes('Unauthorized') &&
                response.body.length > 10) {
              findings.push(
                createFinding(this.id)
                  .title('Confirmed IDOR via HTTP Testing')
                  .description(
                    `Endpoint ${endpoint.method} ${endpoint.path} returned data when accessed with ID "${testId}" ` +
                    'without authentication. This confirms an Insecure Direct Object Reference vulnerability.'
                  )
                  .severity('critical')
                  .cvssScore(9.1)
                  .category('A01_BROKEN_ACCESS_CONTROL')
                  .confidence(0.95)
                  .evidence({
                    request: `${endpoint.method} ${testUrl}`,
                    response: response.body.substring(0, 500),
                    endpoints: [endpoint.path],
                  })
                  .remediation({
                    summary: 'Implement ownership verification for all ID-based endpoints.',
                    steps: [
                      'Add authentication middleware to all resource endpoints',
                      'Verify the requesting user owns the resource',
                      'Return 404 (not 403) for non-owned resources to prevent enumeration',
                    ],
                    effort: 'medium',
                    priority: 1,
                  })
                  .tags(['auth', 'idor', 'access-control', 'http-confirmed'])
                  .build()
              );
              break; // One confirmed finding per endpoint is enough
            }
          } catch {
            // Continue on error
          }
        }
      }
    }

    return findings;
  }

  private buildIdorTestUrl(baseUrl: string, endpoint: DiscoveredEndpoint, testId: string): string {
    const url = new URL(baseUrl);
    const path = endpoint.path.replace(/:id|{id}/g, testId);
    url.pathname = path;
    return url.toString();
  }

  // ─── Privilege Escalation Test ─────────────────────────────────────

  private async testPrivilegeEscalation(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Guard: skip if app doesn't have user roles
    if (context.appContext && !context.appContext.hasUserRoles) return findings;

    // Strategy 1: HTTP-based privilege escalation test (highest confidence)
    if (context.target.type !== 'directory') {
      const adminPaths = ['/admin', '/api/admin', '/api/admin/users', '/api/users', '/dashboard/admin'];
      const baseUrl = context.target.url;

      for (const path of adminPaths.slice(0, 3)) {
        try {
          const url = new URL(path, baseUrl).toString();
          const response = await this.httpClient.get(url);

          // If we get 200 on an admin endpoint without auth, that's privilege escalation
          if (response.status === 200 && response.body &&
              response.body.length > 10 &&
              !response.body.includes('login') &&
              !response.body.includes('sign in') &&
              !response.body.includes('unauthorized')) {
            findings.push(
              createFinding(this.id)
                .title('Confirmed Privilege Escalation: Admin Endpoint Accessible')
                .description(
                  `Admin endpoint ${path} returned 200 OK without authentication. ` +
                  'This confirms that admin-level resources are accessible to unauthenticated users.'
                )
                .severity('critical')
                .cvssScore(9.1)
                .category('A01_BROKEN_ACCESS_CONTROL')
                .confidence(0.95)
                .evidence({
                  request: `GET ${url}`,
                  response: response.body.substring(0, 500),
                  endpoints: [path],
                })
                .remediation({
                  summary: 'Add authentication and authorization middleware to admin endpoints.',
                  steps: [
                    'Add auth middleware that verifies JWT/session',
                    'Add role check middleware that verifies admin role',
                    'Return 401/403 for unauthorized requests',
                  ],
                  effort: 'low',
                  priority: 1,
                })
                .tags(['auth', 'authorization', 'privilege-escalation', 'http-confirmed'])
                .build()
            );
            break;
          }
        } catch {
          // continue
        }
      }
    }

    // Strategy 2: Code-based detection (fallback)
    const escalationEvidence = this.findAnyCodeEvidence(context, [
      {
        pattern: /(?:user\.role|isAdmin|hasRole)\s*===?\s*['"`]admin['"`]/i,
        description: 'Client-side admin role check without server-side verification',
      },
      {
        pattern: /(?:if\s*\(\s*(?:user\.role|isAdmin)\s*(?:===?\s*['"`]admin['"`])?\s*\)\s*{[^}]*(?:navigate|redirect|show))/i,
        description: 'Admin UI gated by client-side role check only',
      },
    ]);

    if (escalationEvidence) {
      findings.push(
        createFinding(this.id)
          .title('Client-Side Authorization Check')
          .description(
            `Found ${escalationEvidence.description} in ${escalationEvidence.file}:${escalationEvidence.line}. ` +
            'Authorization checks on the client side can be bypassed by modifying client-side code ' +
            'or making direct API requests.'
          )
          .severity('high')
          .cvssScore(8.1)
          .category('A01_BROKEN_ACCESS_CONTROL')
          .confidence(0.85)
          .vcvfPattern('auth_authz_conflation')
          .evidence({
            file: escalationEvidence.file,
            line: escalationEvidence.line,
            snippet: escalationEvidence.snippet,
          })
          .remediation({
            summary: 'Implement server-side authorization checks for all protected resources.',
            steps: [
              'Add role/permission checks on the server side for each endpoint',
              'Never trust client-side role information',
              'Use middleware or decorators for consistent authz enforcement',
            ],
            effort: 'medium',
            priority: 2,
          })
          .tags(['auth', 'authorization', 'idor', 'client-side'])
          .build()
      );
    }

    return findings;
  }

  // ─── Session Management Test ───────────────────────────────────────

  private async testSessionManagement(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Guard: skip if no auth
    if (context.appContext && !context.appContext.hasAuth) return findings;

    const codeIndex = (context as any).metadata?.codeIndex;
    let hasLocalstorageFinding = false;

    if (context.target.type === 'directory' && codeIndex) {
      try {
        const { SessionStorageDetector } = await import('../detectors/session-storage-detector.js');
        const detector = new SessionStorageDetector(codeIndex);
        for (const [filePath] of codeIndex.files) {
          const result = detector.detectInFile(filePath);
          if (result) {
            hasLocalstorageFinding = true;
            findings.push(
              createFinding(this.id)
                .title('Insecure Session Token Storage')
                .description(
                  `${result.evidence.reasoning} found in ${result.evidence.file}:${result.evidence.line}. ` +
                  'Storing session tokens in localStorage makes them accessible to XSS attacks.'
                )
                .severity('high')
                .cvssScore(7.5)
                .category('A07_AUTH_FAILURES')
                .confidence(0.9)
                .evidence({
                  file: result.evidence.file,
                  line: result.evidence.line,
                  snippet: result.evidence.snippet,
                })
                .remediation({
                  summary: 'Store session tokens securely using HttpOnly cookies.',
                  steps: [
                    'Use HttpOnly, Secure, SameSite cookies for session tokens',
                    'Never store tokens in localStorage',
                    'Implement session expiration and rotation',
                    'Use a secure session store on the server',
                  ],
                  effort: 'medium',
                  priority: 2,
                })
                .tags(['auth', 'session', 'session-management', 'xss'])
                .build()
            );
            break; // only report one instance
          }
        }
      } catch (e) {
        // skip AST error
      }
    }

    // Only run regex fallback if we didn't find localStorage via AST
    if (!hasLocalstorageFinding) {
      const cookieEvidence = this.findCodeEvidence(
        context,
        /(?:document\.cookie|setCookie)\s*[=(].*(?:token|session|auth).*[^;]\s*$/im
      );

      if (cookieEvidence) {
        findings.push(
          createFinding(this.id)
            .title('Insecure Session Token Storage')
            .description(
              `Found Session cookie set without security flags (HttpOnly, Secure, SameSite) in ${cookieEvidence.file}:${cookieEvidence.line}. ` +
              'Cookies without security flags can be stolen or manipulated.'
            )
            .severity('high')
            .cvssScore(7.5)
            .category('A07_AUTH_FAILURES')
            .confidence(0.8)
            .evidence({
              file: cookieEvidence.file,
              line: cookieEvidence.line,
              snippet: cookieEvidence.snippet,
            })
            .remediation({
              summary: 'Store session tokens securely using HttpOnly cookies.',
              steps: [
                'Use HttpOnly, Secure, SameSite cookies for session tokens',
                'Never store tokens in localStorage',
                'Implement session expiration and rotation',
                'Use a secure session store on the server',
              ],
              effort: 'medium',
              priority: 2,
            })
            .tags(['auth', 'session', 'session-management', 'xss'])
            .build()
        );
      }
    }

    return findings;
  }

  // ─── OAuth Flow Test ───────────────────────────────────────────────

  private async testOAuthFlows(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Guard: skip if no auth or no OAuth endpoints found
    if (context.appContext && !context.appContext.hasAuth) return findings;
    const hasOAuthEndpoints = context.reconData?.authMechanisms.some(a => a.type === 'oauth');
    const hasOAuthCode = this.findCodeEvidence(context, /passport\.(?:use|authenticate)|new\s+(?:OAuth|Google|GitHub)Strategy|next-auth|openid-client/i);
    if (!hasOAuthEndpoints && !hasOAuthCode) return findings;

    // Check for missing state parameter validation (CSRF in OAuth)
    const oauthEvidence = this.findAnyCodeEvidence(context, [
      {
        // OAuth callback without state validation
        pattern: /(?:callback|redirect).*oauth.*(?:req\.query\.code|req\.query\.state)(?!.*(?:verify|validate|check).*state)/i,
        description: 'OAuth callback processing without state parameter validation',
      },
      {
        // OAuth without PKCE
        pattern: /(?:authorization_code|oauth).*(?!.*code_challenge|code_verifier)/i,
        description: 'OAuth flow without PKCE protection',
      },
    ]);

    if (oauthEvidence) {
      findings.push(
        createFinding(this.id)
          .title('OAuth Flow Vulnerability')
          .description(
            `Found ${oauthEvidence.description} in ${oauthEvidence.file}:${oauthEvidence.line}. ` +
            'OAuth callbacks without state parameter validation are vulnerable to CSRF attacks ' +
            'where an attacker can link their account to a victim\'s session.'
          )
          .severity('high')
          .cvssScore(7.5)
          .category('A07_AUTH_FAILURES')
          .confidence(0.8)
          .evidence({
            file: oauthEvidence.file,
            line: oauthEvidence.line,
            snippet: oauthEvidence.snippet,
          })
          .remediation({
            summary: 'Validate OAuth state parameter and implement PKCE.',
            steps: [
              'Validate OAuth state parameter on callback',
              'Implement PKCE for additional security',
              'Validate redirect URIs against a whitelist',
            ],
            effort: 'medium',
            priority: 2,
          })
          .tags(['auth', 'oauth', 'flow', 'csrf'])
          .build()
      );
    }

    return findings;
  }

  // ─── JWT Security Test ────────────────────────────────────────────

  private async testJWTSecurity(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Guard: skip if no auth
    if (context.appContext && !context.appContext.hasAuth) return findings;

    // Strategy 1: HTTP-based JWT alg:none attack (highest confidence)
    if (context.target.type !== 'directory') {
      const authEndpoints = context.reconData?.endpoints.filter(e =>
        /\/(?:api|auth|login|protected|me|profile|admin)/i.test(e.path)
      ) ?? [];

      for (const endpoint of authEndpoints.slice(0, 3)) {
        try {
          // First, try to get a response that reveals JWT structure
          const url = `${context.target.url}${endpoint.path}`;
          const response = await this.httpClient.get(url);

          // Look for JWT in response headers or body
          const authHeader = response.headers?.['authorization'] ?? response.headers?.['www-authenticate'] ?? '';
          const jwtMatch = (response.body + authHeader).match(/eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/);

          if (jwtMatch) {
            // Try alg:none attack: decode the JWT, change header to alg:none, strip signature
            try {
              const parts = jwtMatch[0].split('.');
              const header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString());

              if (header.alg && header.alg !== 'none') {
                // Create alg:none variant
                const noneHeader = Buffer.from(JSON.stringify({ ...header, alg: 'none' })).toString('base64url');
                const noneToken = `${noneHeader}.${parts[1]}.`;

                // Try to access a protected endpoint with the alg:none token
                const testResponse = await this.httpClient.get(url, {
                  'Authorization': `Bearer ${noneToken}`,
                });

                if (testResponse.status === 200 && testResponse.body &&
                    !testResponse.body.includes('error') &&
                    !testResponse.body.includes('unauthorized') &&
                    !testResponse.body.includes('Invalid')) {
                  findings.push(
                    createFinding(this.id)
                      .title('Confirmed JWT alg:none Bypass')
                      .description(
                        `JWT alg:none attack succeeded on ${endpoint.path}. ` +
                        'The server accepted a JWT with algorithm set to "none" and no signature. ' +
                        'Attackers can forge arbitrary JWTs and impersonate any user.'
                      )
                      .severity('critical')
                      .cvssScore(9.8)
                      .category('A07_AUTH_FAILURES')
                      .confidence(0.98)
                      .evidence({
                        request: `GET ${url} with alg:none JWT`,
                        response: testResponse.body.substring(0, 500),
                        endpoints: [endpoint.path],
                      })
                      .remediation({
                        summary: 'Explicitly reject JWTs with alg:none and validate algorithm server-side.',
                        steps: [
                          'Explicitly set allowed algorithms in jwt.verify: { algorithms: [\'RS256\'] }',
                          'Never allow \'none\' algorithm',
                          'Validate iss, aud, exp claims',
                        ],
                        effort: 'low',
                        priority: 1,
                      })
                      .tags(['auth', 'jwt', 'alg-none', 'http-confirmed', 'critical'])
                      .build()
                  );
                  break;
                }
              }
            } catch {
              // JWT decode failed, continue
            }
          }
        } catch {
          // continue
        }
      }
    }

    // Strategy 2: Code-based detection
    const jwtEvidence = this.findAnyCodeEvidence(context, [
      {
        pattern: /(?:algorithms?\s*:\s*\[.*['"`]none['"`]|alg\s*===?\s*['"`]none['"`])/i,
        description: 'JWT accepts "none" algorithm (signature bypass)',
      },
      {
        pattern: /(?:jwt\.verify|jose\.jwtVerify|jsonwebtoken\.verify)\(.*ignoreExpiration\s*:\s*true/i,
        description: 'JWT verified with ignored expiration check',
      },
      {
        pattern: /(?:jwt[_-]?secret|JWT_SECRET)\s*[:=]\s*['"`][^'"`]{8,}['"`]/i,
        description: 'JWT signing secret hardcoded in source code',
      },
    ]);

    if (jwtEvidence) {
      findings.push(
        createFinding(this.id)
          .title('JWT Security Weakness')
          .description(
            `Found ${jwtEvidence.description} in ${jwtEvidence.file}:${jwtEvidence.line}. ` +
            'JWT implementation weaknesses can allow attackers to forge tokens, ' +
            'bypass authentication, or escalate privileges.'
          )
          .severity('critical')
          .cvssScore(9.1)
          .category('A07_AUTH_FAILURES')
          .confidence(0.9)
          .evidence({
            file: jwtEvidence.file,
            line: jwtEvidence.line,
            snippet: jwtEvidence.snippet,
          })
          .remediation({
            summary: 'Fix JWT implementation to use strong algorithms and validate all claims.',
            steps: [
              'Use RS256 or ES256 algorithm (never "none")',
              'Always validate exp, iss, aud, and nbf claims',
              'Store JWT secrets in environment variables, never in code',
              'Implement token refresh mechanism',
            ],
            effort: 'medium',
            priority: 1,
          })
          .tags(['auth', 'jwt', 'token', 'crypto'])
          .build()
      );
    }

    return findings;
  }

  // ─── Password Reset Test ──────────────────────────────────────────

  private async testPasswordReset(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Guard: skip if no auth
    if (context.appContext && !context.appContext.hasAuth) return findings;

    // Only test if password reset endpoints are discovered
    const hasResetEndpoint = context.reconData?.endpoints.some(e =>
      /(?:reset|forgot|recover)/i.test(e.path)
    );
    const hasResetCode = this.findCodeEvidence(context, /(?:resetPassword|forgotPassword|sendResetEmail|reset.*token)/i);
    if (!hasResetEndpoint && !hasResetCode) return findings;

    // Check for specific password reset weaknesses
    const resetEvidence = this.findAnyCodeEvidence(context, [
      {
        // Password reset without rate limiting
        pattern: /(?:resetPassword|forgotPassword|sendResetEmail)\s*\([^)]*\)\s*{[^}]*(?!.*rateLimit|rate.?limit|throttle)/i,
        description: 'Password reset endpoint without rate limiting',
      },
      {
        // Reset token not invalidated after use
        pattern: /(?:resetToken|reset_token).*(?:used|consumed|invalidated)(?!)/i,
        description: 'Reset token may not be invalidated after use',
      },
      {
        // User enumeration via reset response
        pattern: /(?:resetPassword|forgotPassword).*res\.(?:json|send)\s*\(\s*{[^}]*(?:exists|found|not.?found|invalid.?email)/i,
        description: 'Password reset reveals whether email exists (user enumeration)',
      },
    ]);

    if (resetEvidence) {
      findings.push(
        createFinding(this.id)
          .title('Password Reset Vulnerability')
          .description(
            `Found ${resetEvidence.description} in ${resetEvidence.file}:${resetEvidence.line}. ` +
            'Weak password reset implementation can allow user enumeration, brute force, ' +
            'or account takeover attacks.'
          )
          .severity('high')
          .cvssScore(8.1)
          .category('A07_AUTH_FAILURES')
          .confidence(0.8)
          .evidence({
            file: resetEvidence.file,
            line: resetEvidence.line,
            snippet: resetEvidence.snippet,
          })
          .remediation({
            summary: 'Implement secure password reset with rate limiting and proper token handling.',
            steps: [
              'Rate limit password reset requests per IP and email',
              'Use time-limited, single-use reset tokens',
              'Generate cryptographically secure random tokens',
              'Always return the same response regardless of email existence',
              'Invalidate old tokens when new ones are requested',
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
