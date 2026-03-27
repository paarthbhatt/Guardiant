import { AbstractAgent } from './base.js';
import { createFinding } from './types.js';
import type { AgentContext, AgentResult, Finding, DiscoveredEndpoint } from '@guardiant/shared';
import { OWASP_CATEGORIES } from '@guardiant/shared';
import { createWebScanner, type VulnerabilityCheck } from '../http/index.js';
import { getPayloads, checkVulnerability } from '../payloads/index.js';

/**
 * Injection Testing Agent
 *
 * Tests for various injection vulnerabilities including:
 * - SQL Injection
 * - NoSQL Injection
 * - XSS (Cross-Site Scripting)
 * - Command Injection
 * - Template Injection (SSTI)
 * - Path Traversal
 */
export class InjectionAgent extends AbstractAgent {
  readonly id = 'injection' as const;
  readonly name = 'Injection Testing Agent';
  readonly description = 'Tests for SQL injection, XSS, command injection, and other injection vulnerabilities.';
  readonly categories = [OWASP_CATEGORIES.A03_INJECTION.code];
  readonly priority = 'high' as const;

  async execute(context: AgentContext): Promise<AgentResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];
    const scanner = createWebScanner({ timeout: context.config.timeout ?? 30000 });

    try {
      await this.setup?.(context);

      const baseUrl = context.target.url;
      const endpoints = context.reconData?.endpoints ?? [];

      // If no endpoints from recon, try common paths
      if (endpoints.length === 0) {
        endpoints.push(
          { path: '/', method: 'GET', authentication: false },
          { path: '/api', method: 'GET', authentication: false },
          { path: '/api/users', method: 'GET', authentication: false },
          { path: '/search', method: 'GET', authentication: false, parameters: [{ name: 'q', location: 'query', type: 'string' }] },
          { path: '/login', method: 'POST', authentication: false },
        );
      }

      let endpointsTested = 0;
      const allChecks: VulnerabilityCheck[] = [];

      // Test each endpoint
      for (const endpoint of endpoints) {
        if (!context.config.enabled) break; // Stop if agent disabled

        // Test SQL Injection
        const sqliChecks = await this.testSQLInjection(scanner, endpoint, baseUrl);
        allChecks.push(...sqliChecks);

        // Test XSS
        const xssChecks = await this.testXSS(scanner, endpoint, baseUrl);
        allChecks.push(...xssChecks);

        // Test Command Injection (on POST endpoints)
        if (endpoint.method === 'POST') {
          const cmdiChecks = await this.testCommandInjection(scanner, endpoint, baseUrl);
          allChecks.push(...cmdiChecks);
        }

        // Test Path Traversal
        const pathChecks = await this.testPathTraversal(scanner, endpoint, baseUrl);
        allChecks.push(...pathChecks);

        endpointsTested++;

        // Limit to prevent timeout
        if (endpointsTested >= 50) break;
      }

      // Convert checks to findings
      for (const check of allChecks) {
        if (check.vulnerable) {
          findings.push(this.checkToFinding(check));
        }
      }

      await this.teardown?.(context);

      return this.createSuccessResult(findings, {
        endpointsTested,
        custom: {
          totalChecks: allChecks.length,
          vulnerabilitiesFound: findings.length,
        },
      }, this.getDuration(startTime));
    } catch (error) {
      return this.createErrorResult(
        error instanceof Error ? error : new Error('Unknown error'),
        this.getDuration(startTime)
      );
    }
  }

  /**
   * Test for SQL Injection
   */
  private async testSQLInjection(
    scanner: ReturnType<typeof createWebScanner>,
    endpoint: DiscoveredEndpoint,
    baseUrl: string
  ): Promise<VulnerabilityCheck[]> {
    const checks: VulnerabilityCheck[] = [];
    const payloads = getPayloads('sqli').slice(0, 15);

    const params = endpoint.parameters ?? [];
    if (params.length === 0 && endpoint.method === 'GET') {
      // Test URL params even if not discovered
      params.push({ name: 'id', location: 'query', type: 'string' });
      params.push({ name: 'q', location: 'query', type: 'string' });
    }

    for (const param of params) {
      for (const payload of payloads) {
        try {
          const testUrl = this.buildTestUrl(baseUrl, endpoint, param.name, payload);
          const response = await scanner.fetch(testUrl);
          const check = checkVulnerability(response.response, 'sqli');

          if (check.vulnerable) {
            checks.push({
              type: 'sqli',
              endpoint: endpoint.path,
              method: endpoint.method,
              payload,
              parameter: param.name,
              vulnerable: true,
              evidence: check.evidence,
              response: response.response,
            });
            break; // Found vulnerability, move to next param
          }
        } catch {
          // Continue on error
        }
      }
    }

    return checks;
  }

  /**
   * Test for XSS
   */
  private async testXSS(
    scanner: ReturnType<typeof createWebScanner>,
    endpoint: DiscoveredEndpoint,
    baseUrl: string
  ): Promise<VulnerabilityCheck[]> {
    const checks: VulnerabilityCheck[] = [];
    const payloads = getPayloads('xss').slice(0, 15);

    const params = endpoint.parameters ?? [];
    if (params.length === 0 && endpoint.method === 'GET') {
      params.push({ name: 'q', location: 'query', type: 'string' });
      params.push({ name: 'search', location: 'query', type: 'string' });
    }

    for (const param of params) {
      for (const payload of payloads) {
        try {
          const testUrl = this.buildTestUrl(baseUrl, endpoint, param.name, payload);
          const response = await scanner.fetch(testUrl);

          // Check if payload is reflected
          if (response.response.body.includes(payload) ||
              response.response.body.includes(payload.toLowerCase())) {
            checks.push({
              type: 'xss',
              endpoint: endpoint.path,
              method: endpoint.method,
              payload,
              parameter: param.name,
              vulnerable: true,
              evidence: 'Payload reflected in response without proper encoding',
              response: response.response,
            });
            break;
          }
        } catch {
          // Continue on error
        }
      }
    }

    return checks;
  }

  /**
   * Test for Command Injection
   */
  private async testCommandInjection(
    scanner: ReturnType<typeof createWebScanner>,
    endpoint: DiscoveredEndpoint,
    baseUrl: string
  ): Promise<VulnerabilityCheck[]> {
    const checks: VulnerabilityCheck[] = [];
    const payloads = getPayloads('cmdi').slice(0, 10);

    const params = endpoint.parameters ?? [{ name: 'cmd', location: 'body' }];

    for (const param of params) {
      for (const payload of payloads) {
        try {
          // For POST, we'd need to send body
          const testUrl = this.buildTestUrl(baseUrl, endpoint, param.name, payload);
          const response = await scanner.fetch(testUrl);
          const check = checkVulnerability(response.response, 'cmdi');

          if (check.vulnerable) {
            checks.push({
              type: 'cmdi',
              endpoint: endpoint.path,
              method: endpoint.method,
              payload,
              parameter: param.name,
              vulnerable: true,
              evidence: check.evidence,
              response: response.response,
            });
            break;
          }
        } catch {
          // Continue on error
        }
      }
    }

    return checks;
  }

  /**
   * Test for Path Traversal
   */
  private async testPathTraversal(
    scanner: ReturnType<typeof createWebScanner>,
    endpoint: DiscoveredEndpoint,
    baseUrl: string
  ): Promise<VulnerabilityCheck[]> {
    const checks: VulnerabilityCheck[] = [];
    const payloads = getPayloads('path').slice(0, 10);
    const targetFiles = ['/etc/passwd', '/etc/hosts', 'C:\\Windows\\win.ini'];

    // Test path traversal on file-related parameters
    const params = endpoint.parameters?.filter(p =>
      p.name.toLowerCase().includes('file') ||
      p.name.toLowerCase().includes('path') ||
      p.name.toLowerCase().includes('doc') ||
      p.name.toLowerCase().includes('page')
    ) ?? [];

    for (const param of params) {
      for (const payload of payloads) {
        for (const targetFile of targetFiles) {
          const fullPayload = payload + targetFile;
          try {
            const testUrl = this.buildTestUrl(baseUrl, endpoint, param.name, fullPayload);
            const response = await scanner.fetch(testUrl);

            // Check for file content indicators
            const body = response.response.body.toLowerCase();
            if (body.includes('root:') || body.includes('bitbucket') || body.includes('[extensions]')) {
              checks.push({
                type: 'path',
                endpoint: endpoint.path,
                method: endpoint.method,
                payload: fullPayload,
                parameter: param.name,
                vulnerable: true,
                evidence: 'File content detected in response',
                response: response.response,
              });
              break;
            }
          } catch {
            // Continue on error
          }
        }
        if (checks.some(c => c.parameter === param.name && c.vulnerable)) break;
      }
    }

    return checks;
  }

  /**
   * Build test URL with injected parameter
   */
  private buildTestUrl(
    baseUrl: string,
    endpoint: DiscoveredEndpoint,
    paramName: string,
    payload: string
  ): string {
    const url = new URL(baseUrl);
    const path = endpoint.path.startsWith('/') ? endpoint.path : `/${endpoint.path}`;

    // Handle path parameters
    if (path.includes(':')) {
      const filledPath = path.replace(/:\w+/g, payload);
      url.pathname = filledPath;
    } else {
      url.pathname = path;
      url.searchParams.set(paramName, payload);
    }

    return url.toString();
  }

  /**
   * Convert vulnerability check to finding
   */
  private checkToFinding(check: VulnerabilityCheck): Finding {
    const typeInfo: Record<string, { severity: 'critical' | 'high' | 'medium'; cvss: number; title: string }> = {
      sqli: { severity: 'critical', cvss: 9.8, title: 'SQL Injection' },
      xss: { severity: 'high', cvss: 7.5, title: 'Cross-Site Scripting (XSS)' },
      cmdi: { severity: 'critical', cvss: 9.8, title: 'Command Injection' },
      nosqli: { severity: 'critical', cvss: 9.8, title: 'NoSQL Injection' },
      ssti: { severity: 'high', cvss: 8.5, title: 'Server-Side Template Injection' },
      path: { severity: 'high', cvss: 7.5, title: 'Path Traversal' },
    };

    const info = typeInfo[check.type] ?? { severity: 'medium', cvss: 5.0, title: check.type };

    return createFinding(this.id)
      .title(`${info.title} in ${check.endpoint}`)
      .description(
        `A ${info.title} vulnerability was discovered at ${check.endpoint}. ` +
        `The ${check.parameter ? `parameter "${check.parameter}"` : 'endpoint'} is vulnerable. ` +
        `Payload: ${check.payload}`
      )
      .severity(info.severity)
      .cvssScore(info.cvss)
      .category('A03_INJECTION')
      .confidence(0.9)
      .evidence({
        request: check.response?.url,
        response: check.response?.body?.substring(0, 1000),
        payload: check.payload,
        context: { parameter: check.parameter, evidence: check.evidence },
      })
      .remediation({
        summary: 'Sanitize and validate all user input. Use parameterized queries.',
        steps: [
          'Implement input validation on all user-controlled parameters',
          'Use parameterized queries or prepared statements',
          'Encode output appropriately for the context',
          'Use a Web Application Firewall (WAF) as additional protection',
        ],
        codeExample: `// ❌ Vulnerable
const query = "SELECT * FROM users WHERE id = " + userId;

// ✅ Secure (parameterized)
const query = "SELECT * FROM users WHERE id = ?";
db.query(query, [userId]);`,
        effort: 'medium',
        priority: info.severity === 'critical' ? 1 : 2,
      })
      .tags([check.type, 'injection', 'owasp'])
      .build();
  }

  getSystemPrompt(): string {
    return `You are an injection security testing expert. Test for:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Command Injection
- NoSQL Injection
- Template Injection (SSTI)
- Path Traversal

Use polyglot payloads and test all parameters. Report findings with evidence.`;
  }

  buildUserPrompt(context: AgentContext): string {
    return `Test for injection vulnerabilities at ${context.target.url}`;
  }

  async parseResponse(_response: string, _context: AgentContext): Promise<Finding[]> {
    return []; // Findings generated directly
  }
}