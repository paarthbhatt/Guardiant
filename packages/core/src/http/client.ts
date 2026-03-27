import { createHttpClient, isUrlReachable, type HttpResponse } from './index.js';
import { getPayloads, checkVulnerability } from './payloads.js';
import type { Finding, DiscoveredEndpoint, OWASPCategory } from '@guardiant/shared';
import { createFinding } from '../agents/types.js';

export interface ScannerConfig {
  timeout: number;
  maxRetries: number;
  concurrency: number;
  userAgent: string;
  followRedirects: boolean;
  validateSSL: boolean;
}

export const DEFAULT_SCANNER_CONFIG: ScannerConfig = {
  timeout: 30000,
  maxRetries: 2,
  concurrency: 5,
  userAgent: 'Guardiant/0.1.0 Security Scanner',
  followRedirects: true,
  validateSSL: false,
};

export interface ScanResult {
  url: string;
  response: HttpResponse;
  duration: number;
  error?: string;
}

export interface VulnerabilityCheck {
  type: 'sqli' | 'xss' | 'cmdi' | 'nosqli' | 'ssti' | 'path' | 'auth' | 'idor';
  endpoint: string;
  method: string;
  payload?: string;
  parameter?: string;
  vulnerable: boolean;
  evidence?: string;
  response?: HttpResponse;
}

/**
 * Web application scanner
 */
export class WebScanner {
  private httpClient: ReturnType<typeof createHttpClient>;
  private config: ScannerConfig;

  constructor(config: Partial<ScannerConfig> = {}) {
    this.config = { ...DEFAULT_SCANNER_CONFIG, ...config };
    this.httpClient = createHttpClient(this.config.timeout);
  }

  /**
   * Fetch a URL
   */
  async fetch(url: string, headers?: Record<string, string>): Promise<ScanResult> {
    const startTime = Date.now();
    try {
      const response = await this.httpClient.get(url, headers);
      return {
        url,
        response,
        duration: Date.now() - startTime,
      };
    } catch (error) {
      return {
        url,
        response: { status: 0, statusText: '', headers: {}, body: '', duration: Date.now() - startTime, url },
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Check if target is reachable
   */
  async isReachable(url: string): Promise<boolean> {
    return isUrlReachable(url, this.config.timeout);
  }

  /**
   * Discover endpoints from HTML
   */
  discoverEndpoints(html: string, baseUrl: string): DiscoveredEndpoint[] {
    const endpoints: DiscoveredEndpoint[] = [];
    const url = new URL(baseUrl);

    // Find links
    const linkRegex = /href=["']([^"']+)["']/gi;
    let match;
    while ((match = linkRegex.exec(html)) !== null) {
      const href = match[1];
      try {
        const fullUrl = new URL(href as string, baseUrl);
        if (fullUrl.origin === url.origin) {
          endpoints.push({
            path: fullUrl.pathname + fullUrl.search,
            method: 'GET',
            authentication: false,
          });
        }
      } catch {
        // Invalid URL
      }
    }

    // Find forms
    const formRegex = /<form[^>]+action=["']([^"']+)["'][^>]*>/gi;
    while ((match = formRegex.exec(html)) !== null) {
      const action = match[1];
      const formHtml = html.substring(match.index);
      const methodMatch = formHtml.match(/method=["']([^"']+)["']/i);
      const method = methodMatch?.[1]?.toUpperCase() ?? 'GET';

      try {
        const fullUrl = new URL(action as string, baseUrl);
        const params: DiscoveredEndpoint['parameters'] = [];

        // Find form inputs
        const inputRegex = /<input[^>]+name=["']([^"']+)["']/gi;
        let inputMatch;
        while ((inputMatch = inputRegex.exec(formHtml)) !== null) {
          const inputName = inputMatch[1];
          if (inputName) {
            params.push({
              name: inputName,
              location: 'body',
              type: 'string',
            });
          }
        }

        endpoints.push({
          path: fullUrl.pathname,
          method: (method as string).toUpperCase() as DiscoveredEndpoint['method'],
          parameters: params,
          authentication: false,
        });
      } catch {
        // Invalid URL
      }
    }

    // Find API endpoints in JavaScript
    const apiRegex = /["']\/api\/([^"']+)["']/gi;
    while ((match = apiRegex.exec(html)) !== null) {
      endpoints.push({
        path: `/api/${match[1]}`,
        method: 'GET',
        authentication: true,
      });
    }

    // Deduplicate
    const unique = new Map<string, DiscoveredEndpoint>();
    for (const ep of endpoints) {
      const key = `${ep.method}:${ep.path}`;
      if (!unique.has(key)) {
        unique.set(key, ep);
      }
    }

    return Array.from(unique.values());
  }

  /**
   * Test for SQL injection
   */
  async testSQLInjection(
    endpoint: DiscoveredEndpoint,
    baseUrl: string
  ): Promise<VulnerabilityCheck[]> {
    const results: VulnerabilityCheck[] = [];
    const payloads = getPayloads('sqli').slice(0, 10); // Limit for performance

    for (const param of endpoint.parameters ?? []) {
      for (const payload of payloads) {
        const testUrl = this.injectParameter(baseUrl + endpoint.path, param.name, payload);
        try {
          const response = await this.httpClient.get(testUrl);
          const check = checkVulnerability(response, 'sqli');

          if (check.vulnerable) {
            results.push({
              type: 'sqli',
              endpoint: endpoint.path,
              method: endpoint.method,
              payload,
              parameter: param.name,
              vulnerable: true,
              evidence: check.evidence,
              response,
            });
            // Found vulnerability, no need to test more payloads for this param
            break;
          }
        } catch {
          // Continue on error
        }
      }
    }

    return results;
  }

  /**
   * Test for XSS
   */
  async testXSS(
    endpoint: DiscoveredEndpoint,
    baseUrl: string
  ): Promise<VulnerabilityCheck[]> {
    const results: VulnerabilityCheck[] = [];
    const payloads = getPayloads('xss').slice(0, 10);

    for (const param of endpoint.parameters ?? []) {
      for (const payload of payloads) {
        const testUrl = this.injectParameter(baseUrl + endpoint.path, param.name, payload);
        try {
          const response = await this.httpClient.get(testUrl);
          const check = checkVulnerability(response, 'xss');

          if (check.vulnerable) {
            results.push({
              type: 'xss',
              endpoint: endpoint.path,
              method: endpoint.method,
              payload,
              parameter: param.name,
              vulnerable: true,
              evidence: check.evidence,
              response,
            });
            break;
          }
        } catch {
          // Continue on error
        }
      }
    }

    return results;
  }

  /**
   * Inject parameter value
   */
  private injectParameter(url: string, param: string, value: string): string {
    const parsedUrl = new URL(url);
    if (parsedUrl.searchParams.has(param)) {
      parsedUrl.searchParams.set(param, value);
    } else {
      parsedUrl.searchParams.append(param, value);
    }
    return parsedUrl.toString();
  }

  /**
   * Convert vulnerability check to finding
   */
  checkToFinding(check: VulnerabilityCheck, agentId: string): Finding {
    const severityMap: Record<string, 'critical' | 'high' | 'medium' | 'low'> = {
      sqli: 'critical',
      xss: 'high',
      cmdi: 'critical',
      nosqli: 'critical',
      ssti: 'high',
      path: 'high',
      auth: 'critical',
      idor: 'high',
    };

    const categoryMap: Record<string, string> = {
      sqli: 'A03_INJECTION',
      xss: 'A03_INJECTION',
      cmdi: 'A03_INJECTION',
      nosqli: 'A03_INJECTION',
      ssti: 'A03_INJECTION',
      path: 'A01_BROKEN_ACCESS_CONTROL',
      auth: 'A07_AUTH_FAILURES',
      idor: 'A01_BROKEN_ACCESS_CONTROL',
    };

    const typeNames: Record<string, string> = {
      sqli: 'SQL Injection',
      xss: 'Cross-Site Scripting (XSS)',
      cmdi: 'Command Injection',
      nosqli: 'NoSQL Injection',
      ssti: 'Server-Side Template Injection',
      path: 'Path Traversal',
      auth: 'Authentication Bypass',
      idor: 'Insecure Direct Object Reference',
    };

    return createFinding(agentId)
      .title(`${typeNames[check.type] || check.type} in ${check.endpoint}`)
      .description(
        `A ${typeNames[check.type] || check.type} vulnerability was discovered at ${check.endpoint}. ` +
        `The ${check.parameter ? `parameter "${check.parameter}"` : 'endpoint'} is vulnerable to ${check.type} attacks.`
      )
      .severity(severityMap[check.type] ?? 'medium')
      .category((categoryMap[check.type] as OWASPCategory) ?? 'A03_INJECTION')
      .cvssScore(check.type === 'sqli' || check.type === 'cmdi' ? 9.8 : 7.5)
      .confidence(0.85)
      .evidence({
        request: check.response?.url,
        payload: check.payload,
        response: check.response?.body?.substring(0, 500),
        context: { parameter: check.parameter, evidence: check.evidence },
      })
      .remediation({
        summary: `Sanitize and validate all user input. Use parameterized queries/prepared statements.`,
        steps: [
          'Implement input validation on all user-controlled parameters',
          'Use parameterized queries or prepared statements',
          'Encode output appropriately for the context',
          'Implement proper error handling without exposing sensitive information',
        ],
        effort: 'medium',
        priority: check.type === 'sqli' || check.type === 'cmdi' ? 1 : 2,
      })
      .tags([check.type, 'injection', 'security'])
      .build();
  }
}

/**
 * Create web scanner
 */
export function createWebScanner(config?: Partial<ScannerConfig>): WebScanner {
  return new WebScanner(config);
}