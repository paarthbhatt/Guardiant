import { createHttpClient, isUrlReachable, type HttpResponse } from '../http/index.js';
import { getPayloads, checkVulnerability } from '../payloads/index.js';
import type { DiscoveredEndpoint, Finding, OWASPCategory } from '@guardiant/shared';
import { createFinding } from '../agents/types.js';

export interface ScannerConfig {
  timeout: number;
  maxRetries: number;
  concurrency: number;
  userAgent: string;
}

export const DEFAULT_SCANNER_CONFIG: ScannerConfig = {
  timeout: 30000,
  maxRetries: 2,
  concurrency: 5,
  userAgent: 'Guardiant/0.1.0 Security Scanner',
};

export interface ScanResult {
  url: string;
  response: HttpResponse;
  duration: number;
  error?: string;
}

export interface VulnerabilityCheck {
  type: 'sqli' | 'xss' | 'cmdi' | 'nosqli' | 'ssti' | 'path' | 'auth';
  endpoint: string;
  method: string;
  payload?: string;
  parameter?: string;
  vulnerable: boolean;
  evidence?: string;
  response?: HttpResponse;
}

export class WebScanner {
  private httpClient: ReturnType<typeof createHttpClient>;
  private config: ScannerConfig;

  constructor(config: Partial<ScannerConfig> = {}) {
    this.config = { ...DEFAULT_SCANNER_CONFIG, ...config };
    this.httpClient = createHttpClient(this.config.timeout);
  }

  async fetch(url: string): Promise<ScanResult> {
    const startTime = Date.now();
    try {
      const response = await this.httpClient.get(url);
      return { url, response, duration: Date.now() - startTime };
    } catch (error) {
      return { url, response: {} as HttpResponse, duration: Date.now() - startTime, error: error instanceof Error ? error.message : 'Unknown' };
    }
  }

  async isReachable(url: string): Promise<boolean> {
    return isUrlReachable(url, this.config.timeout);
  }

  discoverEndpoints(html: string, baseUrl: string): DiscoveredEndpoint[] {
    const endpoints: DiscoveredEndpoint[] = [];
    const url = new URL(baseUrl);
    const seen = new Set<string>();

    const addEndpoint = (path: string, method: DiscoveredEndpoint['method'] = 'GET') => {
      const key = `${method}:${path}`;
      if (!seen.has(key)) {
        seen.add(key);
        endpoints.push({ path, method, authentication: false });
      }
    };

    // Extract links
    const linkRegex = /(?:href|src)=["']([^"']+)["']/gi;
    let match;
    while ((match = linkRegex.exec(html)) !== null) {
      try {
        const href = match[1];
        if (!href) continue;
        if (href.startsWith('/') || href.startsWith(url.origin)) {
          addEndpoint(href.startsWith('/') ? href : new URL(href).pathname);
        }
      } catch {}
    }

    // Extract API routes
    const apiRegex = /["']\/api\/([^"']+)["']/gi;
    while ((match = apiRegex.exec(html)) !== null) {
      addEndpoint(`/api/${match[1]}`);
    }

    return endpoints;
  }

  async testInjection(endpoint: string, param: string, type: 'sqli' | 'xss' | 'cmdi', baseUrl: string): Promise<VulnerabilityCheck[]> {
    const results: VulnerabilityCheck[] = [];
    const payloads = getPayloads(type).slice(0, 5);

    for (const payload of payloads) {
      const testUrl = `${baseUrl}${endpoint}?${param}=${encodeURIComponent(payload)}`;
      try {
        const { response } = await this.fetch(testUrl);
        const check = checkVulnerability(response, type);
        if (check.vulnerable) {
          results.push({ type, endpoint, method: 'GET', payload, parameter: param, vulnerable: true, evidence: check.evidence, response });
          break;
        }
      } catch {}
    }
    return results;
  }

  checkToFinding(check: VulnerabilityCheck, agentId: string): Finding {
    const severity: Record<string, 'critical' | 'high' | 'medium'> = { sqli: 'critical', xss: 'high', cmdi: 'critical', nosqli: 'critical', ssti: 'high', path: 'high', auth: 'critical' };
    const category: Record<string, string> = { sqli: 'A03_INJECTION', xss: 'A03_INJECTION', cmdi: 'A03_INJECTION', nosqli: 'A03_INJECTION', ssti: 'A03_INJECTION', path: 'A01_BROKEN_ACCESS_CONTROL', auth: 'A07_AUTH_FAILURES' };
    const names: Record<string, string> = { sqli: 'SQL Injection', xss: 'Cross-Site Scripting', cmdi: 'Command Injection', nosqli: 'NoSQL Injection', ssti: 'Template Injection', path: 'Path Traversal', auth: 'Authentication Bypass' };

    return createFinding(agentId)
      .title(`${names[check.type]} in ${check.endpoint}`)
      .description(`${names[check.type]} found at ${check.endpoint}${check.parameter ? ` in parameter '${check.parameter}'` : ''}`)
      .severity(severity[check.type] ?? 'medium')
      .category((category[check.type] ?? 'A03_INJECTION') as OWASPCategory)
      .cvssScore(severity[check.type] === 'critical' ? 9.8 : 7.5)
      .confidence(0.85)
      .evidence({ payload: check.payload, response: check.response?.body?.substring(0, 500), context: { parameter: check.parameter } })
      .remediation({ summary: 'Input validation & output encoding', steps: ['Validate input', 'Use prepared statements', 'Encode output'], effort: 'medium', priority: 1 })
      .tags([check.type])
      .build();
  }
}

export function createWebScanner(config?: Partial<ScannerConfig>): WebScanner {
  return new WebScanner(config);
}