/**
 * HTTP Client for security testing
 */



export interface HttpRequestOptions {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';
  url: string;
  headers?: Record<string, string>;
  body?: unknown;
  timeout?: number;
  followRedirects?: boolean;
  validateSSL?: boolean;
}

export interface HttpResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  json?: unknown;
  duration: number;
  url: string;
}

export interface HttpClient {
  request(options: HttpRequestOptions): Promise<HttpResponse>;
  get(url: string, headers?: Record<string, string>): Promise<HttpResponse>;
  post(url: string, body: unknown, headers?: Record<string, string>): Promise<HttpResponse>;
}

/**
 * Create HTTP client for security testing
 */
export function createHttpClient(defaultTimeout = 30000): HttpClient {
  async function request(options: HttpRequestOptions): Promise<HttpResponse> {
    const startTime = Date.now();
    const controller = new AbortController();
    const timeout = options.timeout ?? defaultTimeout;

    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(options.url, {
        method: options.method,
        headers: {
          'User-Agent': 'Guardiant/0.1.0 Security Scanner',
          'Accept': '*/*',
          ...options.headers,
        },
        body: options.body ? JSON.stringify(options.body) : undefined,
        redirect: options.followRedirects !== false ? 'follow' : 'manual',
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key.toLowerCase()] = value;
      });

      const body = await response.text();
      let json: unknown;
      try {
        if (responseHeaders['content-type']?.includes('application/json')) {
          json = JSON.parse(body);
        }
      } catch {
        // Not valid JSON
      }

      return {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
        body,
        json,
        duration: Date.now() - startTime,
        url: response.url,
      };
    } catch (error) {
      clearTimeout(timeoutId);
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error(`Request timed out after ${timeout}ms`);
      }
      throw error;
    }
  }

  return {
    request,
    get: async (url: string, headers?: Record<string, string>) =>
      request({ method: 'GET', url, headers }),
    post: async (url: string, body: unknown, headers?: Record<string, string>) =>
      request({ method: 'POST', url, body, headers: { 'Content-Type': 'application/json', ...headers } }),
  };
}

/**
 * Check if URL is reachable
 */
export async function isUrlReachable(url: string, timeout = 5000): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    await fetch(url, { method: 'HEAD', signal: controller.signal });
    clearTimeout(timeoutId);
    return true;
  } catch {
    return false;
  }
}

/**
 * Extract domain from URL
 */
export function extractDomain(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/**
 * Build URL with query params
 */
export function buildUrl(baseUrl: string, params: Record<string, string | number | boolean>): string {
  const url = new URL(baseUrl);
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, String(value));
  }
  return url.toString();
}

// Re-export from web-scanner
export { createWebScanner, WebScanner } from '../scanner/web-scanner.js';
export type { VulnerabilityCheck, ScannerConfig, ScanResult } from '../scanner/web-scanner.js';