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
  retries?: number;
  retryDelay?: number;
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
 * Check if an error is retryable (network errors, timeouts, 5xx)
 */
function isRetryableError(error: unknown): boolean {
  if (error instanceof Error) {
    // Timeouts are retryable
    if (error.name === 'AbortError' || error.message.includes('timed out')) {
      return true;
    }
    // Connection errors are retryable (ECONNREFUSED, ECONNRESET, etc.)
    if (
      error.message.includes('ECONNREFUSED') ||
      error.message.includes('ECONNRESET') ||
      error.message.includes('ENOTFOUND') ||
      error.message.includes('fetch failed') ||
      error.message.includes('network')
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Sleep for a given duration
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Create HTTP client for security testing
 */
export function createHttpClient(defaultTimeout = 30000): HttpClient {
  async function request(options: HttpRequestOptions): Promise<HttpResponse> {
    const maxRetries = options.retries ?? 2;
    const baseRetryDelay = options.retryDelay ?? 1000;
    let lastError: unknown;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
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
        lastError = error;

        // Don't retry on non-retryable errors or if we've exhausted retries
        if (!isRetryableError(error) || attempt >= maxRetries) {
          if (error instanceof Error && error.name === 'AbortError') {
            throw new Error(`Request timed out after ${timeout}ms`);
          }
          throw error;
        }

        // Exponential backoff: 1s, 2s, 4s...
        const delay = baseRetryDelay * Math.pow(2, attempt);
        await sleep(delay);
      }
    }

    // Should not reach here, but just in case
    throw lastError instanceof Error ? lastError : new Error('Request failed after retries');
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
export async function isUrlReachable(url: string, timeout = 5000, retries = 2): Promise<boolean> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      await fetch(url, { method: 'HEAD', signal: controller.signal });
      clearTimeout(timeoutId);
      return true;
    } catch {
      if (attempt < retries) {
        await sleep(1000 * Math.pow(2, attempt));
      }
    }
  }
  return false;
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