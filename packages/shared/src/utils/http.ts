/**
 * HTTP Client wrapper for making requests
 */

export interface HttpClientConfig {
  /** Base URL for requests */
  baseUrl?: string;
  /** Default headers */
  headers?: Record<string, string>;
  /** Request timeout in ms */
  timeout?: number;
  /** Max redirects to follow */
  maxRedirects?: number;
  /** Validate SSL certificates */
  validateSSL?: boolean;
  /** User agent */
  userAgent?: string;
}

export interface RequestOptions {
  /** HTTP method */
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';
  /** Request headers */
  headers?: Record<string, string>;
  /** Query parameters */
  query?: Record<string, string | number | boolean>;
  /** Request body */
  body?: unknown;
  /** Request timeout */
  timeout?: number;
  /** Follow redirects */
  followRedirects?: boolean;
  /** Parse JSON response */
  parseJson?: boolean;
}

export interface HttpResponse<T = unknown> {
  /** Response status code */
  status: number;
  /** Response status text */
  statusText: string;
  /** Response headers */
  headers: Record<string, string>;
  /** Response body */
  body: T;
  /** Raw response body */
  rawBody: string;
  /** Request duration in ms */
  duration: number;
  /** Final URL (after redirects) */
  url: string;
}

/**
 * Default HTTP client configuration
 */
export const DEFAULT_HTTP_CONFIG: Required<HttpClientConfig> = {
  baseUrl: '',
  headers: {
    'User-Agent': 'Guardiant/0.1.0 Security Scanner',
    'Accept': 'application/json, text/html, */*',
  },
  timeout: 30000,
  maxRedirects: 5,
  validateSSL: true,
  userAgent: 'Guardiant/0.1.0 Security Scanner',
};

/**
 * Simple HTTP client using fetch
 */
export class HttpClient {
  private config: Required<HttpClientConfig>;

  constructor(config: Partial<HttpClientConfig> = {}) {
    this.config = { ...DEFAULT_HTTP_CONFIG, ...config };
  }

  /**
   * Make an HTTP request
   */
  async request<T = unknown>(url: string, options: RequestOptions = {}): Promise<HttpResponse<T>> {
    const startTime = Date.now();

    // Build full URL
    const fullUrl = this.buildUrl(url, options.query);

    // Merge headers
    const headers = { ...this.config.headers, ...options.headers };

    // Build request options
    const fetchOptions: RequestInit = {
      method: options.method ?? 'GET',
      headers: headers as Record<string, string>,
      redirect: options.followRedirects !== false ? 'follow' : 'manual',
      signal: AbortSignal.timeout(options.timeout ?? this.config.timeout),
    };

    // Add body if present
    if (options.body) {
      if (typeof options.body === 'object' && !(options.body instanceof FormData)) {
        fetchOptions.body = JSON.stringify(options.body);
        (fetchOptions.headers as Record<string, string>)['Content-Type'] = 'application/json';
      } else {
        fetchOptions.body = options.body as BodyInit;
      }
    }

    try {
      const response = await fetch(fullUrl, fetchOptions);
      const duration = Date.now() - startTime;

      // Get response headers
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });

      // Get response body
      const rawBody = await response.text();
      let body: T;

      // Parse JSON if requested
      if (options.parseJson !== false && responseHeaders['content-type']?.includes('application/json')) {
        try {
          body = JSON.parse(rawBody) as T;
        } catch {
          body = rawBody as T;
        }
      } else {
        body = rawBody as T;
      }

      return {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
        body,
        rawBody,
        duration,
        url: response.url,
      };
    } catch (error) {
      // Re-throw with context
      if (error instanceof Error) {
        throw new HttpError(error.message, fullUrl, options.method ?? 'GET', error);
      }
      throw error;
    }
  }

  /**
   * Build URL with query parameters
   */
  private buildUrl(url: string, query?: Record<string, string | number | boolean>): string {
    // Prepend base URL if relative
    let fullUrl = url.startsWith('http') ? url : `${this.config.baseUrl}${url}`;

    // Add query parameters
    if (query && Object.keys(query).length > 0) {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(query)) {
        params.append(key, String(value));
      }
      fullUrl += (fullUrl.includes('?') ? '&' : '?') + params.toString();
    }

    return fullUrl;
  }

  // Convenience methods
  async get<T = unknown>(url: string, options?: Omit<RequestOptions, 'method' | 'body'>): Promise<HttpResponse<T>> {
    return this.request<T>(url, { ...options, method: 'GET' });
  }

  async post<T = unknown>(url: string, body?: unknown, options?: Omit<RequestOptions, 'method' | 'body'>): Promise<HttpResponse<T>> {
    return this.request<T>(url, { ...options, method: 'POST', body });
  }

  async put<T = unknown>(url: string, body?: unknown, options?: Omit<RequestOptions, 'method' | 'body'>): Promise<HttpResponse<T>> {
    return this.request<T>(url, { ...options, method: 'PUT', body });
  }

  async delete<T = unknown>(url: string, options?: Omit<RequestOptions, 'method'>): Promise<HttpResponse<T>> {
    return this.request<T>(url, { ...options, method: 'DELETE' });
  }

  async patch<T = unknown>(url: string, body?: unknown, options?: Omit<RequestOptions, 'method' | 'body'>): Promise<HttpResponse<T>> {
    return this.request<T>(url, { ...options, method: 'PATCH', body });
  }
}

/**
 * HTTP Error class
 */
export class HttpError extends Error {
  constructor(
    message: string,
    public readonly url: string,
    public readonly method: string,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'HttpError';
  }
}

/**
 * Create a default HTTP client
 */
export function createHttpClient(config: Partial<HttpClientConfig> = {}): HttpClient {
  return new HttpClient(config);
}

/**
 * Parse URL safely
 */
export function parseUrl(url: string): { protocol: string; host: string; pathname: string; search: string } | null {
  try {
    const parsed = new URL(url);
    return {
      protocol: parsed.protocol,
      host: parsed.host,
      pathname: parsed.pathname,
      search: parsed.search,
    };
  } catch {
    return null;
  }
}

/**
 * Check if URL is reachable
 */
export async function isUrlReachable(url: string, timeout: number = 5000): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, { method: 'HEAD', signal: controller.signal });
    clearTimeout(timeoutId);

    return response.ok;
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
 * Build URL with path joining
 */
export function buildUrl(baseUrl: string, ...paths: string[]): string {
  const url = new URL(baseUrl);
  url.pathname = paths.reduce((acc, path) => {
    const normalizedPath = path.startsWith('/') ? path.slice(1) : path;
    return acc.endsWith('/') ? `${acc}${normalizedPath}` : `${acc}/${normalizedPath}`;
  }, url.pathname);
  return url.toString();
}