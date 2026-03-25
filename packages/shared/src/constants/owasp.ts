import type { OWASPCategory } from '../types/vulnerability.js';

/**
 * OWASP Top 10 (2021) Categories
 */
export const OWASP_TOP_10: Record<OWASPCategory, {
  code: string;
  name: string;
  description: string;
  examples: string[];
  prevention: string[];
}> = {
  A01_BROKEN_ACCESS_CONTROL: {
    code: 'A01:2021',
    name: 'Broken Access Control',
    description: 'Failures in access control allow unauthorized access to resources. This includes IDOR, missing authentication, and privilege escalation.',
    examples: [
      'Insecure Direct Object References (IDOR)',
      'Privilege escalation (horizontal and vertical)',
      'Missing authentication for sensitive operations',
      'URL manipulation to bypass authorization',
      'Missing rate limiting on login endpoints',
    ],
    prevention: [
      'Implement proper access control on every endpoint',
      'Deny by default except for public resources',
      'Use server-side authorization checks',
      'Implement rate limiting',
      'Log access control failures',
    ],
  },
  A02_CRYPTOGRAPHIC_FAILURES: {
    code: 'A02:2021',
    name: 'Cryptographic Failures',
    description: 'Failures related to cryptography which lead to sensitive data exposure. Includes weak encryption, improper key management, and cleartext transmission.',
    examples: [
      'Weak encryption algorithms (MD5, SHA1)',
      'Hardcoded encryption keys',
      'Transmission of credentials in plaintext',
      'Missing or weak TLS configuration',
      'Improper key storage',
    ],
    prevention: [
      'Use modern encryption algorithms (AES-256, SHA-256)',
      'Implement proper key management',
      'Enforce HTTPS for all connections',
      'Store secrets in secure vaults',
      'Rotate encryption keys regularly',
    ],
  },
  A03_INJECTION: {
    code: 'A03:2021',
    name: 'Injection',
    description: 'SQL, NoSQL, OS command, and other injection vulnerabilities occur when user input is not properly sanitized before use in queries or commands.',
    examples: [
      'SQL injection',
      'NoSQL injection',
      'Command injection',
      'LDAP injection',
      'XPath injection',
      'Template injection (SSTI)',
    ],
    prevention: [
      'Use parameterized queries exclusively',
      'Validate and sanitize all user input',
      'Use ORM libraries with automatic escaping',
      'Apply principle of least privilege to database accounts',
      'Implement input allowlists where possible',
    ],
  },
  A04_INSECURE_DESIGN: {
    code: 'A04:2021',
    name: 'Insecure Design',
    description: 'Flaws in design and architecture that lead to vulnerabilities. Different from implementation flaws, these are fundamental design weaknesses.',
    examples: [
      'Missing rate limiting by design',
      'No separation of concerns between users and admins',
      'Credential recovery workflow flaws',
      'Insecure direct object references by design',
      'Missing security boundaries',
    ],
    prevention: [
      'Implement threat modeling during design',
      'Use secure design patterns',
      'Separate tenants and user roles',
      'Build security controls into design',
      'Reference architecture guidelines',
    ],
  },
  A05_SECURITY_MISCONFIGURATION: {
    code: 'A05:2021',
    name: 'Security Misconfiguration',
    description: 'Missing appropriate security hardening or misconfigured permissions. Includes default credentials, verbose errors, and missing security headers.',
    examples: [
      'Default credentials still enabled',
      'Debug mode enabled in production',
      'Overly permissive CORS configuration',
      'Missing security headers',
      'Unnecessary features enabled',
      'Cloud storage misconfiguration',
    ],
    prevention: [
      'Remove default credentials',
      'Disable debug mode in production',
      'Implement security headers',
      'Configure CORS properly',
      'Regular security audits of configuration',
      'Use infrastructure as code for consistency',
    ],
  },
  A06_VULNERABLE_COMPONENTS: {
    code: 'A06:2021',
    name: 'Vulnerable and Outdated Components',
    description: 'Using components with known vulnerabilities. Includes dependencies, frameworks, and third-party libraries.',
    examples: [
      'Known CVE in dependency',
      'Outdated framework version',
      'Unmaintained packages',
      'Hallucinated packages (supply chain attack)',
      'Transitive vulnerabilities',
    ],
    prevention: [
      'Remove unused dependencies',
      'Regularly update dependencies',
      'Use dependency scanning tools',
      'Only use official package sources',
      'Subscribe to security advisories',
    ],
  },
  A07_AUTH_FAILURES: {
    code: 'A07:2021',
    name: 'Identification and Authentication Failures',
    description: 'Session management and authentication failures. Includes credential stuffing, weak passwords, and session fixation.',
    examples: [
      'Credential stuffing attacks',
      'Weak password policies',
      'Session fixation',
      'Missing MFA for sensitive operations',
      'Improper session expiration',
      'Insecure password recovery',
    ],
    prevention: [
      'Implement multi-factor authentication',
      'Use strong password policies',
      'Implement proper session management',
      'Rate limit authentication attempts',
      'Use secure password recovery flows',
    ],
  },
  A08_INTEGRITY_FAILURES: {
    code: 'A08:2021',
    name: 'Software and Data Integrity Failures',
    description: 'Code and infrastructure integrity verification failures. Includes insecure CI/CD pipelines and auto-update mechanisms.',
    examples: [
      'Insecure deserialization',
      'Compromised CI/CD pipeline',
      'Unverified auto-updates',
      'Missing SRI for CDN resources',
      'Unsigned packages',
    ],
    prevention: [
      'Verify package signatures',
      'Use SRI for CDN resources',
      'Secure CI/CD pipelines',
      'Implement code signing',
      'Validate all inputs during deserialization',
    ],
  },
  A09_LOGGING_FAILURES: {
    code: 'A09:2021',
    name: 'Security Logging and Monitoring Failures',
    description: 'Insufficient logging and monitoring capabilities. Without proper logging, breaches cannot be detected.',
    examples: [
      'Missing authentication failure logs',
      'No logging of sensitive operations',
      'Logs not monitored',
      'Insufficient log retention',
      'Verbose error messages in logs',
    ],
    prevention: [
      'Log all authentication events',
      'Log sensitive operations',
      'Implement log monitoring',
      'Set appropriate log retention',
      'Use structured logging',
    ],
  },
  A10_SSRF: {
    code: 'A10:2021',
    name: 'Server-Side Request Forgery',
    description: 'SSRF vulnerabilities allow the server to make unintended requests. Can lead to internal network scanning and data exfiltration.',
    examples: [
      'Fetching URLs from user input',
      'Webhook URL manipulation',
      'Internal service access',
      'Cloud metadata endpoint access',
      'Port scanning via server',
    ],
    prevention: [
      'Validate and sanitize all URLs',
      'Use allowlists for domains',
      'Block internal IP ranges',
      'Disable unnecessary URL schemes',
      'Use a dedicated SSRF protection service',
    ],
  },
};

/**
 * Get OWASP category by code
 */
export function getOWASPByCode(code: string): OWASPCategory | undefined {
  const entry = Object.entries(OWASP_TOP_10).find(([_, data]) => data.code === code);
  return entry ? (entry[0] as OWASPCategory) : undefined;
}

/**
 * Get OWASP category examples
 */
export function getOWASPExamples(category: OWASPCategory): string[] {
  return OWASP_TOP_10[category]?.examples ?? [];
}

/**
 * Map vulnerability type to OWASP category
 */
export function mapVulnerabilityToOWASP(vulnerabilityType: string): OWASPCategory {
  const mapping: Record<string, OWASPCategory> = {
    // Injection types
    'sqli': 'A03_INJECTION',
    'sql_injection': 'A03_INJECTION',
    'nosql_injection': 'A03_INJECTION',
    'command_injection': 'A03_INJECTION',
    'xss': 'A03_INJECTION',
    'ssti': 'A03_INJECTION',
    'ldap_injection': 'A03_INJECTION',

    // Access control
    'idor': 'A01_BROKEN_ACCESS_CONTROL',
    'broken_access_control': 'A01_BROKEN_ACCESS_CONTROL',
    'privilege_escalation': 'A01_BROKEN_ACCESS_CONTROL',
    'path_traversal': 'A01_BROKEN_ACCESS_CONTROL',

    // Auth failures
    'weak_auth': 'A07_AUTH_FAILURES',
    'credential_stuffing': 'A07_AUTH_FAILURES',
    'session_fixation': 'A07_AUTH_FAILURES',
    'broken_auth': 'A07_AUTH_FAILURES',

    // Crypto
    'weak_encryption': 'A02_CRYPTOGRAPHIC_FAILURES',
    'cleartext_storage': 'A02_CRYPTOGRAPHIC_FAILURES',
    'hardcoded_secrets': 'A02_CRYPTOGRAPHIC_FAILURES',

    // Misconfiguration
    'cors_misconfig': 'A05_SECURITY_MISCONFIGURATION',
    'security_headers': 'A05_SECURITY_MISCONFIGURATION',
    'default_credentials': 'A05_SECURITY_MISCONFIGURATION',
    'rls_disabled': 'A05_SECURITY_MISCONFIGURATION',

    // Components
    'vulnerable_dependency': 'A06_VULNERABLE_COMPONENTS',
    'outdated_package': 'A06_VULNERABLE_COMPONENTS',
    'supply_chain': 'A06_VULNERABLE_COMPONENTS',

    // SSRF
    'ssrf': 'A10_SSRF',

    // Design
    'insecure_design': 'A04_INSECURE_DESIGN',
    'missing_rate_limit': 'A04_INSECURE_DESIGN',
  };

  const normalizedType = vulnerabilityType.toLowerCase().replace(/[-\s]/g, '_');
  return mapping[normalizedType] ?? 'A05_SECURITY_MISCONFIGURATION';
}