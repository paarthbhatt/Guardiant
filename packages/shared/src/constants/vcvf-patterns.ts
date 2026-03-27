/**
 * VCVF (Vibe Code Vulnerability Fingerprint) Patterns
 *
 * These patterns identify code characteristics unique to AI-generated applications
 * that indicate higher vulnerability likelihood.
 */

import type { VCVFPatternType } from '../types/vulnerability.js';

/**
 * VCVF Pattern definition
 */
export interface VCVFPatternDefinition {
  /** Pattern type identifier */
  type: VCVFPatternType;
  /** Human-readable name */
  name: string;
  /** Description of the pattern */
  description: string;
  /** Confidence weight (how indicative this pattern is) */
  confidence: number;
  /** File patterns to search */
  filePatterns: string[];
  /** Code patterns to detect */
  codePatterns: CodePattern[];
  /** Predicted vulnerabilities */
  predictedVulnerabilities: VCVFPredictedVulnerability[];
  /** BaaS-specific indicators */
  baasIndicators?: BaaSIndicator[];
}

export interface CodePattern {
  /** Regex pattern to match */
  pattern: RegExp | string;
  /** Description of what this matches */
  description: string;
  /** Weight for confidence calculation */
  weight: number;
  /** True if pattern indicates presence of vulnerability */
  isVulnerability: boolean;
}

export interface VCVFPredictedVulnerability {
  /** Vulnerability type */
  type: string;
  /** Probability (0-1) */
  probability: number;
  /** Reason for prediction */
  reason: string;
  /** OWASP category */
  owaspCategory: string;
}

export interface BaaSIndicator {
  /** BaaS provider */
  provider: 'supabase' | 'firebase' | 'unknown';
  /** Indicator type */
  type: 'rls_disabled' | 'public_bucket' | 'service_key_exposed' | 'insecure_rules';
  /** Description */
  description: string;
}

/**
 * All VCVF patterns
 */
export const VCVF_PATTERNS: VCVFPatternDefinition[] = [
  {
    type: 'symmetric_crud_vulnerabilities',
    name: 'Symmetric CRUD Vulnerabilities',
    description: 'AI-generated code often has identical vulnerability patterns across all CRUD operations (Create, Read, Update, Delete). For example, if authentication is missing on Read, it\'s likely missing on Create, Update, and Delete.',
    confidence: 0.85,
    filePatterns: ['**/*.{ts,tsx,js,jsx}'],
    codePatterns: [
      {
        pattern: /(?:create|read|update|delete)\w*=\s*(?:async\s*)?\([^)]*\)\s*(?::\s*\w+)?\s*=>/gi,
        description: 'CRUD handler functions',
        weight: 0.7,
        isVulnerability: false,
      },
      {
        pattern: /(?:router\.(get|post|put|delete|patch)\s*\(\s*['"`][^'"`]+['"`])/gi,
        description: 'Express/Fastify route handlers',
        weight: 0.8,
        isVulnerability: false,
      },
      {
        pattern: /(?:app\.(get|post|put|delete|patch)\s*\(\s*['"`][^'"`]+['"`])/gi,
        description: 'Express app route handlers',
        weight: 0.8,
        isVulnerability: false,
      },
    ],
    predictedVulnerabilities: [
      { type: 'broken_access_control', probability: 0.9, reason: 'Symmetric CRUD often indicates missing auth checks across all operations', owaspCategory: 'A01_BROKEN_ACCESS_CONTROL' },
      { type: 'idor', probability: 0.8, reason: 'CRUD operations likely share same ID validation weaknesses', owaspCategory: 'A01_BROKEN_ACCESS_CONTROL' },
    ],
  },
  {
    type: 'auth_authz_conflation',
    name: 'Authentication/Authorization Conflation',
    description: 'Vibe-coded apps frequently conflate authentication with authorization. Authentication is implemented (user is logged in) but authorization is missing (user can access other users\' data).',
    confidence: 0.9,
    filePatterns: ['**/*.{ts,tsx,js,jsx}', '**/middleware/*.{ts,js}'],
    codePatterns: [
      {
        pattern: /(?:requireAuth|isAuthenticated|withAuth|authenticateToken)/gi,
        description: 'Authentication middleware presence',
        weight: 0.8,
        isVulnerability: false,
      },
      {
        pattern: /(?:requireRole|isAuthorized|checkPermission|hasAccess)/gi,
        description: 'Authorization middleware presence',
        weight: 0.9,
        isVulnerability: false,
      },
      {
        pattern: /(?:req\.user\s*&&\s*!req\.user\.(?:role|permissions|access))/gi,
        description: 'User object without role checking',
        weight: 0.95,
        isVulnerability: true,
      },
      {
        pattern: /(?:if\s*\(\s*req\.(?:session\.(?:userId|user)|user(?:Id)?)\s*\))/gi,
        description: 'Simple authentication check without authorization',
        weight: 0.9,
        isVulnerability: true,
      },
    ],
    predictedVulnerabilities: [
      { type: 'privilege_escalation', probability: 0.85, reason: 'Auth check without authz check allows horizontal/vertical escalation', owaspCategory: 'A01_BROKEN_ACCESS_CONTROL' },
      { type: 'idor', probability: 0.8, reason: 'Missing ownership validation on resources', owaspCategory: 'A01_BROKEN_ACCESS_CONTROL' },
    ],
  },
  {
    type: 'optimistic_trust_patterns',
    name: 'Optimistic Trust Patterns',
    description: 'AI-generated code often trusts client-side data without server-side validation. "The frontend validates it, so it\'s safe" is a common anti-pattern.',
    confidence: 0.95,
    filePatterns: ['**/api/**/*.{ts,js}', '**/routes/**/*.{ts,js}', '**/pages/api/**/*.{ts,js}'],
    codePatterns: [
      {
        pattern: /(?:req\.(?:body|query|params)\.\w+)\s*(?!==|!==|\|\||&&|\?\.)/gi,
        description: 'Direct request data access without validation',
        weight: 0.9,
        isVulnerability: true,
      },
      {
        pattern: /(?:parseInt|Number|parseFloat)\s*\(\s*(?:req\.(?:body|query|params)\.\w+)/gi,
        description: 'Type coercion without validation',
        weight: 0.85,
        isVulnerability: true,
      },
      {
        pattern: /(?:\.where\s*\(\s*{[^}]*\b(?:userId|owner|createdBy)\s*:\s*(?:req\.(?:user\.)?id|currentUser))/gi,
        description: 'User ID in query without validation',
        weight: 0.7,
        isVulnerability: false,
      },
    ],
    predictedVulnerabilities: [
      { type: 'sqli', probability: 0.7, reason: 'Unvalidated input in queries', owaspCategory: 'A03_INJECTION' },
      { type: 'broken_access_control', probability: 0.9, reason: 'Trust in client-provided user IDs', owaspCategory: 'A01_BROKEN_ACCESS_CONTROL' },
      { type: 'nosql_injection', probability: 0.65, reason: 'NoSQL queries with unvalidated input', owaspCategory: 'A03_INJECTION' },
    ],
  },
  {
    type: 'copy_paste_insecurity',
    name: 'Copy-Paste Insecurity',
    description: 'AI models often copy code patterns from training data. Identical blocks of code across files suggest copy-paste, and if one has a vulnerability, all copies have it.',
    confidence: 0.75,
    filePatterns: ['**/*.{ts,tsx,js,jsx}'],
    codePatterns: [
      {
        pattern: /(?:\/\/\s*TODO|\/\/\s*FIXME|\/\/\s*HACK)/gi,
        description: 'TODO/FIXME comments indicating incomplete code',
        weight: 0.6,
        isVulnerability: false,
      },
      {
        pattern: /(?:async\s+\w+\s*\([^)]*\)\s*(?::\s*\w+)?\s*=>\s*{[\s\S]{0,500}return[^;]*;[\s\S]{0,100}})/gi,
        description: 'Similar function structures',
        weight: 0.5,
        isVulnerability: false,
      },
    ],
    predictedVulnerabilities: [
      { type: 'injection', probability: 0.6, reason: 'Copied code may not have proper sanitization', owaspCategory: 'A03_INJECTION' },
    ],
  },
  {
    type: 'documentation_reality_gap',
    name: 'Documentation-Reality Gap',
    description: 'AI-generated code often has comments that claim security features that aren\'t implemented. "// Secure endpoint" without actual security is common.',
    confidence: 0.8,
    filePatterns: ['**/*.{ts,tsx,js,jsx}'],
    codePatterns: [
      {
        pattern: /(?:\/\/\s*(?:secure|authenticated|protected|private|authorized|validate|sanitize))/gi,
        description: 'Security-related comments',
        weight: 0.7,
        isVulnerability: false,
      },
      {
        pattern: /(?:@secure|@authenticated|@protected|@private)/gi,
        description: 'Security-related JSDoc annotations',
        weight: 0.8,
        isVulnerability: false,
      },
    ],
    predictedVulnerabilities: [
      { type: 'security_misconfiguration', probability: 0.7, reason: 'Documentation claims may not match implementation', owaspCategory: 'A05_SECURITY_MISCONFIGURATION' },
      { type: 'broken_access_control', probability: 0.65, reason: 'Protected routes may not actually check permissions', owaspCategory: 'A01_BROKEN_ACCESS_CONTROL' },
    ],
  },
  {
    type: 'baas_bypass_architecture',
    name: 'BaaS Bypass Architecture',
    description: 'Backend-as-a-Service architectures often have client-side authentication but lack proper database-level security (e.g., Supabase RLS disabled, Firebase rules in test mode).',
    confidence: 0.95,
    filePatterns: ['**/*.{ts,tsx,js,jsx}', '**/supabase/**/*.sql', '**/firestore.rules', '**/database.rules.json'],
    codePatterns: [
      {
        pattern: String.raw`(?:createClient|initializeApp)\s*\(\s*{[\s\S]*?(?:anon[_-]?key|supabase[_-]?anon[_-]?key)/gi`,
        description: 'BaaS client initialization',
        weight: 0.9,
        isVulnerability: false,
      },
      {
        pattern: /(?:SUPABASE_SERVICE_ROLE_KEY|SUPABASE_SERVICE_KEY|service_role)/gi,
        description: 'Service role key exposure',
        weight: 1.0,
        isVulnerability: true,
      },
      {
        pattern: /(?:allow\s+read,\s*write:\s*if\s+true|allow\s+read,\s*write:\s*if\s+request\.auth\s*!=\s*null)/gi,
        description: 'Firebase test mode rules',
        weight: 1.0,
        isVulnerability: true,
      },
    ],
    baasIndicators: [
      { provider: 'supabase', type: 'rls_disabled', description: 'RLS not enabled on tables' },
      { provider: 'supabase', type: 'service_key_exposed', description: 'Service role key in client code' },
      { provider: 'firebase', type: 'insecure_rules', description: 'Firestore rules allow all access' },
      { provider: 'firebase', type: 'public_bucket', description: 'Storage bucket publicly accessible' },
    ],
    predictedVulnerabilities: [
      { type: 'broken_access_control', probability: 0.95, reason: 'Client-side auth without database-level authz', owaspCategory: 'A01_BROKEN_ACCESS_CONTROL' },
      { type: 'data_exposure', probability: 0.9, reason: 'No row-level security means all data exposed', owaspCategory: 'A01_BROKEN_ACCESS_CONTROL' },
      { type: 'security_misconfiguration', probability: 0.85, reason: 'BaaS default rules often insecure', owaspCategory: 'A05_SECURITY_MISCONFIGURATION' },
    ],
  },
  {
    type: 'missing_negative_cases',
    name: 'Missing Negative Cases',
    description: 'AI-generated code often handles the "happy path" but misses error cases, edge cases, and unauthorized scenarios.',
    confidence: 0.85,
    filePatterns: ['**/*.{ts,tsx,js,jsx}'],
    codePatterns: [
      {
        pattern: /(?:try\s*{[\s\S]*?}\s*catch[^{]*{\s*(?:console\.(?:log|error|warn)|logger\.(?:log|error|warn)))/gi,
        description: 'Try-catch with only logging',
        weight: 0.7,
        isVulnerability: false,
      },
      {
        pattern: /(?:if\s*\([^)]*\)\s*{[\s\S]*?}\s*(?!else))/gi,
        description: 'If without else',
        weight: 0.5,
        isVulnerability: false,
      },
      {
        pattern: /(?:\.catch\s*\(\s*\(\s*\)\s*=>\s*{[\s\S]*?}\s*\))/gi,
        description: 'Empty catch blocks',
        weight: 0.9,
        isVulnerability: true,
      },
    ],
    predictedVulnerabilities: [
      { type: 'insecure_design', probability: 0.7, reason: 'Missing error handling leads to unexpected behavior', owaspCategory: 'A04_INSECURE_DESIGN' },
      { type: 'information_disclosure', probability: 0.6, reason: 'Unhandled errors may leak sensitive info', owaspCategory: 'A05_SECURITY_MISCONFIGURATION' },
    ],
  },
  {
    type: 'phantom_dependencies',
    name: 'Phantom Dependencies',
    description: 'AI-generated code may import packages that don\'t exist (hallucinated) or have typosquatting names. This is a supply chain attack vector.',
    confidence: 0.9,
    filePatterns: ['**/package.json', '**/*.{ts,tsx,js,jsx}'],
    codePatterns: [
      {
        pattern: /(?:import\s+[^'"]*\s+from\s+['"]([a-zA-Z0-9@_\-/.]+)['"])/gi,
        description: 'Import statements',
        weight: 0.5,
        isVulnerability: false,
      },
      {
        pattern: /(?:require\s*\(\s*['"]([a-zA-Z0-9@_\-/.]+)['"]\s*\))/gi,
        description: 'Require statements',
        weight: 0.5,
        isVulnerability: false,
      },
    ],
    predictedVulnerabilities: [
      { type: 'supply_chain', probability: 0.8, reason: 'Hallucinated packages could be typosquatted', owaspCategory: 'A06_VULNERABLE_COMPONENTS' },
      { type: 'supply_chain', probability: 0.7, reason: 'Unverified dependencies may have known CVEs', owaspCategory: 'A06_VULNERABLE_COMPONENTS' },
    ],
  },
  {
    type: 'over_permissive_defaults',
    name: 'Over-Permissive Defaults',
    description: 'Vibe-coded apps often have CORS=*, debug=true in production, or other insecure defaults copied from development templates.',
    confidence: 0.85,
    filePatterns: ['**/*.{ts,tsx,js,jsx}', '**/.env*', '**/config/*'],
    codePatterns: [
      {
        pattern: /(?:cors\s*(?::\s*|\s*=\s*|\(|\{)\s*(?:{[^}]*origin\s*:\s*['"`]\*['"`]|['"`]\*['"`]))/gi,
        description: 'CORS wildcard',
        weight: 1.0,
        isVulnerability: true,
      },
      {
        pattern: /(?:DEBUG\s*=\s*(?:true|1|['"`]true['"`])|NODE_ENV\s*=\s*['"`]development['"`])/gi,
        description: 'Debug mode enabled',
        weight: 0.9,
        isVulnerability: true,
      },
      {
        pattern: /(?:allowMethods\s*:\s*\[?\s*['"`]\*['"`])/gi,
        description: 'All methods allowed',
        weight: 0.85,
        isVulnerability: true,
      },
      {
        pattern: /(?:exposedHeaders\s*:\s*\[?\s*['"`]\*['"`]|accessControlAllowOrigin\s*:\s*['"`]\*['"`])/gi,
        description: 'Wildcard headers',
        weight: 0.8,
        isVulnerability: true,
      },
    ],
    predictedVulnerabilities: [
      { type: 'cors_misconfiguration', probability: 0.95, reason: 'CORS wildcard allows any origin', owaspCategory: 'A05_SECURITY_MISCONFIGURATION' },
      { type: 'security_misconfiguration', probability: 0.85, reason: 'Debug mode may expose sensitive info', owaspCategory: 'A05_SECURITY_MISCONFIGURATION' },
      { type: 'csrf', probability: 0.7, reason: 'Over-permissive CORS enables CSRF', owaspCategory: 'A01_BROKEN_ACCESS_CONTROL' },
    ],
  },
];

/**
 * Get VCVF pattern by type
 */
export function getVCVFPattern(type: VCVFPatternType): VCVFPatternDefinition | undefined {
  return VCVF_PATTERNS.find(p => p.type === type);
}

/**
 * Get all VCVF patterns for a specific OWASP category
 */
export function getVCVFPatternsByOWASP(owaspCategory: string): VCVFPatternDefinition[] {
  return VCVF_PATTERNS.filter(pattern =>
    pattern.predictedVulnerabilities.some(v => v.owaspCategory === owaspCategory)
  );
}

/**
 * Calculate composite VCVF confidence score
 */
export function calculateVCVFConfidence(detectedPatterns: VCVFPatternType[]): number {
  if (detectedPatterns.length === 0) return 0;

  const totalConfidence = detectedPatterns.reduce((sum, type) => {
    const pattern = getVCVFPattern(type);
    return sum + (pattern?.confidence ?? 0);
  }, 0);

  return totalConfidence / detectedPatterns.length;
}

/**
 * Check if code matches VCVF patterns
 */
export function matchVCVFPatterns(
  code: string,
  filePath: string
): { type: VCVFPatternType; matches: string[]; confidence: number }[] {
  const results: { type: VCVFPatternType; matches: string[]; confidence: number }[] = [];

  for (const pattern of VCVF_PATTERNS) {
    // Check file patterns
    const fileMatches = pattern.filePatterns.some(fp => {
      const regex = new RegExp(fp.replace(/\*\*/g, '(.*/)?').replace(/\*/g, '[^/]*'));
      return regex.test(filePath);
    });

    if (!fileMatches) continue;

    // Check code patterns
    const matches: string[] = [];
    for (const codePattern of pattern.codePatterns) {
      if (typeof codePattern.pattern === 'string') {
        if (code.includes(codePattern.pattern)) {
          matches.push(codePattern.description);
        }
      } else {
        const patternMatches = code.match(codePattern.pattern);
        if (patternMatches) {
          matches.push(codePattern.description);
        }
      }
    }

    if (matches.length > 0) {
      results.push({
        type: pattern.type,
        matches,
        confidence: pattern.confidence * (matches.length / pattern.codePatterns.length),
      });
    }
  }

  return results;
}