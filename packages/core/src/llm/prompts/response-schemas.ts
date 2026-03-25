import { z } from 'zod';

/**
 * Zod schemas for structured LLM responses
 */

/**
 * Vulnerability finding schema
 */
export const FindingOutputSchema = z.object({
  title: z.string().describe('Clear, concise title for the vulnerability'),
  description: z.string().describe('Detailed description of the vulnerability'),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).describe('Severity level'),
  cvssScore: z.number().min(0).max(10).describe('CVSS score (0-10)'),
  confidence: z.number().min(0).max(1).describe('Confidence level (0-1)'),
  category: z.string().describe('OWASP category code (e.g., A01:2021)'),
  evidence: z.object({
    request: z.string().optional().describe('HTTP request that triggers the vulnerability'),
    response: z.string().optional().describe('Response showing the vulnerability'),
    file: z.string().optional().describe('File where vulnerability was found'),
    line: z.number().optional().describe('Line number'),
    payload: z.string().optional().describe('Payload used to exploit'),
    context: z.record(z.unknown()).optional().describe('Additional context'),
  }).describe('Evidence of the vulnerability'),
  remediation: z.object({
    summary: z.string().describe('Brief summary of the fix'),
    steps: z.array(z.string()).describe('Step-by-step remediation instructions'),
    codeExample: z.string().optional().describe('Code example showing the fix'),
    references: z.array(z.string()).optional().describe('Reference links'),
    effort: z.enum(['trivial', 'low', 'medium', 'high']).describe('Effort to fix'),
    priority: z.number().min(1).max(10).describe('Priority (1=critical, 10=low)'),
  }).describe('Remediation advice'),
  tags: z.array(z.string()).describe('Tags for categorization'),
});

/**
 * Multiple findings schema
 */
export const FindingsOutputSchema = z.object({
  findings: z.array(FindingOutputSchema).describe('List of findings'),
  summary: z.string().describe('Summary of findings'),
  confidence: z.number().min(0).max(1).describe('Overall confidence'),
});

/**
 * Reconnaissance output schema
 */
export const ReconOutputSchema = z.object({
  endpoints: z.array(z.object({
    path: z.string().describe('Endpoint path'),
    method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']).describe('HTTP method'),
    parameters: z.array(z.object({
      name: z.string().describe('Parameter name'),
      location: z.enum(['query', 'body', 'header', 'path']).describe('Parameter location'),
      type: z.string().optional().describe('Parameter type'),
      required: z.boolean().optional().describe('Is required'),
    })).optional().describe('Endpoint parameters'),
    authentication: z.boolean().optional().describe('Requires authentication'),
  })).describe('Discovered endpoints'),
  techStack: z.object({
    frontend: z.object({
      framework: z.string().optional().describe('Frontend framework'),
      version: z.string().optional().describe('Version'),
      language: z.string().optional().describe('Programming language'),
    }).optional(),
    backend: z.object({
      framework: z.string().optional().describe('Backend framework'),
      version: z.string().optional().describe('Version'),
      language: z.string().optional().describe('Programming language'),
    }).optional(),
    database: z.object({
      type: z.string().optional().describe('Database type'),
      provider: z.string().optional().describe('Database provider'),
    }).optional(),
    baas: z.object({
      provider: z.enum(['supabase', 'firebase', 'other', 'none']).optional().describe('BaaS provider'),
      features: z.array(z.string()).optional().describe('BaaS features used'),
    }).optional(),
    auth: z.object({
      provider: z.string().optional().describe('Auth provider'),
      type: z.string().optional().describe('Auth type'),
    }).optional(),
  }).describe('Technology stack'),
  authMechanisms: z.array(z.object({
    type: z.enum(['jwt', 'session', 'oauth', 'apikey', 'basic', 'custom']).describe('Auth type'),
    provider: z.string().optional().describe('Auth provider'),
    location: z.enum(['header', 'cookie', 'query', 'body']).describe('Where auth is passed'),
  })).optional().describe('Authentication mechanisms'),
  securityConcerns: z.array(z.string()).describe('Initial security concerns'),
});

/**
 * Analysis reasoning schema
 */
export const ReasoningOutputSchema = z.object({
  reasoning: z.array(z.object({
    step: z.number().describe('Step number'),
    type: z.enum(['observation', 'hypothesis', 'test', 'conclusion']).describe('Step type'),
    description: z.string().describe('Step description'),
    finding: z.string().optional().describe('Finding from this step'),
    confidence: z.number().min(0).max(1).optional().describe('Confidence in this step'),
  })).describe('Reasoning chain'),
  conclusion: z.string().describe('Final conclusion'),
  recommendations: z.array(z.string()).describe('Recommendations'),
});

/**
 * CVC Analysis schema
 */
export const CVCOutputSchema = z.object({
  chains: z.array(z.object({
    findings: z.array(z.string()).describe('Finding IDs in the chain'),
    compoundSeverity: z.enum(['critical', 'high', 'medium', 'low', 'info']).describe('Compound severity'),
    exploitPath: z.string().describe('Step-by-step exploit path'),
    attackSteps: z.array(z.object({
      order: z.number().describe('Step order'),
      findingId: z.string().describe('Finding ID'),
      action: z.string().describe('Attack action'),
      result: z.string().describe('Result of this step'),
    })).describe('Attack steps'),
  })).describe('Compound vulnerability chains'),
});

/**
 * TIEF Analysis schema
 */
export const TIEFOutputSchema = z.object({
  trustInversions: z.array(z.object({
    type: z.enum([
      'frontend_auth_logic',
      'direct_database_access',
      'client_secrets',
      'missing_server_validation',
      'over_permissive_cors',
      'insecure_defaults',
    ]).describe('Inversion type'),
    description: z.string().describe('Description of the trust inversion'),
    misplacedTrust: z.string().describe('Where trust is misplaced'),
    expectedBoundary: z.string().describe('Expected trust boundary'),
    actualBoundary: z.string().describe('Actual trust boundary'),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).describe('Severity'),
    findings: z.array(z.string()).describe('Associated finding IDs'),
  })).describe('Trust inversions detected'),
});

/**
 * Export types
 */
export type FindingOutput = z.infer<typeof FindingOutputSchema>;
export type FindingsOutput = z.infer<typeof FindingsOutputSchema>;
export type ReconOutput = z.infer<typeof ReconOutputSchema>;
export type ReasoningOutput = z.infer<typeof ReasoningOutputSchema>;
export type CVCOutput = z.infer<typeof CVCOutputSchema>;
export type TIEFOutput = z.infer<typeof TIEFOutputSchema>;