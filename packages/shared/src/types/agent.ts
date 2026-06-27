import { z } from 'zod';
import type { Finding } from './vulnerability.js';

// Re-export VCVFPatternType from agent.ts to avoid circular dependency
export type VCVFPatternType =
  | 'symmetric_crud_vulnerabilities'
  | 'auth_authz_conflation'
  | 'optimistic_trust_patterns'
  | 'copy_paste_insecurity'
  | 'documentation_reality_gap'
  | 'baas_bypass_architecture'
  | 'missing_negative_cases'
  | 'phantom_dependencies'
  | 'over_permissive_defaults';

// Re-export PredictedVulnerability type for use in vulnerability.ts
export interface PredictedVulnerability {
  type: string;
  probability: number;
  location: string;
  reason: string;
}

/**
 * Agent identifier type
 */
export type AgentId =
  | 'recon'
  | 'baas'
  | 'secrets'
  | 'auth'
  | 'injection'
  | 'supply_chain'
  | 'business_logic'
  | 'race_condition'
  | 'exploit'
  | 'fix';

/**
 * Agent execution status
 */
export type AgentStatus = 'pending' | 'running' | 'completed' | 'failed' | 'skipped';

/**
 * Agent priority levels
 */
export type AgentPriority = 'critical' | 'high' | 'medium' | 'low';

/**
 * Agent configuration
 */
export interface AgentConfig {
  /** Enable/disable this agent */
  enabled: boolean;
  /** Execution priority */
  priority: AgentPriority;
  /** Timeout in milliseconds */
  timeout: number;
  /** Maximum retries */
  maxRetries: number;
  /** Custom settings */
  settings?: Record<string, unknown>;
}

/**
 * Base agent configuration for all agents
 */
export const DEFAULT_AGENT_CONFIGS: Record<AgentId, AgentConfig> = {
  recon: {
    enabled: true,
    priority: 'critical',
    timeout: 60000,
    maxRetries: 3,
  },
  baas: {
    enabled: true,
    priority: 'critical',
    timeout: 120000,
    maxRetries: 2,
  },
  secrets: {
    enabled: true,
    priority: 'critical',
    timeout: 30000,
    maxRetries: 3,
  },
  auth: {
    enabled: true,
    priority: 'high',
    timeout: 180000,
    maxRetries: 2,
  },
  injection: {
    enabled: true,
    priority: 'high',
    timeout: 300000,
    maxRetries: 1,
  },
  supply_chain: {
    enabled: true,
    priority: 'medium',
    timeout: 60000,
    maxRetries: 3,
  },
  business_logic: {
    enabled: true,
    priority: 'medium',
    timeout: 180000,
    maxRetries: 1,
  },
  race_condition: {
    enabled: true,
    priority: 'low',
    timeout: 120000,
    maxRetries: 2,
  },
  exploit: {
    enabled: true,
    priority: 'medium',
    timeout: 60000,
    maxRetries: 1,
  },
  fix: {
    enabled: true,
    priority: 'low',
    timeout: 60000,
    maxRetries: 1,
  },
};

/**
 * Application type classification
 */
export type AppType =
  | 'ecommerce'
  | 'crm'
  | 'saas'
  | 'blog'
  | 'portfolio'
  | 'social'
  | 'dashboard'
  | 'api'
  | 'unknown';

/**
 * Application context produced by the App Classifier
 * Agents consume this to decide which checks are relevant
 */
export interface AppContext {
  /** Classified application type */
  appType: AppType;
  /** Application has payment/checkout flows */
  hasPayments: boolean;
  /** Application has authentication */
  hasAuth: boolean;
  /** Application has user roles/permissions */
  hasUserRoles: boolean;
  /** Application uses BaaS (Supabase, Firebase, etc.) */
  hasBaaS: boolean;
  /** Application has multi-tenant architecture */
  hasMultiTenancy: boolean;
  /** Application has file upload functionality */
  hasFileUpload: boolean;
  /** Tech stack details */
  techStack: {
    framework: string;
    backend: string;
    database: string;
    baas?: string;
    auth?: string;
  };
  /** Table/model names discovered from routes or schema */
  dataModels: string[];
  /** Routes that handle money, auth, admin */
  sensitiveEndpoints: string[];
  /** Rule IDs to skip for this app type */
  suppressions: string[];
}

/**
 * Scan target information
 */
export interface ScanTarget {
  /** URL or file path */
  url: string;
  /** Target type */
  type: 'url' | 'directory' | 'repository';
  /** BaaS provider if detected */
  baasProvider?: 'supabase' | 'firebase' | 'unknown' | 'none';
  /** Framework detected */
  framework?: string;
  /** Tech stack */
  techStack?: string[];
}

/**
 * Context passed to each agent during execution
 */
export interface AgentContext {
  /** Scan identifier */
  scanId: string;
  /** Target information */
  target: ScanTarget;
  /** Recon data from recon agent (available after recon completes) */
  reconData?: ReconData;
  /** Agent configuration */
  config: AgentConfig;
  /** LLM client reference */
  llmClient?: unknown;
  /** HTTP client for requests */
  httpClient?: unknown;
  /** Logger instance */
  logger?: unknown;
  /** Session data for maintaining state */
  session?: Record<string, unknown>;
  /** App classification context (available after recon + classification) */
  appContext?: AppContext;
}

/**
 * Data collected by recon agent
 */
export interface ReconData {
  /** Discovered API endpoints */
  endpoints: DiscoveredEndpoint[];
  /** Technology stack */
  techStack: TechStackInfo;
  /** External services detected */
  externalServices: ExternalService[];
  /** Authentication mechanisms */
  authMechanisms: AuthMechanism[];
  /** Source map availability */
  sourceMapsAvailable: boolean;
  /** Configuration files found */
  configFiles: ConfigFile[];
  /** VCVF patterns detected */
  vcvfPatterns: VCVFPattern[];
  /** Data flow information */
  dataFlows: DataFlow[];
}

export interface DiscoveredEndpoint {
  path: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';
  parameters?: EndpointParameter[];
  authentication?: boolean;
  authorization?: string;
  location?: CodeLocation;
}

export interface EndpointParameter {
  name: string;
  location: 'query' | 'body' | 'header' | 'path';
  type: string;
  required?: boolean;
}

export interface TechStackInfo {
  /** Server header value */
  server?: string;
  /** X-Powered-By header value */
  poweredBy?: string;
  /** Detected frontend frameworks */
  frameworks?: string[];
  /** Detected BaaS provider */
  baas?: {
    provider: 'supabase' | 'firebase' | 'other';
    features: string[];
  };
  /** Detected authentication providers */
  authProviders?: string[];
  /** Detected auth mechanism */
  authMechanism?: {
    type: string;
    provider?: string;
  };
  /** Backend framework if detected */
  backendFramework?: string;
  /** Database type if detected */
  databaseType?: string;
  /** Hosting platform if detected */
  hostingPlatform?: string;
}

export interface ExternalService {
  name: string;
  type: string;
}

export interface AuthMechanism {
  type: 'jwt' | 'session' | 'oauth' | 'apikey' | 'basic' | 'custom';
  provider?: string;
  location: 'header' | 'cookie' | 'query' | 'body';
  flows: string[];
}

export interface ConfigFile {
  path: string;
  accessible: boolean;
  sensitive?: boolean;
}

export interface VCVFPattern {
  type: string;
  locations: CodeLocation[];
  confidence: number;
}

export interface CodeLocation {
  file: string;
  line?: number;
  snippet?: string;
}

export interface DataFlow {
  source: string;
  sink: string;
  transformation: string;
}

/**
 * Result returned by an agent after execution
 */
export interface AgentResult {
  /** Agent that produced this result */
  agentId: AgentId;
  /** Execution status */
  status: AgentStatus;
  /** Findings discovered */
  findings: Finding[];
  /** Execution metadata */
  metadata: AgentMetadata;
  /** Error message if failed */
  error?: string;
  /** Duration in milliseconds */
  duration: number;
}

export interface AgentMetadata {
  /** Tokens used by LLM */
  tokensUsed?: number;
  /** HTTP requests made */
  requestsMade?: number;
  /** Files analyzed */
  filesAnalyzed?: number;
  /** Endpoints tested */
  endpointsTested?: number;
  /** Custom metadata */
  custom?: Record<string, unknown>;
}

/**
 * Base agent interface that all agents must implement
 */
export interface BaseAgent {
  /** Unique agent identifier */
  id: AgentId;
  /** Human-readable name */
  name: string;
  /** Agent description */
  description: string;
  /** OWASP categories this agent covers */
  categories: string[];
  /** Agent priority */
  priority: AgentPriority;

  /** Execute the agent */
  execute(context: AgentContext): Promise<AgentResult>;

  /** Get system prompt for LLM */
  getSystemPrompt(): string;

  /** Build user prompt from context */
  buildUserPrompt(context: AgentContext): string;

  /** Parse LLM response into findings */
  parseResponse(response: string, context: AgentContext): Promise<Finding[]>;

  /** Validate a finding */
  validateFinding(finding: Finding): Promise<Finding>;

  /** Optional: Run before main execution */
  setup?(context: AgentContext): Promise<void>;

  /** Optional: Run after main execution */
  teardown?(context: AgentContext): Promise<void>;
}

/**
 * Zod schema for AgentResult validation
 */
export const AgentResultSchema = z.object({
  agentId: z.enum([
    'recon',
    'baas',
    'secrets',
    'auth',
    'injection',
    'supply_chain',
    'business_logic',
    'race_condition',
    'exploit',
    'fix',
  ]),
  status: z.enum(['pending', 'running', 'completed', 'failed', 'skipped']),
  findings: z.array(z.any()), // FindingSchema would be circular here
  metadata: z.object({
    tokensUsed: z.number().optional(),
    requestsMade: z.number().optional(),
    filesAnalyzed: z.number().optional(),
    endpointsTested: z.number().optional(),
    custom: z.record(z.unknown()).optional(),
  }),
  error: z.string().optional(),
  duration: z.number(),
});

/**
 * Exploit narrative attached to findings by the exploit agent
 */
export interface ExploitNarrative {
  findingId: string;
  attackSteps: string[];
  pocCommand: string;
  whyItWorks: string;
  trustBoundary: string;
  fix: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  runnable: boolean;
}

/**
 * Fix patch generated by the fix agent
 */
export interface FixPatch {
  findingId: string;
  filePath: string;
  description: string;
  diff: string;
  before: string;
  after: string;
  reasoning: string;
  confidence: number;
  autoApplicable: boolean;
}