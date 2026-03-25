import type { AgentId, ScanConfig } from '@guardiant/shared';

/**
 * Job types
 */
export type JobType = 'scan' | 'agent' | 'analysis' | 'report';

/**
 * Job status
 */
export type JobStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

/**
 * Job priority levels
 */
export type JobPriority = 'critical' | 'high' | 'normal' | 'low';

/**
 * Scan job data
 */
export interface ScanJobData {
  scanId: string;
  config: ScanConfig;
}

/**
 * Agent job data
 */
export interface AgentJobData {
  scanId: string;
  agentId: AgentId;
  target: ScanConfig['target'];
  reconData?: ReconJobResult;
}

/**
 * Analysis job data
 */
export interface AnalysisJobData {
  scanId: string;
  agentResults: Record<AgentId, AgentJobResult>;
}

/**
 * Report job data
 */
export interface ReportJobData {
  scanId: string;
  audience: 'executive' | 'developer' | 'security';
  format: 'json' | 'markdown' | 'html' | 'pdf';
}

/**
 * Recon job result
 */
export interface ReconJobResult {
  endpoints: Array<{
    path: string;
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';
    parameters?: Array<{ name: string; location: 'query' | 'body' | 'header' | 'path'; type: string; required?: boolean }>;
  }>;
  techStack: {
    frontend?: { framework: string };
    backend?: { framework: string };
    baas?: { provider: 'supabase' | 'firebase' | 'other'; features: string[] };
  };
  authMechanisms: Array<{ type: string; provider?: string }>;
  vcvfPatterns: Array<{ type: string; confidence: number }>;
  externalServices: Array<{ name: string; type: string }>;
  sourceMapsAvailable: boolean;
  configFiles: Array<{ path: string; accessible: boolean; sensitive?: boolean }>;
  dataFlows: Array<{ source: string; sink: string; transformation: string }>;
}

/**
 * Agent job result
 */
export interface AgentJobResult {
  agentId: AgentId;
  status: JobStatus;
  findings: Array<{
    id: string;
    title: string;
    severity: string;
    category: string;
  }>;
  error?: string;
  duration: number;
  metadata?: Record<string, unknown>;
}

/**
 * Job result type
 */
export type JobResult<T> = {
  success: boolean;
  data?: T;
  error?: string;
  duration: number;
};

/**
 * Queue configuration
 */
export interface QueueConfig {
  /** Queue name */
  name: string;
  /** Concurrency */
  concurrency?: number;
  /** Job timeout in ms */
  timeout?: number;
  /** Max retries */
  maxRetries?: number;
  /** Backoff strategy */
  backoff?: {
    type: 'exponential' | 'fixed';
    delay: number;
  };
}

/**
 * Default queue configurations
 */
export const QUEUE_CONFIGS: Record<string, QueueConfig> = {
  scan: {
    name: 'scans',
    concurrency: 1,
    timeout: 600000, // 10 minutes
    maxRetries: 1,
    backoff: { type: 'exponential', delay: 5000 },
  },
  agent: {
    name: 'agents',
    concurrency: 4,
    timeout: 300000, // 5 minutes
    maxRetries: 2,
    backoff: { type: 'exponential', delay: 3000 },
  },
  analysis: {
    name: 'analysis',
    concurrency: 1,
    timeout: 120000, // 2 minutes
    maxRetries: 2,
    backoff: { type: 'fixed', delay: 2000 },
  },
  report: {
    name: 'reports',
    concurrency: 2,
    timeout: 60000, // 1 minute
    maxRetries: 3,
    backoff: { type: 'fixed', delay: 1000 },
  },
};