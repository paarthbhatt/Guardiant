import type { AgentJobData, JobResult, AgentJobResult, ReconJobResult } from '../types.js';
import type { AgentId, AgentContext, Finding, ReconData } from '@guardiant/shared';

/**
 * Agent job interface
 */
export interface AgentJob {
  id: string;
  name: string;
  data: AgentJobData;
  priority: number;
  attempts: number;
  maxAttempts: number;
}

/**
 * Agent job handlers
 */
export interface AgentJobHandlers {
  getAgent: (agentId: AgentId) => {
    execute: (context: AgentContext) => Promise<{ findings: Finding[]; metadata: Record<string, unknown> }>;
  } | undefined;
  updateProgress: (scanId: string, agentId: AgentId, progress: number, message: string) => Promise<void>;
  storeResults: (scanId: string, agentId: AgentId, results: AgentJobResult) => Promise<void>;
}

/**
 * Process agent job
 */
export async function processAgentJob(
  job: AgentJob,
  handlers: AgentJobHandlers
): Promise<JobResult<AgentJobResult>> {
  const startTime = Date.now();
  const { scanId, agentId, target, reconData } = job.data;

  try {
    // Get agent implementation
    const agent = handlers.getAgent(agentId);
    if (!agent) {
      throw new Error(`Agent ${agentId} not found`);
    }

    // Update progress
    await handlers.updateProgress(scanId, agentId, 0, 'Starting agent...');

    // Build agent context
    const context: AgentContext = {
      scanId,
      target: {
        url: target,
        type: 'url', // Will be determined by config
      },
      // ReconJobResult is a lightweight DTO; cast to ReconData for agent use
      reconData: reconData as unknown as ReconData,
      config: {
        enabled: true,
        priority: 'high',
        timeout: 300000,
        maxRetries: 2,
      },
    };

    // Execute agent
    await handlers.updateProgress(scanId, agentId, 50, 'Executing security tests...');
    const result = await agent.execute(context);

    // Create job result
    const jobResult: AgentJobResult = {
      agentId,
      status: 'completed',
      findings: result.findings.map(f => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        category: f.category,
      })),
      duration: Date.now() - startTime,
      metadata: result.metadata,
    };

    // Store results
    await handlers.storeResults(scanId, agentId, jobResult);
    await handlers.updateProgress(scanId, agentId, 100, 'Agent completed');

    return {
      success: true,
      data: jobResult,
      duration: Date.now() - startTime,
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    const jobResult: AgentJobResult = {
      agentId,
      status: 'failed',
      findings: [],
      error: errorMessage,
      duration: Date.now() - startTime,
    };

    await handlers.storeResults(scanId, agentId, jobResult);
    await handlers.updateProgress(scanId, agentId, 100, `Agent failed: ${errorMessage}`);

    return {
      success: false,
      error: errorMessage,
      duration: Date.now() - startTime,
    };
  }
}

/**
 * Create agent job data
 */
export function createAgentJobData(
  scanId: string,
  agentId: AgentId,
  target: string,
  reconData?: ReconJobResult
): AgentJobData {
  return {
    scanId,
    agentId,
    target,
    reconData,
  };
}

