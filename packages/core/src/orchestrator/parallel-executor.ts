/**
 * Parallel executor for running agents concurrently
 */

import type { AgentId, AgentResult, AgentContext, BaseAgent } from '@guardiant/shared';
import { createLogger } from '@guardiant/shared';

import { AGENT_DEPENDENCIES } from './constants.js';

const logger = createLogger({ level: 'info' });

/**
 * Execution result
 */
export interface ExecutionResult {
  agentId: AgentId;
  result: AgentResult;
  duration: number;
}

/**
 * Parallel execution options
 */
export interface ParallelOptions {
  maxConcurrency?: number;
  timeout?: number;
  retries?: number;
}

/**
 * Default parallel options
 */
const DEFAULT_PARALLEL_OPTIONS: Required<ParallelOptions> = {
  maxConcurrency: 4,
  timeout: 300000, // 5 minutes
  retries: 1,
};

/**
 * Parallel agent executor
 */
export class ParallelExecutor {
  private options: Required<ParallelOptions>;

  constructor(options: ParallelOptions = {}) {
    this.options = { ...DEFAULT_PARALLEL_OPTIONS, ...options };
  }

  /**
   * Execute agents in parallel respecting dependencies
   */
  async execute(
    agents: BaseAgent[],
    context: AgentContext
  ): Promise<ExecutionResult[]> {
    const results: ExecutionResult[] = [];
    const completed = new Set<AgentId>();

    // Phase 1: Run recon first
    const reconAgent = agents.find(a => a.id === 'recon');
    if (reconAgent) {
      logger.info('Executing recon agent...');
      const result = await this.executeAgent(reconAgent, context);
      results.push(result);
      completed.add('recon');

      // Update context with recon data
      if (result.result.status === 'completed' && result.result.metadata.custom?.reconData) {
        context.reconData = result.result.metadata.custom.reconData as AgentContext['reconData'];
      }
    }

    // Phase 2: Run remaining agents in parallel
    const remainingAgents = agents.filter(a => a.id !== 'recon');
    const batches = this.createBatches(remainingAgents, completed);

    for (const batch of batches) {
      logger.info(`Executing batch of ${batch.length} agents...`);

      const batchPromises = batch.map(agent => this.executeAgent(agent, context));
      const batchResults = await Promise.all(batchPromises);

      results.push(...batchResults);

      // Mark all as completed
      for (const result of batchResults) {
        completed.add(result.agentId);
      }
    }

    return results;
  }

  /**
   * Execute a single agent
   */
  private async executeAgent(agent: BaseAgent, context: AgentContext): Promise<ExecutionResult> {
    const startTime = Date.now();

    try {
      // Run with timeout
      const result = await Promise.race([
        agent.execute(context),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error(`Agent ${agent.id} timed out`)), this.options.timeout)
        ),
      ]);

      return {
        agentId: agent.id,
        result,
        duration: Date.now() - startTime,
      };
    } catch (error) {
      return {
        agentId: agent.id,
        result: {
          agentId: agent.id,
          status: 'failed',
          findings: [],
          metadata: {},
          error: error instanceof Error ? error.message : 'Unknown error',
          duration: Date.now() - startTime,
        },
        duration: Date.now() - startTime,
      };
    }
  }

  /**
   * Create execution batches respecting dependencies
   */
  private createBatches(agents: BaseAgent[], completed: Set<AgentId>): BaseAgent[][] {
    const batches: BaseAgent[][] = [];
    const pending = new Set(agents.map(a => a.id));
    const inBatch = new Set<AgentId>();

    while (pending.size > 0) {
      const batch: BaseAgent[] = [];

      for (const agentId of pending) {
        if (inBatch.has(agentId)) continue;

        // Check if all dependencies are completed
        const deps = AGENT_DEPENDENCIES[agentId] ?? [];
        const depsMet = deps.every(dep => completed.has(dep) || inBatch.has(dep));

        if (depsMet) {
          const agent = agents.find(a => a.id === agentId);
          if (agent) {
            batch.push(agent);
            inBatch.add(agentId);
          }
        }
      }

      // Limit batch size by concurrency
      const limitedBatch = batch.slice(0, this.options.maxConcurrency);
      if (limitedBatch.length > 0) {
        batches.push(limitedBatch);
        for (const agent of limitedBatch) {
          pending.delete(agent.id);
          inBatch.delete(agent.id);
        }
      } else {
        // No progress - there might be a circular dependency or all deps not met
        // Just run remaining agents
        const remaining = agents.filter(a => pending.has(a.id));
        batches.push(remaining);
        break;
      }
    }

    return batches;
  }

  /**
   * Execute with retry logic
   */
  async executeWithRetry(
    agent: BaseAgent,
    context: AgentContext,
    retries: number = this.options.retries
  ): Promise<ExecutionResult> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        return await this.executeAgent(agent, context);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error('Unknown error');
        logger.warn(`Agent ${agent.id} failed on attempt ${attempt + 1}/${retries + 1}:`, error);

        if (attempt < retries) {
          // Exponential backoff
          await new Promise(resolve => setTimeout(resolve, 1000 * Math.pow(2, attempt)));
        }
      }
    }

    return {
      agentId: agent.id,
      result: {
        agentId: agent.id,
        status: 'failed',
        findings: [],
        metadata: {},
        error: lastError?.message ?? 'Unknown error',
        duration: 0,
      },
      duration: 0,
    };
  }
}

/**
 * Create parallel executor
 */
export function createParallelExecutor(options?: ParallelOptions): ParallelExecutor {
  return new ParallelExecutor(options);
}