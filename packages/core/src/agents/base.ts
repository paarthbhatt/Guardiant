import type {
  BaseAgent,
  AgentId,
  AgentContext,
  AgentResult,
  AgentConfig,
  AgentPriority,
  Finding,
} from '@guardiant/shared';

/**
 * Abstract base class for all security agents
 */
export abstract class AbstractAgent implements BaseAgent {
  abstract readonly id: AgentId;
  abstract readonly name: string;
  abstract readonly description: string;
  abstract readonly categories: string[];
  abstract readonly priority: AgentPriority;

  /**
   * Execute the agent
   */
  abstract execute(context: AgentContext): Promise<AgentResult>;

  /**
   * Get the system prompt for the LLM
   */
  abstract getSystemPrompt(): string;

  /**
   * Build the user prompt from context
   */
  abstract buildUserPrompt(context: AgentContext): string;

  /**
   * Parse LLM response into findings
   */
  abstract parseResponse(response: string, context: AgentContext): Promise<Finding[]>;

  /**
   * Validate a finding to reduce false positives
   */
  async validateFinding(finding: Finding): Promise<Finding> {
    // Default implementation - can be overridden
    // Basic validation checks
    if (!finding.title || !finding.description) {
      throw new Error('Finding must have title and description');
    }

    // Adjust confidence based on evidence
    if (!finding.evidence.request && !finding.evidence.response && !finding.evidence.payload) {
      finding.confidence = Math.min(finding.confidence, 0.7);
    }

    return finding;
  }

  /**
   * Optional setup before execution
   */
  async setup?(context: AgentContext): Promise<void>;

  /**
   * Optional cleanup after execution
   */
  async teardown?(context: AgentContext): Promise<void>;

  /**
   * Calculate duration in milliseconds
   */
  protected getDuration(startTime: number): number {
    return Date.now() - startTime;
  }

  /**
   * Create a success result
   */
  protected createSuccessResult(
    findings: Finding[],
    metadata: AgentResult['metadata'],
    duration: number
  ): AgentResult {
    return {
      agentId: this.id,
      status: 'completed',
      findings,
      metadata,
      duration,
    };
  }

  /**
   * Create an error result
   */
  protected createErrorResult(error: Error, duration: number): AgentResult {
    return {
      agentId: this.id,
      status: 'failed',
      findings: [],
      metadata: {},
      error: error.message,
      duration,
    };
  }
}

/**
 * Agent constructor type
 */
export type AgentConstructor = new (config?: AgentConfig) => BaseAgent;