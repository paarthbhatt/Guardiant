import { describe, it, expect, beforeEach, vi } from 'vitest';
import { AbstractAgent } from '../agents/base.js';
import type { AgentContext, AgentResult, Finding } from '@guardiant/shared';

/**
 * Concrete test implementation of AbstractAgent
 */
class TestAgent extends AbstractAgent {
  readonly id = 'recon' as const;
  readonly name = 'Test Agent';
  readonly description = 'A test agent';
  readonly categories = ['A01_BROKEN_ACCESS_CONTROL'];
  readonly priority = 'high' as const;

  async execute(context: AgentContext): Promise<AgentResult> {
    return this.createSuccessResult([], { endpointsTested: 0 }, 100);
  }

  getSystemPrompt(): string {
    return 'You are a test agent.';
  }

  buildUserPrompt(context: AgentContext): string {
    return `Testing ${context.target.url}`;
  }

  async parseResponse(response: string, context: AgentContext): Promise<Finding[]> {
    return [];
  }

  // Expose protected methods for testing
  public testCreateSuccessResult(findings: Finding[], metadata: AgentResult['metadata'], duration: number) {
    return this.createSuccessResult(findings, metadata, duration);
  }

  public testCreateErrorResult(error: Error, duration: number) {
    return this.createErrorResult(error, duration);
  }

  public testGetDuration(startTime: number) {
    return this.getDuration(startTime);
  }
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'f1',
    title: 'Test Finding',
    description: 'Test description',
    severity: 'medium',
    category: 'A03_INJECTION',
    cvssScore: 5.0,
    confidence: 0.8,
    discoveredBy: 'recon',
    timestamp: new Date().toISOString(),
    evidence: {},
    remediation: {
      summary: 'Fix it',
      steps: ['Step 1'],
      effort: 'low',
      priority: 3,
    },
    status: 'open',
    tags: [],
    ...overrides,
  };
}

describe('AbstractAgent.createSuccessResult', () => {
  let agent: TestAgent;

  beforeEach(() => {
    agent = new TestAgent();
  });

  it('should return a result with status completed', () => {
    const result = agent.testCreateSuccessResult([], {}, 100);
    expect(result.status).toBe('completed');
    expect(result.agentId).toBe('recon');
    expect(result.findings).toEqual([]);
    expect(result.duration).toBe(100);
  });

  it('should include provided findings', () => {
    const findings = [makeFinding()];
    const result = agent.testCreateSuccessResult(findings, {}, 200);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].id).toBe('f1');
  });
});

describe('AbstractAgent.createErrorResult', () => {
  let agent: TestAgent;

  beforeEach(() => {
    agent = new TestAgent();
  });

  it('should return a result with status failed', () => {
    const error = new Error('Something went wrong');
    const result = agent.testCreateErrorResult(error, 50);
    expect(result.status).toBe('failed');
    expect(result.error).toBe('Something went wrong');
    expect(result.findings).toEqual([]);
    expect(result.agentId).toBe('recon');
  });
});

describe('AbstractAgent.getDuration', () => {
  let agent: TestAgent;

  beforeEach(() => {
    agent = new TestAgent();
  });

  it('should return elapsed milliseconds since start', async () => {
    const start = Date.now() - 100;
    const duration = agent.testGetDuration(start);
    expect(duration).toBeGreaterThanOrEqual(100);
  });
});

describe('AbstractAgent.validateFinding', () => {
  let agent: TestAgent;

  beforeEach(() => {
    agent = new TestAgent();
  });

  it('should return finding unchanged when evidence is present', async () => {
    const finding = makeFinding({ evidence: { request: 'GET /api', payload: "' OR 1=1" } });
    const validated = await agent.validateFinding(finding);
    expect(validated.confidence).toBe(0.8); // unchanged
  });

  it('should cap confidence at 0.7 when no evidence', async () => {
    const finding = makeFinding({ confidence: 0.95, evidence: {} });
    const validated = await agent.validateFinding(finding);
    expect(validated.confidence).toBe(0.7);
  });

  it('should throw when title is missing', async () => {
    const finding = makeFinding({ title: '' });
    await expect(agent.validateFinding(finding)).rejects.toThrow('Finding must have title and description');
  });

  it('should throw when description is missing', async () => {
    const finding = makeFinding({ description: '' });
    await expect(agent.validateFinding(finding)).rejects.toThrow('Finding must have title and description');
  });
});
