import { z } from 'zod';

/**
 * LLM Provider type
 */
export type LLMProvider = 'anthropic' | 'openrouter' | 'gemini' | 'openai' | 'zenmux' | 'nvidia';

/**
 * LLM configuration
 */
export interface LLMConfig {
  /** Provider to use */
  provider: LLMProvider;
  /** API key (can also be set via environment) */
  apiKey?: string;
  /** Model to use */
  model?: string;
  /** Max tokens */
  maxTokens?: number;
  /** Temperature */
  temperature?: number;
  /** Base URL override */
  baseUrl?: string;
}

/**
 * Default LLM configurations per provider
 */
export const DEFAULT_LLM_CONFIGS: Record<LLMProvider, { model: string; maxTokens: number }> = {
  anthropic: {
    model: 'claude-sonnet-4-6',
    maxTokens: 4096,
  },
  openrouter: {
    model: 'nvidia/nemotron-3-ultra-550b-a55b:free',
    maxTokens: 4096,
  },
  gemini: {
    model: 'gemini-2.5-flash',
    maxTokens: 4096,
  },
  openai: {
    model: 'gpt-4o',
    maxTokens: 4096,
  },
  zenmux: {
    model: 'stepfun/step-3.7-flash-free',
    maxTokens: 4096,
  },
  nvidia: {
    model: 'meta/llama-3.3-70b-instruct',
    maxTokens: 4096,
  },
};

/**
 * LLM message format
 */
export interface LLMMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

/**
 * LLM completion request
 */
export interface LLMRequest {
  /** System prompt */
  system?: string;
  /** Conversation messages */
  messages: LLMMessage[];
  /** Maximum tokens to generate */
  maxTokens?: number;
  /** Temperature (0-1) */
  temperature?: number;
  /** Response format schema (for structured output) */
  responseFormat?: z.ZodType<unknown>;
  /** Stop sequences */
  stopSequences?: string[];
}

/**
 * LLM completion response
 */
export interface LLMResponse {
  /** Generated text */
  content: string;
  /** Tokens used (input + output) */
  tokensUsed: {
    input: number;
    output: number;
    total: number;
  };
  /** Model used */
  model: string;
  /** Provider used */
  provider: LLMProvider;
  /** Duration in milliseconds */
  duration: number;
  /** Parsed structured output (if responseFormat was provided) */
  parsedOutput?: unknown;
}

/**
 * LLM provider status
 */
export interface LLMProviderStatus {
  /** Provider name */
  provider: LLMProvider;
  /** Whether the provider is available */
  available: boolean;
  /** API key is configured */
  hasApiKey: boolean;
  /** Priority order */
  priority: number;
  /** Error message if unavailable */
  error?: string;
}

/**
 * Reasoning step for chain-of-thought
 */
export interface ReasoningStep {
  /** Step number */
  step: number;
  /** Step type */
  type: 'observation' | 'hypothesis' | 'test' | 'conclusion';
  /** Step description */
  description: string;
  /** Finding if any */
  finding?: string;
  /** Confidence in this step */
  confidence: number;
}

/**
 * Structured LLM output for findings
 */
export const FindingOutputSchema = z.object({
  title: z.string(),
  description: z.string(),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  category: z.string(),
  cvssScore: z.number().min(0).max(10),
  confidence: z.number().min(0).max(1),
  evidence: z.object({
    request: z.string().optional(),
    response: z.string().optional(),
    file: z.string().optional(),
    line: z.number().optional(),
    payload: z.string().optional(),
    context: z.record(z.unknown()).optional(),
  }),
  remediation: z.object({
    summary: z.string(),
    steps: z.array(z.string()),
    codeExample: z.string().optional(),
    references: z.array(z.string()).optional(),
    effort: z.enum(['trivial', 'low', 'medium', 'high']),
    priority: z.number(),
  }),
  tags: z.array(z.string()),
});

/**
 * Multiple findings output schema
 */
export const FindingsOutputSchema = z.object({
  findings: z.array(FindingOutputSchema),
  reasoning: z.array(z.object({
    step: z.number(),
    type: z.enum(['observation', 'hypothesis', 'test', 'conclusion']),
    description: z.string(),
    confidence: z.number(),
  })),
  summary: z.string(),
});