import Anthropic from '@anthropic-ai/sdk';
import OpenAI from 'openai';
import type { LLMProvider, LLMConfig, LLMRequest, LLMResponse } from '@guardiant/shared';
import { DEFAULT_LLM_CONFIGS } from '@guardiant/shared';
import { z } from 'zod';
import { zodToJsonSchema } from 'zod-to-json-schema';

/**
 * LLM Provider interface
 */
interface LLMProviderClient {
  name: LLMProvider;
  available: () => Promise<boolean>;
  complete: (request: LLMRequest) => Promise<LLMResponse>;
}

/**
 * Process-wide LLM runtime status (BATCAVE-89 fix #2).
 *
 * The scan command reads this to report honestly instead of always printing
 * "completed successfully": if AI was requested but no provider was configured,
 * or if LLM calls failed / rate-limited, the scan is PARTIAL for LLM-dependent
 * rules — never reported as a full success.
 */
export interface LlmRuntimeStatus {
  /** GUARDIANT_ENABLE_AI === '1' AND an explicit provider was named. */
  requested: boolean;
  /** How many providers were actually initialised (0 = static only). */
  providersInitialized: number;
  /** Count of failed LLM completions (rate-limit, quota, auth, empty, ...). */
  failures: number;
  /** Most recent LLM error message, for the honest status line. */
  lastError?: string;
}

const DEFAULT_REQUEST_TIMEOUT_MS = 20_000;
const DEFAULT_MAX_TOKENS = 2_048;

function boundedEnvNumber(name: string, fallback: number, min: number, max: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') return fallback;
  const value = Number(raw);
  return Number.isFinite(value) && value >= min && value <= max ? value : fallback;
}

function llmRequestTimeoutMs(): number {
  return boundedEnvNumber('GUARDIANT_AI_TIMEOUT_MS', DEFAULT_REQUEST_TIMEOUT_MS, 1_000, 120_000);
}

function llmMaxTokens(): number {
  return boundedEnvNumber('GUARDIANT_AI_MAX_TOKENS', DEFAULT_MAX_TOKENS, 256, 16_384);
}

export const llmRuntimeStatus: LlmRuntimeStatus = {
  requested: false,
  providersInitialized: 0,
  failures: 0,
};

export function recordLlmFailure(error: unknown): void {
  llmRuntimeStatus.failures += 1;
  llmRuntimeStatus.lastError = error instanceof Error ? error.message : String(error);
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    const error = new Error('LLM request aborted');
    error.name = 'AbortError';
    throw error;
  }
}

function waitWithAbort(ms: number, signal?: AbortSignal): Promise<void> {
  if (!signal) return new Promise(resolve => setTimeout(resolve, ms));
  throwIfAborted(signal);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      const error = new Error('LLM request aborted');
      error.name = 'AbortError';
      reject(error);
    };
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * Multi-provider LLM client with automatic fallback
 */
export class LLMClient {
  private providers: LLMProviderClient[] = [];
  private defaultConfig: LLMConfig;
  private lastRequestTimes = new Map<string, number>();
  private disabledProviders = new Set<string>();

  constructor(config: Partial<LLMConfig> = {}) {
    this.defaultConfig = {
      provider: 'anthropic',
      maxTokens: llmMaxTokens(),
      temperature: 0.7,
      ...config,
    };

    this.initializeProviders();
  }

  private initializeProviders(): void {
    // DETERMINISM / HONESTY CONTRACT (BATCAVE-89 fix #2):
    // The LLM layer is OFF unless explicitly enabled, and it never
    // auto-consumes whatever provider key happens to be exported. AI runs only
    // when GUARDIANT_ENABLE_AI === '1', and then only the single provider named
    // by GUARDIANT_AI_PROVIDER is initialised. This prevents the scanner from
    // silently picking up e.g. GEMINI_API_KEY and producing non-deterministic
    // results across runs.
    this.providers = [];

    if (process.env.GUARDIANT_ENABLE_AI !== '1') {
      llmRuntimeStatus.requested = false;
      llmRuntimeStatus.providersInitialized = 0;
      return; // deterministic static-only scan
    }

    const explicit = (process.env.GUARDIANT_AI_PROVIDER || '').trim().toLowerCase();
    llmRuntimeStatus.requested = true;
    if (!explicit) {
      llmRuntimeStatus.providersInitialized = 0;
      return; // enabled but no explicit provider -> no LLM (caller reports PARTIAL)
    }

    const factories: Record<string, () => LLMProviderClient | null> = {
      nvidia: () => this.createNvidiaProvider(),
      openrouter: () => this.createOpenRouterProvider(),
      gemini: () => this.createGeminiProvider(),
      zenmux: () => this.createZenmuxProvider(),
      anthropic: () => this.createAnthropicProvider(),
      openai: () => this.createOpenAIProvider(),
    };

    const make = factories[explicit];
    if (!make) {
      llmRuntimeStatus.providersInitialized = 0;
      return;
    }
    const provider = make();
    if (provider) {
      this.providers = [provider];
    }
    llmRuntimeStatus.providersInitialized = this.providers.length;
  }

  /**
   * Create Anthropic provider
   */
  private createAnthropicProvider(): LLMProviderClient | null {
    const apiKey = process.env.ANTHROPIC_API_KEY ?? this.defaultConfig.apiKey;
    if (!apiKey) return null;

    const client = new Anthropic({ apiKey });

    return {
      name: 'anthropic',
      available: async () => true,
      complete: async (request: LLMRequest) => {
        const startTime = Date.now();
        const model = this.defaultConfig.model ?? DEFAULT_LLM_CONFIGS.anthropic.model;
        const maxTokens = request.maxTokens ?? this.defaultConfig.maxTokens ?? DEFAULT_LLM_CONFIGS.anthropic.maxTokens;

        const response = await client.messages.create({
          model,
          max_tokens: maxTokens,
          system: request.system,
          messages: request.messages.map(m => ({
            role: m.role as 'user' | 'assistant',
            content: m.content,
          })),
        }, request.signal ? { signal: request.signal } : undefined);

        const content = response.content
          .filter(block => block.type === 'text')
          .map(block => (block as Anthropic.TextBlock).text)
          .join('');

        return {
          content,
          tokensUsed: {
            input: response.usage.input_tokens,
            output: response.usage.output_tokens,
            total: response.usage.input_tokens + response.usage.output_tokens,
          },
          model,
          provider: 'anthropic',
          duration: Date.now() - startTime,
        };
      },
    };
  }

  /**
   * Create OpenAI provider
   */
  private createOpenAIProvider(): LLMProviderClient | null {
    const apiKey = process.env.OPENAI_API_KEY ?? this.defaultConfig.apiKey;
    if (!apiKey) return null;

    const client = new OpenAI({
      apiKey,
      baseURL: process.env.OPENAI_BASE_URL ?? 'https://api.openai.com/v1',
      timeout: llmRequestTimeoutMs(),
      maxRetries: 0,
    });

    return {
      name: 'openai',
      available: async () => true,
      complete: async (request: LLMRequest) => {
        const startTime = Date.now();
        const model = process.env.OPENAI_MODEL ?? process.env.GUARDIANT_OPENAI_MODEL ?? this.defaultConfig.model ?? DEFAULT_LLM_CONFIGS.openai.model;
        const maxTokens = request.maxTokens ?? this.defaultConfig.maxTokens ?? DEFAULT_LLM_CONFIGS.openai.maxTokens;

        const messages: OpenAI.ChatCompletionMessageParam[] = [];
        if (request.system) {
          messages.push({ role: 'system', content: request.system });
        }
        for (const m of request.messages) {
          messages.push({
            role: m.role as 'system' | 'user' | 'assistant',
            content: m.content,
          });
        }

        const response = await client.chat.completions.create({
          model,
          max_tokens: maxTokens,
          messages,
        }, request.signal ? { signal: request.signal } : undefined);

        const content = response.choices[0]?.message.content ?? '';

        return {
          content,
          tokensUsed: {
            input: response.usage?.prompt_tokens ?? 0,
            output: response.usage?.completion_tokens ?? 0,
            total: (response.usage?.prompt_tokens ?? 0) + (response.usage?.completion_tokens ?? 0),
          },
          model,
          provider: 'openai',
          duration: Date.now() - startTime,
        };
      },
    };
  }

  /**
   * Create Zenmux provider
   */
  private createZenmuxProvider(): LLMProviderClient | null {
    const apiKey = process.env.ZENMUX_API_KEY;
    if (!apiKey) return null;

    const client = new OpenAI({
      apiKey,
      baseURL: process.env.ZENMUX_BASE_URL ?? 'https://zenmux.ai/api/v1',
    });

    return {
      name: 'zenmux',
      available: async () => true,
      complete: async (request: LLMRequest) => {
        const startTime = Date.now();
        const model = process.env.ZENMUX_MODEL ?? DEFAULT_LLM_CONFIGS.zenmux.model;
        const maxTokens = request.maxTokens ?? this.defaultConfig.maxTokens ?? DEFAULT_LLM_CONFIGS.zenmux.maxTokens;

        const messages: OpenAI.ChatCompletionMessageParam[] = [];
        if (request.system) {
          messages.push({ role: 'system', content: request.system });
        }
        for (const m of request.messages) {
          messages.push({
            role: m.role as 'system' | 'user' | 'assistant',
            content: m.content,
          });
        }

        const response = await client.chat.completions.create({
          model,
          max_tokens: maxTokens,
          messages,
        }, request.signal ? { signal: request.signal } : undefined);

        const content = response.choices[0]?.message.content ?? '';

        return {
          content,
          tokensUsed: {
            input: response.usage?.prompt_tokens ?? 0,
            output: response.usage?.completion_tokens ?? 0,
            total: (response.usage?.prompt_tokens ?? 0) + (response.usage?.completion_tokens ?? 0),
          },
          model,
          provider: 'zenmux',
          duration: Date.now() - startTime,
        };
      },
    };
  }

  /**
   * Create Nvidia provider
   */
  private createNvidiaProvider(): LLMProviderClient | null {
    const apiKey = process.env.NVIDIA_API_KEY;
    if (!apiKey) return null;

    const client = new OpenAI({
      apiKey,
      baseURL: process.env.NVIDIA_BASE_URL ?? 'https://integrate.api.nvidia.com/v1',
    });

    return {
      name: 'nvidia',
      available: async () => true,
      complete: async (request: LLMRequest) => {
        const startTime = Date.now();
        const model = process.env.NVIDIA_MODEL ?? DEFAULT_LLM_CONFIGS.nvidia.model;
        const maxTokens = request.maxTokens ?? this.defaultConfig.maxTokens ?? DEFAULT_LLM_CONFIGS.nvidia.maxTokens;

        const messages: OpenAI.ChatCompletionMessageParam[] = [];
        if (request.system) {
          messages.push({ role: 'system', content: request.system });
        }
        for (const m of request.messages) {
          messages.push({
            role: m.role as 'system' | 'user' | 'assistant',
            content: m.content,
          });
        }

        const response = await client.chat.completions.create({
          model,
          max_tokens: maxTokens,
          messages,
        }, request.signal ? { signal: request.signal } : undefined);

        const content = response.choices[0]?.message.content ?? '';

        return {
          content,
          tokensUsed: {
            input: response.usage?.prompt_tokens ?? 0,
            output: response.usage?.completion_tokens ?? 0,
            total: (response.usage?.prompt_tokens ?? 0) + (response.usage?.completion_tokens ?? 0),
          },
          model,
          provider: 'nvidia',
          duration: Date.now() - startTime,
        };
      },
    };
  }

  /**
   * Create OpenRouter provider
   */
  private createOpenRouterProvider(): LLMProviderClient | null {
    const apiKey = process.env.OPENROUTER_API_KEY;
    if (!apiKey) return null;

    const client = new OpenAI({
      apiKey,
      baseURL: process.env.OPENROUTER_BASE_URL ?? 'https://openrouter.ai/api/v1',
      defaultHeaders: {
        'HTTP-Referer': 'https://guardiant.dev',
        'X-Title': 'Guardiant Security Scanner',
      },
    });

    return {
      name: 'openrouter',
      available: async () => true,
      complete: async (request: LLMRequest) => {
        const startTime = Date.now();
        const model = process.env.OPENROUTER_MODEL ?? DEFAULT_LLM_CONFIGS.openrouter.model;
        const maxTokens = request.maxTokens ?? this.defaultConfig.maxTokens ?? DEFAULT_LLM_CONFIGS.openrouter.maxTokens;

        const messages: OpenAI.ChatCompletionMessageParam[] = [];
        if (request.system) {
          messages.push({ role: 'system', content: request.system });
        }
        for (const m of request.messages) {
          messages.push({
            role: m.role as 'system' | 'user' | 'assistant',
            content: m.content,
          });
        }

        const response = await client.chat.completions.create({
          model,
          max_tokens: maxTokens,
          messages,
        }, request.signal ? { signal: request.signal } : undefined);

        const content = response.choices[0]?.message.content ?? '';

        return {
          content,
          tokensUsed: {
            input: response.usage?.prompt_tokens ?? 0,
            output: response.usage?.completion_tokens ?? 0,
            total: (response.usage?.prompt_tokens ?? 0) + (response.usage?.completion_tokens ?? 0),
          },
          model,
          provider: 'openrouter',
          duration: Date.now() - startTime,
        };
      },
    };
  }

  /**
   * Create Gemini provider
   */
  private createGeminiProvider(): LLMProviderClient | null {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) return null;

    const client = new OpenAI({
      apiKey,
      baseURL: process.env.GEMINI_BASE_URL ?? 'https://generativelanguage.googleapis.com/v1beta',
    });

    return {
      name: 'gemini',
      available: async () => true,
      complete: async (request: LLMRequest) => {
        const startTime = Date.now();
        const model = process.env.GEMINI_MODEL ?? DEFAULT_LLM_CONFIGS.gemini.model;
        const maxTokens = request.maxTokens ?? this.defaultConfig.maxTokens ?? DEFAULT_LLM_CONFIGS.gemini.maxTokens;

        const messages: OpenAI.ChatCompletionMessageParam[] = [];
        if (request.system) {
          messages.push({ role: 'system', content: request.system });
        }
        for (const m of request.messages) {
          messages.push({
            role: m.role as 'system' | 'user' | 'assistant',
            content: m.content,
          });
        }

        const response = await client.chat.completions.create({
          model,
          max_tokens: maxTokens,
          messages,
        }, request.signal ? { signal: request.signal } : undefined);

        const content = response.choices[0]?.message.content ?? '';

        return {
          content,
          tokensUsed: {
            input: response.usage?.prompt_tokens ?? 0,
            output: response.usage?.completion_tokens ?? 0,
            total: (response.usage?.prompt_tokens ?? 0) + (response.usage?.completion_tokens ?? 0),
          },
          model,
          provider: 'gemini',
          duration: Date.now() - startTime,
        };
      },
    };
  }

  /**
   * Complete a request using available providers with fallback
   */
  async complete(request: LLMRequest): Promise<LLMResponse> {
    const errors: Error[] = [];

    for (const provider of this.providers) {
      throwIfAborted(request.signal);
      if (this.disabledProviders.has(provider.name)) {
        continue;
      }
      try {
        const isAvailable = await provider.available();
        if (!isAvailable) {
          continue;
        }

        // Rate limits enforcing (to prevent crossing RPM limits)
        const now = Date.now();
        const minIntervals: Record<string, number> = {
          gemini: 4000,      // 15 RPM -> 4s interval
          nvidia: 1500,      // 40 RPM -> 1.5s interval
          openrouter: 500,   // minimal delay
          zenmux: 500,
          openai: 3000,      // OpenAI-compatible gateways (e.g. HCNSEC) throttle bursts -> 3s interval
        };
        const interval = minIntervals[provider.name] ?? 0;
        const lastTime = this.lastRequestTimes.get(provider.name) ?? 0;
        const elapsed = now - lastTime;
        if (elapsed < interval) {
          const waitTime = interval - elapsed;
          await waitWithAbort(waitTime, request.signal);
        }

        throwIfAborted(request.signal);
        const response = await provider.complete(request);
        if (!response.content || response.content.trim() === '') {
          throw new Error('LLM returned an empty response');
        }
        this.lastRequestTimes.set(provider.name, Date.now());
        return response;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        errors.push(new Error(`${provider.name}: ${errorMessage}`));
        console.warn(`LLM provider ${provider.name} failed, trying next provider...`);
        
        // Disable provider for the rest of the scan session on permanent failure triggers
        const errUpper = errorMessage.toUpperCase();
        if (
          errUpper.includes('QUOTA') ||
          errUpper.includes('EXHAUSTED') ||
          errUpper.includes('401') ||
          errUpper.includes('UNAUTHORIZED') ||
          errUpper.includes('BILLING') ||
          errUpper.includes('NOT_FOUND') ||
          errUpper.includes('NOT FOUND')
        ) {
          console.warn(`LLM provider ${provider.name} disabled for session due to permanent error.`);
          this.disabledProviders.add(provider.name);
        }
        continue;
      }
    }

    recordLlmFailure(new Error(errors.map(e => e.message).join('; ')));
    throw new Error(
      `All LLM providers failed: ${errors.map(e => e.message).join('; ')}`
    );
  }

  /**
   * Complete with structured output using Zod schema
   */
  async completeStructured<T>(
    request: LLMRequest,
    schema: z.ZodType<T>
  ): Promise<{ data: T; response: LLMResponse }> {
    const jsonSchema = zodToJsonSchema(schema);

    const structuredRequest: LLMRequest = {
      ...request,
      responseFormat: schema,
    };

    // Add JSON mode instructions
    const systemWithJson = `${request.system ?? ''}

IMPORTANT: You must respond with valid JSON that matches this schema:
${JSON.stringify(jsonSchema, null, 2)}

Do not include any text outside the JSON object.`;

    const response = await this.complete({
      ...structuredRequest,
      system: systemWithJson,
    });

    // Parse the JSON response
    try {
      const jsonContent = this.extractJSON(response.content);
      const parsed = JSON.parse(jsonContent);
      const validated = schema.parse(parsed);

      return {
        data: validated,
        response,
      };
    } catch (parseError) {
      recordLlmFailure(parseError);
      throw new Error(`Failed to parse structured output: ${parseError instanceof Error ? parseError.message : 'Unknown error'}`);
    }
  }

  /**
   * Extract JSON from potentially markdown-wrapped content
   */
  private extractJSON(content: string): string {
    // Try to extract JSON from markdown code blocks
    const jsonMatch = content.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (jsonMatch?.[1]) {
      return jsonMatch[1].trim();
    }

    // Try to find JSON object directly
    const objectMatch = content.match(/\{[\s\S]*\}/);
    if (objectMatch?.[0]) {
      return objectMatch[0];
    }

    return content;
  }

  /**
   * Get available providers
   */
  getAvailableProviders(): LLMProvider[] {
    return this.providers.map(p => p.name);
  }

  /**
   * Check if any provider is available
   */
  async hasProvider(): Promise<boolean> {
    for (const provider of this.providers) {
      if (await provider.available()) {
        return true;
      }
    }
    return false;
  }
}

/**
 * Create LLM client
 */
export function createLLMClient(config?: Partial<LLMConfig>): LLMClient {
  return new LLMClient(config);
}
