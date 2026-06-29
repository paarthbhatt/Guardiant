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
      maxTokens: 4096,
      temperature: 0.7,
      ...config,
    };

    this.initializeProviders();
  }

  private initializeProviders(): void {
    const userConfigured: LLMProviderClient[] = [];
    const fallbackConfigured: LLMProviderClient[] = [];

    // Priority: Nvidia -> OpenRouter -> Gemini -> Zenmux -> Anthropic -> OpenAI
    const providerConfigs: Array<{ name: LLMProvider; envKey: string; create: () => LLMProviderClient | null }> = [
      { name: 'nvidia', envKey: 'NVIDIA_API_KEY', create: () => this.createNvidiaProvider() },
      { name: 'openrouter', envKey: 'OPENROUTER_API_KEY', create: () => this.createOpenRouterProvider() },
      { name: 'gemini', envKey: 'GEMINI_API_KEY', create: () => this.createGeminiProvider() },
      { name: 'zenmux', envKey: 'ZENMUX_API_KEY', create: () => this.createZenmuxProvider() },
      { name: 'anthropic', envKey: 'ANTHROPIC_API_KEY', create: () => this.createAnthropicProvider() },
      { name: 'openai', envKey: 'OPENAI_API_KEY', create: () => this.createOpenAIProvider() },
    ];

    for (const { envKey, create } of providerConfigs) {
      const provider = create();
      if (provider) {
        if (process.env[envKey]) {
          userConfigured.push(provider);
        } else {
          fallbackConfigured.push(provider);
        }
      }
    }

    this.providers = [...userConfigured, ...fallbackConfigured];
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
        });

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
        });

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
        });

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
        });

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
        });

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
        });

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
        };
        const interval = minIntervals[provider.name] ?? 0;
        const lastTime = this.lastRequestTimes.get(provider.name) ?? 0;
        const elapsed = now - lastTime;
        if (elapsed < interval) {
          const waitTime = interval - elapsed;
          await new Promise(resolve => setTimeout(resolve, waitTime));
        }

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