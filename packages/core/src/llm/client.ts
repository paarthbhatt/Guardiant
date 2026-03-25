import Anthropic from '@anthropic-ai/sdk';
import OpenAI from 'openai';
import { GoogleGenerativeAI } from '@google/generative-ai';
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

  constructor(config: Partial<LLMConfig> = {}) {
    this.defaultConfig = {
      provider: 'anthropic',
      maxTokens: 4096,
      temperature: 0.7,
      ...config,
    };

    this.initializeProviders();
  }

  /**
   * Initialize available providers in priority order
   */
  private initializeProviders(): void {
    // Priority: Anthropic -> OpenRouter -> Gemini
    const providerConfigs: Array<{ name: LLMProvider; create: () => LLMProviderClient | null }> = [
      { name: 'anthropic', create: () => this.createAnthropicProvider() },
      { name: 'openrouter', create: () => this.createOpenRouterProvider() },
      { name: 'gemini', create: () => this.createGeminiProvider() },
    ];

    for (const { name, create } of providerConfigs) {
      const provider = create();
      if (provider) {
        this.providers.push(provider);
      }
    }
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
   * Create OpenRouter provider
   */
  private createOpenRouterProvider(): LLMProviderClient | null {
    const apiKey = process.env.OPENROUTER_API_KEY;
    if (!apiKey) return null;

    const client = new OpenAI({
      apiKey,
      baseURL: 'https://openrouter.ai/api/v1',
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
        const model = this.defaultConfig.model ?? DEFAULT_LLM_CONFIGS.openrouter.model;
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

    const genAI = new GoogleGenerativeAI(apiKey);

    return {
      name: 'gemini',
      available: async () => true,
      complete: async (request: LLMRequest) => {
        const startTime = Date.now();
        const model = this.defaultConfig.model ?? DEFAULT_LLM_CONFIGS.gemini.model;

        const geminiModel = genAI.getGenerativeModel({ model });

        const prompt = request.system
          ? `${request.system}\n\n${request.messages.map(m => `${m.role}: ${m.content}`).join('\n')}`
          : request.messages.map(m => `${m.role}: ${m.content}`).join('\n');

        const result = await geminiModel.generateContent(prompt);
        const content = result.response.text();

        return {
          content,
          tokensUsed: {
            input: 0, // Gemini doesn't provide token counts in the same way
            output: 0,
            total: 0,
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
      try {
        const isAvailable = await provider.available();
        if (!isAvailable) {
          continue;
        }

        return await provider.complete(request);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        errors.push(new Error(`${provider.name}: ${errorMessage}`));
        console.warn(`LLM provider ${provider.name} failed, trying next provider...`);
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
    if (jsonMatch) {
      return jsonMatch[1].trim();
    }

    // Try to find JSON object directly
    const objectMatch = content.match(/\{[\s\S]*\}/);
    if (objectMatch) {
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