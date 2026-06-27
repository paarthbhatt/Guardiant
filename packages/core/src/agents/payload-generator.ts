import { createHttpClient } from '../http/index.js';
import type { Finding } from '@guardiant/shared';
import { createLogger } from '@guardiant/shared';

const logger = createLogger({ level: 'info' });

export interface PayloadGeneratorConfig {
  apiKey?: string;
  provider?: 'openai' | 'anthropic';
  model?: string;
}

export class PayloadGenerator {
  private httpClient = createHttpClient(15000);
  private apiKey: string;
  private provider: 'openai' | 'anthropic';
  private model: string;

  constructor(config?: PayloadGeneratorConfig) {
    this.provider = config?.provider || (process.env.GUARDIANT_ANTHROPIC_API_KEY ? 'anthropic' : 'openai');
    this.apiKey = config?.apiKey || process.env.GUARDIANT_OPENAI_API_KEY || process.env.GUARDIANT_ANTHROPIC_API_KEY || '';
    
    if (this.provider === 'openai') {
      this.model = config?.model || 'gpt-4o';
    } else {
      this.model = config?.model || 'claude-3-5-sonnet-20240620';
    }
  }

  public isAvailable(): boolean {
    return this.apiKey.length > 0;
  }

  /**
   * Generates a context-aware exploit payload for a specific finding
   */
  public async generatePayload(finding: Finding, contextData?: Record<string, any>): Promise<string | null> {
    if (!this.isAvailable()) {
      logger.debug('Payload generator not available (no API key)');
      return null;
    }

    const systemPrompt = `You are an expert penetration tester. Your job is to generate a SINGLE highly specific, context-aware exploit payload string for a given vulnerability finding.
Return ONLY the raw payload string. Do not include markdown formatting, explanations, or quotes around the payload. If you cannot generate a payload, return an empty string.`;

    const userPrompt = `Generate an exploit payload for the following finding:
Title: ${finding.title}
Category: ${finding.category}
Description: ${finding.description}
Context: ${JSON.stringify(contextData || {})}

Ensure the payload is tailored to this specific vulnerability context (e.g. if it's an SQL injection, generate a payload that fits the likely database syntax; if XSS, craft a payload that steals cookies or bypasses basic filters).`;

    try {
      if (this.provider === 'openai') {
        return await this.callOpenAI(systemPrompt, userPrompt);
      } else {
        return await this.callAnthropic(systemPrompt, userPrompt);
      }
    } catch (error) {
      logger.warn(`Failed to generate dynamic payload: ${error}`);
      return null;
    }
  }

  private async callOpenAI(system: string, user: string): Promise<string> {
    const response = await this.httpClient.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model: this.model,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user }
        ],
        temperature: 0.2,
      },
      {
        'Authorization': `Bearer ${this.apiKey}`
      }
    );

    if (response.status !== 200) {
      throw new Error(`OpenAI API error: ${response.body}`);
    }

    const json = response.json as any;
    return json?.choices?.[0]?.message?.content?.trim() || '';
  }

  private async callAnthropic(system: string, user: string): Promise<string> {
    const response = await this.httpClient.post(
      'https://api.anthropic.com/v1/messages',
      {
        model: this.model,
        max_tokens: 1024,
        system: system,
        messages: [
          { role: 'user', content: user }
        ],
        temperature: 0.2,
      },
      {
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01'
      }
    );

    if (response.status !== 200) {
      throw new Error(`Anthropic API error: ${response.body}`);
    }

    const json = response.json as any;
    return json?.content?.[0]?.text?.trim() || '';
  }
}
