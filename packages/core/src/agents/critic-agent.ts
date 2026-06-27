import { createHttpClient } from '../http/index.js';
import type { Finding } from '@guardiant/shared';
import { createLogger } from '@guardiant/shared';

const logger = createLogger({ level: 'info' });

export interface CriticAgentConfig {
  apiKey?: string;
  provider?: 'openai' | 'anthropic';
  model?: string;
}

export class CriticAgent {
  private httpClient = createHttpClient(30000); // 30s timeout for complex reflections
  private apiKey: string;
  private provider: 'openai' | 'anthropic';
  private model: string;

  constructor(config?: CriticAgentConfig) {
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
   * Reviews a list of findings and returns only those that are NOT deemed false positives.
   */
  public async reviewFindings(findings: Finding[]): Promise<Finding[]> {
    if (!this.isAvailable()) {
      logger.warn('Critic Agent not available (no API key). Skipping reflection phase.');
      return findings;
    }
    
    if (findings.length === 0) return findings;

    logger.info(`Critic Agent reviewing ${findings.length} findings for false positives...`);
    const verifiedFindings: Finding[] = [];

    // Process in batches or one by one to avoid huge context sizes
    for (const finding of findings) {
      const isVerified = await this.evaluateFinding(finding);
      if (isVerified) {
        verifiedFindings.push(finding);
      } else {
        logger.info(`Critic Agent rejected finding: ${finding.title} as a false positive.`);
      }
    }

    return verifiedFindings;
  }

  private async evaluateFinding(finding: Finding): Promise<boolean> {
    const systemPrompt = `You are a strict AppSec auditor. Your job is to review automated security scanner findings and determine if they are TRUE POSITIVES or FALSE POSITIVES.
You must analyze the finding description, severity, and any evidence provided.
Reply with exactly "VERDICT: TRUE POSITIVE" or "VERDICT: FALSE POSITIVE". Do not output anything else.`;

    const userPrompt = `Review this finding:
Title: ${finding.title}
Severity: ${finding.severity}
Category: ${finding.category}
Description: ${finding.description}
Evidence: ${JSON.stringify(finding.evidence || {})}

Is this a real vulnerability or a false positive?`;

    try {
      let responseText = '';
      if (this.provider === 'openai') {
        responseText = await this.callOpenAI(systemPrompt, userPrompt);
      } else {
        responseText = await this.callAnthropic(systemPrompt, userPrompt);
      }

      return responseText.includes('TRUE POSITIVE');
    } catch (error) {
      logger.warn(`Critic evaluation failed for ${finding.title}: ${error}`);
      // Default to true positive if we can't evaluate
      return true;
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
        temperature: 0.1,
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
        max_tokens: 100,
        system: system,
        messages: [
          { role: 'user', content: user }
        ],
        temperature: 0.1,
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
