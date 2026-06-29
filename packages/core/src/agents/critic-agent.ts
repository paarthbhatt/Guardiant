import { z } from 'zod';
import type { Finding } from '@guardiant/shared';
import { createLogger } from '@guardiant/shared';
import { createLLMClient, type LLMClient } from '../llm/client.js';

const logger = createLogger({ level: 'info' });

export interface CriticAgentConfig {
  llmClient?: LLMClient;
}

const CriticVerdictSchema = z.object({
  reasoning: z.string().describe('Detailed step-by-step AppSec reasoning explaining why this is a true positive or false positive.'),
  verdict: z.enum(['TRUE_POSITIVE', 'FALSE_POSITIVE']).describe('The final verification verdict.'),
});

export class CriticAgent {
  private llmClient: LLMClient;

  constructor(config?: CriticAgentConfig) {
    this.llmClient = config?.llmClient ?? createLLMClient();
    
    // Filter out low-reasoning providers for Critic Agent (reflection phase)
    // to guarantee high-reasoning decisions (Nvidia Llama 3.3, OpenRouter Nemotron 550B, Gemini 2.5 Flash)
    if (this.llmClient && (this.llmClient as any).providers) {
      (this.llmClient as any).providers = (this.llmClient as any).providers.filter(
        (p: any) => p.name !== 'zenmux' && p.name !== 'openai'
      );
    }
  }

  /**
   * Reviews a list of findings and returns only those that are NOT deemed false positives.
   */
  public async reviewFindings(findings: Finding[], rootPath?: string): Promise<Finding[]> {
    const hasLLM = await this.llmClient.hasProvider();
    if (!hasLLM) {
      logger.warn('Critic Agent not available (no LLM provider configured). Skipping reflection phase.');
      return findings;
    }
    
    if (findings.length === 0) return findings;

    logger.info(`Critic Agent reviewing ${findings.length} findings for false positives...`);
    const verifiedFindings: Finding[] = [];

    // Process findings one by one
    for (const finding of findings) {
      const isVerified = await this.evaluateFinding(finding, rootPath);
      if (isVerified) {
        verifiedFindings.push(finding);
      } else {
        logger.info(`Critic Agent rejected finding: ${finding.title} as a false positive.`);
      }
    }

    return verifiedFindings;
  }

  private async evaluateFinding(finding: Finding, rootPath?: string): Promise<boolean> {
    const systemPrompt = `You are a strict AppSec auditor. Your job is to review automated security scanner findings and determine if they are TRUE POSITIVES or FALSE POSITIVES.
Analyze the finding, its category, its description, the evidence, and the surrounding source code context carefully.
Consider:
1. Does the evidence code actually exist in the file at the specified line? If not, it is a FALSE POSITIVE.
2. Is the vulnerability already fully mitigated by a middleware, helper function, query filter, or framework safeguard in the code? If yes, it is a FALSE POSITIVE.
3. If it is an IDOR finding: check if vertical/role checks are already performed elsewhere or if the endpoint is intentionally public/shared for all authenticated roles.
4. If it is a package dependency issue (like bcrypt CVE): is it valid for the workspace?
Provide your reasoning step-by-step, then write the final verdict.`;

    // Read file content window (±15 lines around the claimed line)
    let fileContext = '';
    if (rootPath && finding.evidence && finding.evidence.file && finding.evidence.line) {
      try {
        const { join } = await import('path');
        const { existsSync, readFileSync } = await import('fs');
        const filePath = join(rootPath, finding.evidence.file as string);
        if (existsSync(filePath)) {
          const lines = readFileSync(filePath, 'utf-8').split('\n');
          const claimedLine = (finding.evidence.line as number) - 1;
          const start = Math.max(0, claimedLine - 15);
          const end = Math.min(lines.length, claimedLine + 15);
          fileContext = lines.slice(start, end).map((l, i) => `${start + i + 1}: ${l}`).join('\n');
        }
      } catch {
        // skip
      }
    }

    // Find routing context to provide full middleware and routing information
    let routeContext = '';
    if (rootPath && finding.evidence && finding.evidence.file) {
      try {
        const { join, basename } = await import('path');
        const { existsSync, readdirSync, readFileSync } = await import('fs');
        const routesDir = join(rootPath, 'backend/src/routes');
        if (existsSync(routesDir)) {
          const files = readdirSync(routesDir);
          // Extract the method name (e.g. listByLead)
          const controllerName = basename(finding.evidence.file as string, '.js');
          const fileLines = fileContext.split('\n');
          // Look for "exports.methodName = ..." on the claimed line range
          let methodName = '';
          for (const line of fileLines) {
            const match = line.match(/exports\.(\w+)\s*=/);
            if (match?.[1]) {
              methodName = match[1];
              break;
            }
          }
          
          if (methodName) {
            for (const file of files) {
              if (file.endsWith('.js') || file.endsWith('.ts')) {
                const content = readFileSync(join(routesDir, file), 'utf-8');
                if (content.includes(methodName) || content.includes(controllerName)) {
                  routeContext = `\nAssociated Route File (${file}):\n\`\`\`javascript\n${content}\n\`\`\``;
                  break;
                }
              }
            }
          }
        }
      } catch {
        // skip
      }
    }

    const userPrompt = `Review this finding:
Title: ${finding.title}
Severity: ${finding.severity}
Category: ${finding.category}
Description: ${finding.description}
Claimed Evidence: ${JSON.stringify(finding.evidence || {})}
${fileContext ? `\nActual source code around the claimed location:\n\`\`\`\n${fileContext}\n\`\`\`` : ''}
${routeContext}

Is this a real vulnerability or a false positive?`;

    try {
      const { data } = await this.llmClient.completeStructured(
        {
          system: systemPrompt,
          messages: [{ role: 'user', content: userPrompt }],
        },
        CriticVerdictSchema
      );

      logger.info(`Critic Agent reasoning for ${finding.title}: ${data.reasoning}`);
      return data.verdict === 'TRUE_POSITIVE';
    } catch (error) {
      logger.warn(`Critic evaluation failed for ${finding.title}: ${error}`);
      // Default to true positive if we can't evaluate
      return true;
    }
  }
}
