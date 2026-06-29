import type { ScanConfig, AgentId, AgentResult, Finding, VulnerabilityChain, VCVFFingerprint, TrustInversion, ReconData, VCVFPatternType, ExploitNarrative, FixPatch, AgentContext } from '@guardiant/shared';
import { DEFAULT_AGENT_CONFIGS, createLogger } from '@guardiant/shared';
import { agentRegistry } from '../agents/registry.js';
import { AGENT_EXECUTION_ORDER } from './constants.js';
import { createCVCAnalyzer, type CVCAnalyzer } from '../analyzers/cvc-analyzer.js';
import { createAppClassifier, type AppClassifier } from '../classifier/app-classifier.js';
import { createFindingValidator, type FindingValidator } from '../validators/finding-validator.js';
import { CriticAgent } from '../agents/critic-agent.js';
import { buildCodeIndex, type CodeIndex } from '../indexer/code-index.js';
import { createLLMClient, type LLMClient } from '../llm/client.js';

import { createTIEFDetector, type TIEFDetector } from '../analyzers/tief-detector.js';
import { DiffScanner } from '../scanner/diff-scanner.js';


/**
 * Orchestrator coordinates all agents and analysis
 */
export class Orchestrator {
  private cvcAnalyzer: CVCAnalyzer;
  private tiefDetector: TIEFDetector;
  private appClassifier: AppClassifier;
  private findingValidator: FindingValidator;
  private criticAgent: CriticAgent;
  private llmClient: LLMClient;
  private logger = createLogger({ level: 'info' });

  constructor() {
    this.cvcAnalyzer = createCVCAnalyzer();
    this.tiefDetector = createTIEFDetector();
    this.appClassifier = createAppClassifier();
    this.findingValidator = createFindingValidator();
    this.llmClient = createLLMClient();
    this.criticAgent = new CriticAgent({ llmClient: this.llmClient });
  }

  /**
   * Run a full security scan
   */
  async runScan(config: ScanConfig): Promise<{
    findings: Finding[];
    agentResults: Record<AgentId, AgentResult>;
    chains: VulnerabilityChain[];
    vcvfFingerprints: VCVFFingerprint[];
    trustInversions: TrustInversion[];
    reconData?: ReconData;
    exploitNarratives: ExploitNarrative[];
    fixPatches: FixPatch[];
  }> {
    this.logger.info(`Starting scan for target: ${config.target}`);

    const agentResults: Record<AgentId, AgentResult> = {} as Record<AgentId, AgentResult>;
    const exploitNarratives: ExploitNarrative[] = [];
    const fixPatches: FixPatch[] = [];
    let reconData: ReconData | undefined;
    let changedFiles: string[] | undefined;

    if (config.incremental && config.type === 'directory') {
      this.logger.info(`Running incremental scan using baseRef: ${config.baseRef || 'HEAD~1'}`);
      const diffScanner = new DiffScanner(config.target);
      if (diffScanner.isGitRepo()) {
        changedFiles = diffScanner.getChangedFiles(config.baseRef || 'HEAD~1');
        this.logger.info(`Detected ${changedFiles.length} changed files`);
      } else {
        this.logger.warn('Target is not a git repository, falling back to full scan');
      }
    }

    // Phase 1: Recon (must run first)
    this.logger.info('Phase 1: Running Recon Agent...');
    const reconAgent = agentRegistry.get('recon');
    if (reconAgent) {
      const reconResult = await reconAgent.execute({
        scanId: 'scan_temp',
        target: {
          url: config.target,
          type: config.type,
        },
        config: DEFAULT_AGENT_CONFIGS.recon,
        changedFiles,
      });
      agentResults.recon = reconResult;
      reconData = reconResult.metadata.custom?.reconData as ReconData | undefined;
    }

    // Phase 1.5: App Classification (between recon and agent swarm)
    this.logger.info('Phase 1.5: Classifying application type...');
    const appContext = this.appClassifier.classify(reconData, config.type === 'directory' ? config.target : undefined);
    if (config.type === 'directory') {
      (appContext as any).rootPath = config.target;
    }
    this.logger.info(`App classified as: ${appContext.appType} (${appContext.suppressions.length} suppressions)`);

    // Phase 1.7: Build Code Index for directory scans
    let codeIndex: CodeIndex | undefined;
    if (config.type === 'directory') {
      this.logger.info('Phase 1.7: Building Code Index...');
      try {
        codeIndex = await buildCodeIndex(config.target);
      } catch (e) {
        this.logger.error('Failed to build Code Index:', e);
      }
    }

    // Phase 2: Run all other agents in parallel
    this.logger.info('Phase 2: Running Agent Swarm...');
    const allParallelAgents = AGENT_EXECUTION_ORDER[1] ?? []; // All agents except recon

    // Filter agents if specific agents are requested
    const requestedAgents = (config.agents as string[] | undefined)?.filter(a => a !== 'recon' && a !== 'all');
    const parallelAgents = requestedAgents && requestedAgents.length > 0
      ? allParallelAgents.filter(id => requestedAgents.includes(id))
      : allParallelAgents;

    const agentsToRun = parallelAgents.map(id => ({ id, agent: agentRegistry.get(id) })).filter(a => !!a.agent);

    const agentResultsArray = [];
    for (const agentObj of agentsToRun) {
      const agentId = agentObj.id as AgentId;
      const agent = agentObj.agent!;
      const agentConfig = config.agentConfigs?.[agentId] ?? DEFAULT_AGENT_CONFIGS[agentId];

      if (agentConfig?.enabled === false) {
        this.logger.info(`Skipping ${agentId} agent (disabled)`);
        agentResultsArray.push({
          agentId,
          status: 'completed' as const,
          findings: [],
          metadata: {},
          duration: 0,
        });
        continue;
      }

      this.logger.info(`Running ${agentId} agent...`);

      const startTime = Date.now();
      const agentContext = {
        scanId: 'scan_temp',
        target: {
          url: config.target,
          type: config.type,
        },
        reconData,
        appContext,
        config: agentConfig,
        changedFiles,
        metadata: {
          codeIndex,
        },
      } as any;

      try {
        const [staticResult, llmFindings] = await Promise.all([
          agent.execute(agentContext),
          this.runLLMAgent(agent, agentContext)
        ]);

        const mergedFindings = [...staticResult.findings, ...llmFindings];
        this.logger.info(`${agentId} completed: ${mergedFindings.length} findings (${staticResult.findings.length} static, ${llmFindings.length} LLM)`);
        
        agentResultsArray.push({
          agentId,
          status: 'completed' as const,
          findings: mergedFindings,
          metadata: {
            ...staticResult.metadata,
            llmFindingsCount: llmFindings.length,
          },
          duration: Date.now() - startTime,
        });
      } catch (error) {
        this.logger.error(`${agentId} failed:`, error);
        agentResultsArray.push({
          agentId,
          status: 'failed' as const,
          findings: [],
          metadata: {},
          error: error instanceof Error ? error.message : 'Unknown error',
          duration: Date.now() - startTime,
        });
      }
    }

    for (const result of agentResultsArray) {
      if (result && 'agentId' in result) {
        agentResults[result.agentId as AgentId] = result as AgentResult;
      }
    }

    // Collect all raw findings from Phase 2
    let allFindings: Finding[] = [];
    for (const result of Object.values(agentResults)) {
      allFindings.push(...result.findings);
    }

    // Phase 2.5: Finding Validation — deterministic filtering and adjust confidence
    this.logger.info('Phase 2.5: Validating findings...');
    const { validated: validatedFindings, suppressed } = this.findingValidator.validate(allFindings, appContext, codeIndex);
    this.logger.info(`Validation: ${validatedFindings.length} passed, ${suppressed.length} suppressed`);

    // Phase 2.6: Critic Agent — LLM reflection to filter false positives
    this.logger.info('Phase 2.6: Running Critic Agent...');
    const preCriticCount = validatedFindings.length;
    const finalFindings = await this.criticAgent.reviewFindings(validatedFindings, config.type === 'directory' ? config.target : undefined);
    this.logger.info(`Critic Agent filtered ${preCriticCount - finalFindings.length} false positives`);

    // Update agent results to reflect only validated findings
    const validatedByAgent = new Map<string, Finding[]>();
    for (const f of finalFindings) {
      const agentId = f.discoveredBy;
      if (!validatedByAgent.has(agentId)) validatedByAgent.set(agentId, []);
      validatedByAgent.get(agentId)!.push(f);
    }
    for (const [agentId, result] of Object.entries(agentResults)) {
      result.findings = validatedByAgent.get(agentId) ?? [];
    }

    // Use validated findings for all downstream phases (CVC, VCVF, TIEF, Exploit, Fix)
    const findingsForAnalysis = finalFindings;

    // Phase 3: CVC Analysis - Find compound vulnerability chains
    this.logger.info('Phase 3: Running CVC Analysis...');

    const chains = await this.cvcAnalyzer.findChains(findingsForAnalysis, reconData?.dataFlows);

    // Phase 4: VCVF Pattern Matching
    this.logger.info('Phase 4: Running VCVF Analysis...');
    const vcvfFingerprints: VCVFFingerprint[] = reconData?.vcvfPatterns.map(p => ({
      id: `vcvf_${p.type}_${Date.now()}`,
      patternType: p.type as VCVFPatternType,
      confidence: p.confidence,
      evidence: [],
      locations: p.locations,
      predictedVulnerabilities: [],
    })) ?? [];

    // Phase 5: TIEF Detection
    this.logger.info('Phase 5: Running TIEF Analysis...');
    const trustInversions = await this.tiefDetector.detect(findingsForAnalysis);

    // Phase 6: Exploit Generation (depends on all findings from Phase 2 + analysis from Phase 3-5)
    if (config.phases?.exploit !== false) {
      this.logger.info('Phase 6: Running Exploit Agent...');
      const exploitAgent = agentRegistry.get('exploit');
      if (exploitAgent) {
        try {
          const exploitContext = {
            scanId: 'scan_temp',
            target: { url: config.target, type: config.type },
            reconData,
            config: DEFAULT_AGENT_CONFIGS.exploit,
            metadata: {
              findings: findingsForAnalysis,
              reconData,
              activeMode: config.activeExploit === true,
            },
          } as unknown as AgentContext;
          const exploitResult = await exploitAgent.execute(exploitContext);
          agentResults.exploit = exploitResult;

          const meta = exploitResult.metadata.custom as { narratives?: ExploitNarrative[] } | undefined;
          if (meta?.narratives) {
            exploitNarratives.push(...meta.narratives);
          }
        } catch (error) {
          this.logger.error('Exploit agent failed:', error);
        }
      }
    }

    // Phase 7: Fix Generation (depends on findings + target path)
    if (config.phases?.fix !== false) {
      this.logger.info('Phase 7: Running Fix Agent...');
      const fixAgent = agentRegistry.get('fix');
      if (fixAgent) {
        try {
          const fixContext = {
            scanId: 'scan_temp',
            target: { url: config.target, type: config.type },
            reconData,
            config: DEFAULT_AGENT_CONFIGS.fix,
            metadata: {
              findings: findingsForAnalysis,
              targetPath: config.target,
              mode: config.autoFix === true ? 'apply' : 'dry-run',
            },
          } as unknown as AgentContext;
          const fixResult = await fixAgent.execute(fixContext);
          agentResults.fix = fixResult;

          const meta = fixResult.metadata.custom as { patches?: FixPatch[] } | undefined;
          if (meta?.patches) {
            fixPatches.push(...meta.patches);
          }
        } catch (error) {
          this.logger.error('Fix agent failed:', error);
        }
      }
    }

    this.logger.info(
      `Scan complete: ${findingsForAnalysis.length} findings, ${chains.length} chains, ` +
      `${trustInversions.length} trust inversions, ${exploitNarratives.length} exploit narratives, ` +
      `${fixPatches.length} fix patches`
    );

    return {
      findings: findingsForAnalysis,
      agentResults,
      chains,
      vcvfFingerprints,
      trustInversions,
      reconData,
      exploitNarratives,
      fixPatches,
    };
  }

  /**
   * Run a specific agent
   */
  async runAgent(agentId: AgentId, context: {
    target: string;
    type: 'url' | 'directory' | 'repository';
    reconData?: ReconData;
  }): Promise<AgentResult> {
    const agent = agentRegistry.get(agentId);
    if (!agent) {
      throw new Error(`Agent ${agentId} not registered`);
    }

    return agent.execute({
      scanId: 'scan_temp',
      target: {
        url: context.target,
        type: context.type,
      },
      reconData: context.reconData,
      config: DEFAULT_AGENT_CONFIGS[agentId],
    });
  }

  /**
   * Get available agents
   */
  getAvailableAgents(): AgentId[] {
    return agentRegistry.getIds();
  }

  /**
   * Check if an agent is enabled
   */
  isAgentEnabled(agentId: AgentId): boolean {
    const config = DEFAULT_AGENT_CONFIGS[agentId];
    return config?.enabled ?? false;
  }

  private extractJSON(content: string): string {
    const jsonMatch = content.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (jsonMatch?.[1]) {
      return jsonMatch[1].trim();
    }
    const objectMatch = content.match(/\{[\s\S]*\}/);
    if (objectMatch?.[0]) {
      return objectMatch[0];
    }
    return content;
  }

  private async runLLMAgent(agent: any, context: AgentContext): Promise<Finding[]> {
    const hasLLM = await this.llmClient.hasProvider();
    if (!hasLLM) return [];

    try {
      const systemPrompt = agent.getSystemPrompt() + `
\n\nIMPORTANT: You must return a JSON object matching this schema exactly. Do not output any thinking or extra text, ONLY the JSON block:
{
  "findings": [
    {
      "title": "Vulnerability Title",
      "description": "Vulnerability Description",
      "severity": "critical" | "high" | "medium" | "low" | "info",
      "category": "OWASP category code",
      "cvssScore": 5.0,
      "confidence": 0.8,
      "evidence": {
        "file": "relative/path/to/file.js",
        "line": 42,
        "snippet": "code snippet",
        "reasoning": "why it is vulnerable"
      },
      "remediation": {
        "summary": "remediation description",
        "steps": ["step 1", "step 2"],
        "codeExample": "code example"
      }
    }
  ]
}`;

      let filesContext = '';
      const codeIndex = (context as any).metadata?.codeIndex;
      if (codeIndex && codeIndex.files) {
        filesContext = '\n\nHere is the source code of the project files:\n';
        for (const [filePath, fileData] of codeIndex.files.entries()) {
          // Avoid reading huge files, cap to 2000 chars per file
          const content = fileData.source.substring(0, 2000);
          filesContext += `\n--- File: ${filePath} ---\n${content}\n`;
        }
      }

      const userPrompt = agent.buildUserPrompt(context) + filesContext;

      this.logger.info(`Running AI agent reasoning for ${agent.id} using LLM...`);
      const response = await this.llmClient.complete({
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }],
      });

      if (!response.content || response.content.trim() === '') {
        throw new Error('LLM returned an empty response');
      }

      const extracted = this.extractJSON(response.content);
      const data = JSON.parse(extracted);
      if (data && Array.isArray(data.findings)) {
        this.logger.info(`AI agent ${agent.id} discovered ${data.findings.length} findings via LLM`);
        return data.findings.map((f: any, idx: number) => ({
          id: `finding_${agent.id}_llm_${idx}_${Date.now()}`,
          title: f.title || 'Vulnerability Discovered',
          description: f.description || '',
          severity: f.severity || 'medium',
          category: f.category || agent.categories?.[0] || 'A00_UNKNOWN',
          cvssScore: f.cvssScore || 5.0,
          confidence: f.confidence || 0.8,
          evidence: {
            file: f.evidence?.file || '',
            line: f.evidence?.line || 1,
            snippet: f.evidence?.snippet || '',
            reasoning: f.evidence?.reasoning || '',
          },
          remediation: {
            summary: f.remediation?.summary || '',
            steps: f.remediation?.steps || [],
            codeExample: f.remediation?.codeExample || '',
          },
          discoveredBy: agent.id,
          timestamp: new Date().toISOString(),
          status: 'open',
          tags: f.tags || [agent.id, 'llm'],
        }));
      }
    } catch (error) {
      this.logger.warn(`AI agent ${agent.id} reasoning failed: ${error}`);
    }

    return [];
  }
}

/**
 * Create orchestrator
 */
export function createOrchestrator(): Orchestrator {
  return new Orchestrator();
}