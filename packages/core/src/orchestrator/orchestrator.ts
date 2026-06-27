import type { ScanConfig, AgentId, AgentResult, Finding, VulnerabilityChain, VCVFFingerprint, TrustInversion, ReconData, VCVFPatternType, ExploitNarrative, FixPatch, AgentContext } from '@guardiant/shared';
import { DEFAULT_AGENT_CONFIGS, createLogger } from '@guardiant/shared';
import { agentRegistry } from '../agents/registry.js';
import { AGENT_EXECUTION_ORDER } from './constants.js';
import { createCVCAnalyzer, type CVCAnalyzer } from '../analyzers/cvc-analyzer.js';
import { createAppClassifier, type AppClassifier } from '../classifier/app-classifier.js';
import { createFindingValidator, type FindingValidator } from '../validators/finding-validator.js';

import { createTIEFDetector, type TIEFDetector } from '../analyzers/tief-detector.js';


/**
 * Orchestrator coordinates all agents and analysis
 */
export class Orchestrator {
  private cvcAnalyzer: CVCAnalyzer;
  private tiefDetector: TIEFDetector;
  private appClassifier: AppClassifier;
  private findingValidator: FindingValidator;
  private logger = createLogger({ level: 'info' });

  constructor() {
    this.cvcAnalyzer = createCVCAnalyzer();
    this.tiefDetector = createTIEFDetector();
    this.appClassifier = createAppClassifier();
    this.findingValidator = createFindingValidator();
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
      });
      agentResults.recon = reconResult;
      reconData = reconResult.metadata.custom?.reconData as ReconData | undefined;
    }

    // Phase 1.5: App Classification (between recon and agent swarm)
    this.logger.info('Phase 1.5: Classifying application type...');
    const appContext = this.appClassifier.classify(reconData, config.type === 'directory' ? config.target : undefined);
    this.logger.info(`App classified as: ${appContext.appType} (${appContext.suppressions.length} suppressions)`);

    // Phase 2: Run all other agents in parallel
    this.logger.info('Phase 2: Running Agent Swarm...');
    const allParallelAgents = AGENT_EXECUTION_ORDER[1] ?? []; // All agents except recon

    // Filter agents if specific agents are requested
    const requestedAgents = (config.agents as string[] | undefined)?.filter(a => a !== 'recon' && a !== 'all');
    const parallelAgents = requestedAgents && requestedAgents.length > 0
      ? allParallelAgents.filter(id => requestedAgents.includes(id))
      : allParallelAgents;

    const agentPromises = parallelAgents.map(async (agentId) => {
      const agent = agentRegistry.get(agentId);
      if (!agent) {
        this.logger.warn(`Agent ${agentId} not registered`);
        return null;
      }

      // Check if agent is enabled
      const agentConfig = config.agentConfigs?.[agentId] ?? DEFAULT_AGENT_CONFIGS[agentId];
      if (!agentConfig.enabled) {
        this.logger.info(`Agent ${agentId} is disabled, skipping`);
        return {
          agentId,
          status: 'skipped' as const,
          findings: [],
          metadata: {},
          duration: 0,
        };
      }

      this.logger.info(`Running ${agentId} agent...`);

      const startTime = Date.now();
      try {
        const result = await agent.execute({
          scanId: 'scan_temp',
          target: {
            url: config.target,
            type: config.type,
          },
          reconData,
          appContext,
          config: agentConfig,
        });

        this.logger.info(`${agentId} completed: ${result.findings.length} findings`);
        return result;
      } catch (error) {
        this.logger.error(`${agentId} failed:`, error);
        return {
          agentId,
          status: 'failed' as const,
          findings: [],
          metadata: {},
          error: error instanceof Error ? error.message : 'Unknown error',
          duration: Date.now() - startTime,
        };
      }
    });

    const agentResultsArray = await Promise.all(agentPromises);
    for (const result of agentResultsArray) {
      if (result && 'agentId' in result) {
        agentResults[result.agentId as AgentId] = result as AgentResult;
      }
    }

    // Collect all raw findings from Phase 2
    const allFindings: Finding[] = [];
    for (const result of Object.values(agentResults)) {
      allFindings.push(...result.findings);
    }

    // Phase 2.5: Finding Validation — filter false positives and adjust confidence
    this.logger.info('Phase 2.5: Validating findings...');
    const { validated: validatedFindings, suppressed } = this.findingValidator.validate(allFindings, appContext);
    this.logger.info(`Validation: ${validatedFindings.length} passed, ${suppressed.length} suppressed`);

    // Update agent results to reflect only validated findings
    const validatedByAgent = new Map<string, Finding[]>();
    for (const f of validatedFindings) {
      const agentId = f.discoveredBy;
      if (!validatedByAgent.has(agentId)) validatedByAgent.set(agentId, []);
      validatedByAgent.get(agentId)!.push(f);
    }
    for (const [agentId, result] of Object.entries(agentResults)) {
      result.findings = validatedByAgent.get(agentId) ?? [];
    }

    // Use validated findings for all downstream phases (CVC, VCVF, TIEF, Exploit, Fix)
    const findingsForAnalysis = validatedFindings;

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
}

/**
 * Create orchestrator
 */
export function createOrchestrator(): Orchestrator {
  return new Orchestrator();
}