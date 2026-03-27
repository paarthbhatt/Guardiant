import type { ScanConfig, AgentId, AgentResult, Finding, VulnerabilityChain, VCVFFingerprint, TrustInversion, ReconData, VCVFPatternType } from '@guardiant/shared';
import { DEFAULT_AGENT_CONFIGS, createLogger } from '@guardiant/shared';
import { agentRegistry } from '../agents/registry.js';
import { AGENT_EXECUTION_ORDER } from './constants.js';
import { createCVCAnalyzer, type CVCAnalyzer } from '../analyzers/cvc-analyzer.js';

import { createTIEFDetector, type TIEFDetector } from '../analyzers/tief-detector.js';


/**
 * Orchestrator coordinates all agents and analysis
 */
export class Orchestrator {
  private cvcAnalyzer: CVCAnalyzer;
  // private vcvfMatcher: VCVFMatcher; // currently unused natively but kept per design, keeping instance for future or we can remove it.
  // actually wait, let's just remove vcvfMatcher field if it's unused.
  private tiefDetector: TIEFDetector;
  private logger = createLogger({ level: 'info' });

  constructor() {
    this.cvcAnalyzer = createCVCAnalyzer();
    // this.vcvfMatcher = createVCVFMatcher();
    this.tiefDetector = createTIEFDetector();
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
  }> {
    this.logger.info(`Starting scan for target: ${config.target}`);

    const agentResults: Record<AgentId, AgentResult> = {} as Record<AgentId, AgentResult>;
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

    // Phase 2: Run all other agents in parallel
    this.logger.info('Phase 2: Running Agent Swarm...');
    const parallelAgents = AGENT_EXECUTION_ORDER[1] ?? []; // All agents except recon

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

    // Phase 3: CVC Analysis - Find compound vulnerability chains
    this.logger.info('Phase 3: Running CVC Analysis...');
    const allFindings: Finding[] = [];
    for (const result of Object.values(agentResults)) {
      allFindings.push(...result.findings);
    }

    const chains = await this.cvcAnalyzer.findChains(allFindings, reconData?.dataFlows);

    // Phase 4: VCVF Pattern Matching
    this.logger.info('Phase 4: Running VCVF Analysis...');
    // In a real implementation, we'd analyze the actual code
    // For now, use recon data patterns
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
    const trustInversions = await this.tiefDetector.detect(allFindings);

    this.logger.info(`Scan complete: ${allFindings.length} findings, ${chains.length} chains, ${trustInversions.length} trust inversions`);

    return {
      findings: allFindings,
      agentResults,
      chains,
      vcvfFingerprints,
      trustInversions,
      reconData,
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