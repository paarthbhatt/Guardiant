import type { AnalysisJobData, JobResult } from '../types.js';
import type { Finding, VulnerabilityChain, VCVFFingerprint, TrustInversion } from '@guardiant/shared';

/**
 * Analysis job interface
 */
export interface AnalysisJob {
  id: string;
  name: string;
  data: AnalysisJobData;
  priority: number;
  attempts: number;
  maxAttempts: number;
}

/**
 * Analysis job handlers
 */
export interface AnalysisJobHandlers {
  analyzeCVC: (findings: Finding[]) => Promise<VulnerabilityChain[]>;
  analyzeVCVF: (scanId: string) => Promise<VCVFFingerprint[]>;
  analyzeTIEF: (findings: Finding[], chains: VulnerabilityChain[]) => Promise<TrustInversion[]>;
  storeResults: (scanId: string, results: AnalysisResults) => Promise<void>;
}

/**
 * Analysis results
 */
export interface AnalysisResults {
  chains: VulnerabilityChain[];
  vcvfFingerprints: VCVFFingerprint[];
  trustInversions: TrustInversion[];
}

/**
 * Process analysis job
 */
export async function processAnalysisJob(
  job: AnalysisJob,
  handlers: AnalysisJobHandlers
): Promise<JobResult<AnalysisResults>> {
  const startTime = Date.now();
  const { scanId, agentResults } = job.data;

  try {
    // Flatten all findings from all agents
    const allFindings: Finding[] = [];
    for (const result of Object.values(agentResults)) {
      // Convert simplified findings back to full Finding objects
      // This would normally be done by fetching from the database
      for (const f of result.findings) {
        allFindings.push(f as unknown as Finding);
      }
    }

    // Run CVC analysis
    const chains = await handlers.analyzeCVC(allFindings);

    // Run VCVF analysis
    const vcvfFingerprints = await handlers.analyzeVCVF(scanId);

    // Run TIEF analysis
    const trustInversions = await handlers.analyzeTIEF(allFindings, chains);

    // Store results
    const results: AnalysisResults = {
      chains,
      vcvfFingerprints,
      trustInversions,
    };

    await handlers.storeResults(scanId, results);

    return {
      success: true,
      data: results,
      duration: Date.now() - startTime,
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return {
      success: false,
      error: errorMessage,
      duration: Date.now() - startTime,
    };
  }
}

/**
 * Create analysis job data
 */
export function createAnalysisJobData(
  scanId: string,
  agentResults: Record<string, unknown>
): AnalysisJobData {
  return {
    scanId,
    agentResults: agentResults as AnalysisJobData['agentResults'],
  };
}