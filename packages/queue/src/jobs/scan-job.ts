import type { ScanJobData, JobResult, ReconJobResult } from '../types.js';
import type { ScanConfig } from '@guardiant/shared';

/**
 * Scan job interface
 */
export interface ScanJob {
  id: string;
  name: string;
  data: ScanJobData;
  priority: number;
  attempts: number;
  maxAttempts: number;
}

/**
 * Process scan job
 */
export async function processScanJob(
  job: ScanJob,
  handlers: {
    onScanStart: (scanId: string, config: ScanConfig) => Promise<void>;
    onReconComplete: (scanId: string, reconData: ReconJobResult) => Promise<void>;
    onScanComplete: (scanId: string) => Promise<void>;
    onScanError: (scanId: string, error: Error) => Promise<void>;
  }
): Promise<JobResult<{ scanId: string; reconData: ReconJobResult }>> {
  const startTime = Date.now();
  const { scanId, config } = job.data;

  try {
    // Notify scan start
    await handlers.onScanStart(scanId, config);

    // The actual scanning is done by spawning agent jobs
    // This job orchestrates the overall scan

    return {
      success: true,
      data: { scanId, reconData: {} as ReconJobResult },
      duration: Date.now() - startTime,
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    await handlers.onScanError(scanId, new Error(errorMessage));
    return {
      success: false,
      error: errorMessage,
      duration: Date.now() - startTime,
    };
  }
}

/**
 * Create scan job data
 */
export function createScanJobData(
  scanId: string,
  config: ScanConfig
): ScanJobData {
  return {
    scanId,
    config,
  };
}