import type { ReportJobData, JobResult } from '../types.js';
import type { Report, ReportOptions } from '@guardiant/shared';

/**
 * Report job interface
 */
export interface ReportJob {
  id: string;
  name: string;
  data: ReportJobData;
  priority: number;
  attempts: number;
  maxAttempts: number;
}

/**
 * Report job handlers
 */
export interface ReportJobHandlers {
  generateReport: (scanId: string, options: ReportOptions) => Promise<Report>;
  storeReport: (report: Report) => Promise<void>;
}

/**
 * Process report job
 */
export async function processReportJob(
  job: ReportJob,
  handlers: ReportJobHandlers
): Promise<JobResult<Report>> {
  const startTime = Date.now();
  const { scanId, audience, format } = job.data;

  try {
    // Generate report
    const report = await handlers.generateReport(scanId, {
      audience,
      format,
      includePocs: true,
      includeCodeSnippets: true,
    });

    // Store report
    await handlers.storeReport(report);

    return {
      success: true,
      data: report,
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
 * Create report job data
 */
export function createReportJobData(
  scanId: string,
  audience: ReportJobData['audience'],
  format: ReportJobData['format']
): ReportJobData {
  return {
    scanId,
    audience,
    format,
  };
}