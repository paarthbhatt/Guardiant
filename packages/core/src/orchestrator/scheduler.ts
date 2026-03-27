/**
 * Scheduler for managing scan jobs
 */

import type { AgentId } from '@guardiant/shared';
import type { ScanJobData, AgentJobData } from '@guardiant/queue';
import { MemoryQueue } from '@guardiant/queue';
import { AGENT_EXECUTION_ORDER } from './constants.js';

/**
 * Job priority
 */
export type JobPriority = 'critical' | 'high' | 'normal' | 'low';

/**
 * Scheduled job
 */
export interface ScheduledJob {
  id: string;
  type: 'scan' | 'agent' | 'analysis';
  priority: JobPriority;
  status: 'pending' | 'running' | 'completed' | 'failed';
  scheduledAt: Date;
  startedAt?: Date;
  completedAt?: Date;
  data: ScanJobData | AgentJobData;
  result?: unknown;
  error?: string;
}

/**
 * Scheduler options
 */
export interface SchedulerOptions {
  maxConcurrency?: number;
  queueBackend?: 'memory' | 'redis';
}

/**
 * Default scheduler options
 */
const DEFAULT_OPTIONS: Required<SchedulerOptions> = {
  maxConcurrency: 4,
  queueBackend: 'memory',
};

/**
 * Job scheduler
 */
export class Scheduler {
  private scanQueue: MemoryQueue<ScanJobData>;
  private agentQueue: MemoryQueue<AgentJobData>;
  private jobs: Map<string, ScheduledJob> = new Map();

  constructor(options: SchedulerOptions = {}) {
    const maxConcurrency = options.maxConcurrency ?? DEFAULT_OPTIONS.maxConcurrency;

    // Create queues
    this.scanQueue = new MemoryQueue<ScanJobData, void>({
      name: 'scans',
      concurrency: maxConcurrency
    });
    this.agentQueue = new MemoryQueue<AgentJobData, void>({
      name: 'agents',
      concurrency: maxConcurrency
    });

    // Set up event handlers
    this.setupQueueHandlers();
  }

  /**
   * Set up queue event handlers
   */
  private setupQueueHandlers(): void {
    this.scanQueue.on('waiting', (job) => {
      this.updateJobStatus(job.id, 'pending');
    });

    this.scanQueue.on('active', (job) => {
      this.updateJobStatus(job.id, 'running');
    });

    this.scanQueue.on('completed', (job, result) => {
      this.updateJobStatus(job.id, 'completed', result);
    });

    this.scanQueue.on('failed', (job, error) => {
      this.updateJobStatus(job.id, 'failed', undefined, error.message);
    });

    this.agentQueue.on('waiting', (job) => {
      this.updateJobStatus(job.id, 'pending');
    });

    this.agentQueue.on('active', (job) => {
      this.updateJobStatus(job.id, 'running');
    });

    this.agentQueue.on('completed', (job, result) => {
      this.updateJobStatus(job.id, 'completed', result);
    });

    this.agentQueue.on('failed', (job, error) => {
      this.updateJobStatus(job.id, 'failed', undefined, error.message);
    });
  }

  /**
   * Update job status
   */
  private updateJobStatus(
    jobId: string,
    status: ScheduledJob['status'],
    result?: unknown,
    error?: string
  ): void {
    const job = this.jobs.get(jobId);
    if (!job) return;

    job.status = status;
    if (status === 'running') {
      job.startedAt = new Date();
    } else if (status === 'completed' || status === 'failed') {
      job.completedAt = new Date();
    }
    if (result) job.result = result;
    if (error) job.error = error;
  }

  /**
   * Schedule a scan job
   */
  async scheduleScan(data: ScanJobData, priority: JobPriority = 'normal'): Promise<string> {
    const jobId = data.scanId;

    const job: ScheduledJob = {
      id: jobId,
      type: 'scan',
      priority,
      status: 'pending',
      scheduledAt: new Date(),
      data,
    };

    this.jobs.set(jobId, job);
    await this.scanQueue.add(jobId, data, { priority });

    return jobId;
  }

  /**
   * Schedule an agent job
   */
  async scheduleAgent(data: AgentJobData, priority: JobPriority = 'normal'): Promise<string> {
    const jobId = `${data.scanId}_${data.agentId}`;

    const job: ScheduledJob = {
      id: jobId,
      type: 'agent',
      priority,
      status: 'pending',
      scheduledAt: new Date(),
      data,
    };

    this.jobs.set(jobId, job);
    await this.agentQueue.add(jobId, data, { priority });

    return jobId;
  }

  /**
   * Schedule all agents for a scan
   */
  async scheduleAllAgents(scanId: string, target: string, reconData?: unknown): Promise<string[]> {
    const jobIds: string[] = [];

    // Phase 1: Schedule recon first
    const reconId = await this.scheduleAgent(
      { scanId, agentId: 'recon' as AgentId, target, reconData: reconData as AgentJobData['reconData'] },
      'critical'
    );
    jobIds.push(reconId);

    // Phase 2: Schedule all other agents
    // Note: In reality, these should wait for recon to complete
    const parallelAgents = AGENT_EXECUTION_ORDER[1] || [];
    for (const agentId of parallelAgents) {
      const jobId = await this.scheduleAgent(
        { scanId, agentId, target },
        'normal'
      );
      jobIds.push(jobId);
    }

    return jobIds;
  }

  /**
   * Get job status
   */
  getJobStatus(jobId: string): ScheduledJob | undefined {
    return this.jobs.get(jobId);
  }

  /**
   * Get all jobs
   */
  getAllJobs(): ScheduledJob[] {
    return Array.from(this.jobs.values());
  }

  /**
   * Get pending jobs
   */
  getPendingJobs(): ScheduledJob[] {
    return this.getAllJobs().filter(j => j.status === 'pending');
  }

  /**
   * Get running jobs
   */
  getRunningJobs(): ScheduledJob[] {
    return this.getAllJobs().filter(j => j.status === 'running');
  }

  /**
   * Cancel a job
   */
  async cancelJob(jobId: string): Promise<boolean> {
    const job = this.jobs.get(jobId);
    if (!job || job.status === 'completed' || job.status === 'failed') {
      return false;
    }

    job.status = 'failed';
    job.error = 'Cancelled';
    job.completedAt = new Date();

    return true;
  }

  /**
   * Close the scheduler
   */
  async close(): Promise<void> {
    await this.scanQueue.close();
    await this.agentQueue.close();
  }
}

/**
 * Create scheduler
 */
export function createScheduler(options?: SchedulerOptions): Scheduler {
  return new Scheduler(options);
}