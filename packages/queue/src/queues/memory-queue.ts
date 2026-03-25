import type { JobStatus, JobType, JobPriority } from '../types.js';

/**
 * In-memory job representation
 */
interface MemoryJob<T> {
  id: string;
  type: JobType;
  data: T;
  priority: JobPriority;
  status: JobStatus;
  attempts: number;
  maxAttempts: number;
  createdAt: Date;
  startedAt?: Date;
  completedAt?: Date;
  error?: string;
  result?: unknown;
}

/**
 * Job processor function
 */
type JobProcessor<T, R> = (job: MemoryJob<T>) => Promise<R>;

/**
 * In-memory queue configuration
 */
export interface MemoryQueueConfig {
  name: string;
  concurrency?: number;
  timeout?: number;
  maxRetries?: number;
}

/**
 * In-memory queue event handlers
 */
export interface MemoryQueueEvents<T> {
  onWaiting?: (job: MemoryJob<T>) => void;
  onActive?: (job: MemoryJob<T>) => void;
  onCompleted?: (job: MemoryJob<T>, result: unknown) => void;
  onFailed?: (job: MemoryJob<T>, error: Error) => void;
  onProgress?: (job: MemoryJob<T>, progress: number) => void;
}

/**
 * In-memory queue implementation (fallback when Redis is not available)
 */
export class MemoryQueue<T = unknown, R = unknown> {
  private name: string;
  private jobs: Map<string, MemoryJob<T>> = new Map();
  private waiting: string[] = [];
  private active: string[] = [];
  private processors: Map<JobType, JobProcessor<T, R>> = new Map();
  private concurrency: number;
  private timeout: number;
  private maxRetries: number;
  private events: MemoryQueueEvents<T> = {};
  private running = false;
  private jobIdCounter = 0;

  constructor(config: MemoryQueueConfig) {
    this.name = config.name;
    this.concurrency = config.concurrency ?? 1;
    this.timeout = config.timeout ?? 30000;
    this.maxRetries = config.maxRetries ?? 3;
  }

  /**
   * Register a job processor
   */
  process(processor: JobProcessor<T, R>): void {
    this.processors.set(this.name as JobType, processor);
  }

  /**
   * Add a job to the queue
   */
  async add(id: string, data: T, options?: { priority?: JobPriority; maxAttempts?: number }): Promise<string> {
    const priority = options?.priority ?? 'normal';
    const maxAttempts = options?.maxAttempts ?? this.maxRetries;

    const job: MemoryJob<T> = {
      id: id || `${this.name}-${++this.jobIdCounter}`,
      type: this.name as JobType,
      data,
      priority,
      status: 'pending',
      attempts: 0,
      maxAttempts,
      createdAt: new Date(),
    };

    this.jobs.set(job.id, job);
    this.waiting.push(job.id);

    this.events.onWaiting?.(job);

    // Start processing if not already running
    if (!this.running) {
      this.processQueue();
    }

    return job.id;
  }

  /**
   * Get a job by ID
   */
  async getJob(jobId: string): Promise<MemoryJob<T> | undefined> {
    return this.jobs.get(jobId);
  }

  /**
   * Get job counts
   */
  async getJobCounts(): Promise<{ waiting: number; active: number; completed: number; failed: number }> {
    let waiting = 0;
    let active = 0;
    let completed = 0;
    let failed = 0;

    for (const job of this.jobs.values()) {
      switch (job.status) {
        case 'pending':
          waiting++;
          break;
        case 'running':
          active++;
          break;
        case 'completed':
          completed++;
          break;
        case 'failed':
          failed++;
          break;
      }
    }

    return { waiting, active, completed, failed };
  }

  /**
   * Process jobs in the queue
   */
  private async processQueue(): Promise<void> {
    if (this.running) return;
    this.running = true;

    while (this.waiting.length > 0 || this.active.length > 0) {
      // Process up to concurrency limit
      while (this.active.length < this.concurrency && this.waiting.length > 0) {
        const jobId = this.waiting.shift();
        if (!jobId) continue;

        const job = this.jobs.get(jobId);
        if (!job) continue;

        // Process job
        this.active.push(jobId);
        job.status = 'running';
        job.startedAt = new Date();
        this.events.onActive?.(job);

        // Run processor
        this.processJob(job);
      }

      // Small delay to prevent tight loop
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    this.running = false;
  }

  /**
   * Process a single job
   */
  private async processJob(job: MemoryJob<T>): Promise<void> {
    const processor = this.processors.get(job.type);
    if (!processor) {
      job.status = 'failed';
      job.error = `No processor for job type ${job.type}`;
      this.events.onFailed?.(job, new Error(job.error));
      this.active = this.active.filter(id => id !== job.id);
      return;
    }

    try {
      // Execute processor with timeout
      const result = await Promise.race([
        processor(job),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error('Job timeout')), this.timeout)
        ),
      ]);

      job.status = 'completed';
      job.completedAt = new Date();
      job.result = result;
      this.events.onCompleted?.(job, result);
    } catch (error) {
      job.attempts++;

      if (job.attempts >= job.maxAttempts) {
        job.status = 'failed';
        job.error = error instanceof Error ? error.message : 'Unknown error';
        this.events.onFailed?.(job, error instanceof Error ? error : new Error('Unknown error'));
      } else {
        // Retry
        job.status = 'pending';
        this.waiting.push(job.id);
      }
    } finally {
      this.active = this.active.filter(id => id !== job.id);
    }
  }

  /**
   * Set event handlers
   */
  on<E extends keyof MemoryQueueEvents<T>>(event: E, handler: NonNullable<MemoryQueueEvents<T>[E]>): void {
    this.events[event] = handler as never;
  }

  /**
   * Close the queue
   */
  async close(): Promise<void> {
    this.running = false;
    this.jobs.clear();
    this.waiting = [];
    this.active = [];
  }

  /**
   * Pause the queue
   */
  async pause(): Promise<void> {
    this.running = false;
  }

  /**
   * Resume the queue
   */
  async resume(): Promise<void> {
    if (!this.running) {
      this.processQueue();
    }
  }

  /**
   * Drain the queue (remove all jobs)
   */
  async drain(): Promise<void> {
    this.jobs.clear();
    this.waiting = [];
    this.active = [];
  }
}

/**
 * Create a memory queue
 */
export function createMemoryQueue<T = unknown, R = unknown>(
  config: MemoryQueueConfig
): MemoryQueue<T, R> {
  return new MemoryQueue<T, R>(config);
}