import { Queue, Worker, Job, QueueEvents, type WorkerOptions, type DefaultJobOptions } from 'bullmq';
import type { JobPriority } from '../types.js';

/**
 * Redis queue configuration
 */
export interface RedisQueueConfig {
  name: string;
  connection?: {
    host?: string;
    port?: number;
    password?: string;
    db?: number;
  };
  concurrency?: number;
  timeout?: number;
  maxRetries?: number;
}

/**
 * Redis-backed queue using BullMQ
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export class RedisQueue<T = unknown, _R = unknown> {
  private queue: Queue;
  private worker: Worker | null = null;
  private queueEvents: QueueEvents;
  private name: string;
  private maxRetries: number;
  private concurrency: number;
  private connection: { host: string; port: number; password?: string; db: number };

  constructor(config: RedisQueueConfig) {
    this.name = config.name;
    this.maxRetries = config.maxRetries ?? 3;
    this.concurrency = config.concurrency ?? 4;

    this.connection = config.connection
      ? {
          host: config.connection.host ?? 'localhost',
          port: config.connection.port ?? 6379,
          password: config.connection.password,
          db: config.connection.db ?? 0,
        }
      : { host: 'localhost', port: 6379, db: 0 };

    this.queue = new Queue(this.name, {
      connection: this.connection,
      defaultJobOptions: {
        attempts: this.maxRetries,
        removeOnComplete: 100,
        removeOnFail: 50,
      } satisfies DefaultJobOptions,
    });

    this.queueEvents = new QueueEvents(this.name, { connection: this.connection });
  }

  /**
   * Register a job processor
   */
  process(processor: (job: Job) => Promise<unknown>): void {
    const workerOptions: WorkerOptions = {
      concurrency: this.concurrency,
      connection: this.connection,
    };

    this.worker = new Worker(
      this.name,
      async (job: Job) => {
        return processor(job);
      },
      workerOptions
    );

    // Event handlers
    this.worker.on('completed', (job: Job, result: unknown) => {
      console.log(`Job ${job.id} completed with result:`, result);
    });

    this.worker.on('failed', (job: Job | undefined, error: Error) => {
      console.error(`Job ${job?.id} failed:`, error.message);
    });

    this.worker.on('progress', (job: Job, progress: unknown) => {
      console.log(`Job ${job.id} progress: ${JSON.stringify(progress)}`);
    });
  }

  /**
   * Add a job to the queue
   */
  async add(id: string, data: T, options?: { priority?: JobPriority; maxAttempts?: number }): Promise<string> {
    const priority = this.getPriority(options?.priority);
    const attempts = options?.maxAttempts ?? this.maxRetries;

    const job = await this.queue.add(id, data, {
      jobId: id,
      priority,
      attempts,
    });

    return job.id ?? '';
  }

  /**
   * Get a job by ID
   */
  async getJob(jobId: string): Promise<Job | undefined> {
    return this.queue.getJob(jobId);
  }

  /**
   * Get job counts
   */
  async getJobCounts(): Promise<{
    waiting: number;
    active: number;
    completed: number;
    failed: number;
  }> {
    const counts = await this.queue.getJobCounts('waiting', 'active', 'completed', 'failed');
    return {
      waiting: counts.waiting ?? 0,
      active: counts.active ?? 0,
      completed: counts.completed ?? 0,
      failed: counts.failed ?? 0,
    };
  }

  /**
   * Close the queue
   */
  async close(): Promise<void> {
    await this.queueEvents.close();
    if (this.worker) {
      await this.worker.close();
    }
    await this.queue.close();
  }

  /**
   * Pause the queue
   */
  async pause(): Promise<void> {
    await this.queue.pause();
  }

  /**
   * Resume the queue
   */
  async resume(): Promise<void> {
    await this.queue.resume();
  }

  /**
   * Drain the queue
   */
  async drain(): Promise<void> {
    await this.queue.drain();
  }

  /**
   * Convert priority string to number
   */
  private getPriority(priority?: JobPriority): number {
    switch (priority) {
      case 'critical':
        return 1;
      case 'high':
        return 2;
      case 'normal':
        return 3;
      case 'low':
        return 4;
      default:
        return 3;
    }
  }
}

/**
 * Create a Redis queue
 */
export function createRedisQueue<T = unknown>(
  config: RedisQueueConfig
): RedisQueue<T> {
  return new RedisQueue<T>(config);
}

/**
 * Check if Redis is available
 */
export async function isRedisAvailable(
  connection?: { host?: string; port?: number; password?: string }
): Promise<boolean> {
  try {
    const { default: Redis } = await import('ioredis');
    const redis = new Redis({
      host: connection?.host ?? 'localhost',
      port: connection?.port ?? 6379,
      password: connection?.password,
      maxRetriesPerRequest: 1,
      lazyConnect: true,
    });

    await redis.connect();
    await redis.ping();
    await redis.quit();

    return true;
  } catch {
    return false;
  }
}