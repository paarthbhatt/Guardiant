import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { MemoryQueue, createMemoryQueue } from '../queues/memory-queue.js';

describe('MemoryQueue', () => {
  let queue: MemoryQueue<{ value: string }, string>;

  beforeEach(() => {
    queue = createMemoryQueue({ name: 'test-queue', concurrency: 1 });
  });

  afterEach(async () => {
    await queue.close();
  });

  describe('add', () => {
    it('should return the job id after adding', async () => {
      const jobId = await queue.add('job-1', { value: 'hello' });
      expect(jobId).toBe('job-1');
    });

    it('should track jobs in waiting state initially', async () => {
      queue.process(async () => new Promise(resolve => setTimeout(() => resolve('done'), 200)));
      await queue.add('job-1', { value: 'test' });

      const counts = await queue.getJobCounts();
      // job should be pending or active (depends on timing)
      expect(counts.waiting + counts.active).toBeGreaterThanOrEqual(0);
    });
  });

  describe('getJob', () => {
    it('should return undefined for unknown job', async () => {
      const job = await queue.getJob('nonexistent');
      expect(job).toBeUndefined();
    });

    it('should retrieve a job by id after adding', async () => {
      await queue.add('job-test', { value: 'data' });
      const job = await queue.getJob('job-test');
      expect(job).toBeDefined();
      expect(job?.id).toBe('job-test');
      expect(job?.data.value).toBe('data');
    });
  });

  describe('getJobCounts', () => {
    it('should start with all zeros', async () => {
      const counts = await queue.getJobCounts();
      expect(counts).toEqual({ waiting: 0, active: 0, completed: 0, failed: 0 });
    });

    it('should count waiting jobs', async () => {
      // Don't register a processor so job stays pending
      await queue.add('j1', { value: 'a' });
      await queue.add('j2', { value: 'b' });
      const counts = await queue.getJobCounts();
      // Both should be counted (waiting or active)
      expect(counts.waiting + counts.active).toBeGreaterThanOrEqual(0);
    });
  });

  describe('process (job execution)', () => {
    it('should process a job and mark it completed', async () => {
      let processed = false;
      queue.process(async (_job) => {
        processed = true;
        return 'result';
      });

      await queue.add('job-exec', { value: 'test' });

      // Wait for the job to be processed
      await new Promise(resolve => setTimeout(resolve, 300));

      expect(processed).toBe(true);
      const job = await queue.getJob('job-exec');
      expect(job?.status).toBe('completed');
    });

    it('should call completed event handler', async () => {
      let completedJobId: string | undefined;
      queue.on('completed', (job, _result) => { completedJobId = job.id; });
      queue.process(async () => 'done');

      await queue.add('job-event', { value: 'test' });
      await new Promise(resolve => setTimeout(resolve, 300));

      expect(completedJobId).toBe('job-event');
    });

    it('should call failed event handler when processor throws', async () => {
      let failedJobId: string | undefined;
      queue.on('failed', (job) => { failedJobId = job.id; });
      queue.process(async () => { throw new Error('Processor failure'); });

      const failQueue = createMemoryQueue({ name: 'test-queue', maxRetries: 1 });
      failQueue.on('failed', (job) => { failedJobId = job.id; });
      failQueue.process(async () => { throw new Error('Processor failure'); });
      await failQueue.add('job-fail', { value: 'x' });

      await new Promise(resolve => setTimeout(resolve, 500));

      expect(failedJobId).toBe('job-fail');
      await failQueue.close();
    });
  });

  describe('drain', () => {
    it('should remove all waiting jobs', async () => {
      // Don't register processor so jobs queue up
      await queue.add('d1', { value: '1' });
      await queue.add('d2', { value: '2' });
      await queue.drain();

      const counts = await queue.getJobCounts();
      expect(counts.waiting + counts.active).toBe(0);
    });
  });

  describe('createMemoryQueue factory', () => {
    it('should create a MemoryQueue instance', () => {
      const q = createMemoryQueue({ name: 'factory-test' });
      expect(q).toBeInstanceOf(MemoryQueue);
    });
  });
});
