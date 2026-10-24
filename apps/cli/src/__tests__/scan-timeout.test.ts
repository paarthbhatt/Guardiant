import { describe, expect, it, vi } from 'vitest';
import { runWithTimeout, ScanTimeoutError } from '../commands/scan-timeout.js';

describe('scan timeout handling', () => {
  it('aborts on deadline and does not leave a rejecting operation unhandled', async () => {
    const onTimeout = vi.fn();
    const lateFailure = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('late scan failure')), 25);
    });

    await expect(runWithTimeout(() => lateFailure, 1, onTimeout)).rejects.toBeInstanceOf(ScanTimeoutError);
    expect(onTimeout).toHaveBeenCalledOnce();
    await new Promise(resolve => setTimeout(resolve, 35));
  });

  it('returns the scan result and clears the timeout when it completes first', async () => {
    const onTimeout = vi.fn();

    await expect(runWithTimeout(async () => 'complete', 50, onTimeout)).resolves.toBe('complete');
    expect(onTimeout).not.toHaveBeenCalled();
  });
});
