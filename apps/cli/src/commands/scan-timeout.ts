export class ScanTimeoutError extends Error {
  constructor(timeoutMs: number) {
    super(`scan timeout after ${timeoutMs}ms`);
    this.name = 'ScanTimeoutError';
  }
}

export async function runWithTimeout<T>(
  operation: () => Promise<T>,
  timeoutMs: number,
  onTimeout?: () => void,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const operationPromise = Promise.resolve().then(operation);
  // The operation may still settle after the deadline. Attach a rejection
  // handler so cancellation does not turn into an unhandled rejection.
  operationPromise.catch(() => undefined);

  try {
    return await Promise.race([
      operationPromise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          onTimeout?.();
          reject(new ScanTimeoutError(timeoutMs));
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
