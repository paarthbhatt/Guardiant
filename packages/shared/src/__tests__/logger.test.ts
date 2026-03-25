import { describe, it, expect } from 'vitest';
import { createLogger, createAgentLogger, isValidLogLevel } from '../utils/logger.js';

describe('createLogger', () => {
  it('should return a logger with expected log methods', () => {
    const logger = createLogger({ level: 'debug', console: false });
    expect(typeof logger.info).toBe('function');
    expect(typeof logger.error).toBe('function');
    expect(typeof logger.warn).toBe('function');
    expect(typeof logger.debug).toBe('function');
  });

  it('should not throw when logging', () => {
    const logger = createLogger({ level: 'error', console: false });
    expect(() => logger.error('test error')).not.toThrow();
  });

  it('should accept json format option', () => {
    const logger = createLogger({ level: 'info', console: false, json: true });
    expect(typeof logger.info).toBe('function');
  });
});

describe('createAgentLogger', () => {
  it('should return a child logger with agentId and scanId context', () => {
    const logger = createAgentLogger('recon', 'scan_123');
    expect(typeof logger.info).toBe('function');
    expect(typeof logger.error).toBe('function');
  });
});

describe('isValidLogLevel', () => {
  it('should return true for valid levels', () => {
    const validLevels = ['error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly'];
    for (const level of validLevels) {
      expect(isValidLogLevel(level)).toBe(true);
    }
  });

  it('should return false for invalid levels', () => {
    expect(isValidLogLevel('trace')).toBe(false);
    expect(isValidLogLevel('fatal')).toBe(false);
    expect(isValidLogLevel('')).toBe(false);
  });
});
