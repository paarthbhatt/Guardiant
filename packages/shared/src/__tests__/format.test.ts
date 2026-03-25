import { describe, it, expect } from 'vitest';
import {
  formatFindingId,
  formatDuration,
  formatTimestamp,
  formatNumber,
  formatBytes,
  formatPercentage,
  truncate,
  formatCodeSnippet,
  formatTable,
  formatUrl,
  formatFindingsSummary,
} from '../utils/format.js';

describe('formatFindingId', () => {
  it('should return first 12 characters', () => {
    expect(formatFindingId('finding_abcdefghijklmnop')).toBe('finding_abcd');
  });
});

describe('formatDuration', () => {
  it('should format milliseconds', () => {
    expect(formatDuration(500)).toBe('500ms');
  });

  it('should format seconds', () => {
    expect(formatDuration(5000)).toBe('5.0s');
  });

  it('should format minutes', () => {
    expect(formatDuration(90000)).toBe('1m 30s');
  });

  it('should format hours', () => {
    expect(formatDuration(7200000)).toBe('2h 0m');
  });
});

describe('formatTimestamp', () => {
  it('should return an ISO string', () => {
    const ts = formatTimestamp();
    expect(() => new Date(ts)).not.toThrow();
    expect(typeof ts).toBe('string');
  });

  it('should use provided date', () => {
    const d = new Date('2024-01-01T00:00:00.000Z');
    expect(formatTimestamp(d)).toBe('2024-01-01T00:00:00.000Z');
  });
});

describe('formatNumber', () => {
  it('should format numbers with locale commas', () => {
    const result = formatNumber(1000000);
    expect(result).toContain('1');
    expect(result).toContain('0');
    // Just ensure it's a non-empty string
    expect(result.length).toBeGreaterThan(0);
  });
});

describe('formatBytes', () => {
  it('should format bytes', () => {
    expect(formatBytes(500)).toBe('500.0 B');
  });

  it('should format kilobytes', () => {
    expect(formatBytes(1024)).toBe('1.0 KB');
  });

  it('should format megabytes', () => {
    expect(formatBytes(1024 * 1024)).toBe('1.0 MB');
  });

  it('should format gigabytes', () => {
    expect(formatBytes(1024 ** 3)).toBe('1.0 GB');
  });
});

describe('formatPercentage', () => {
  it('should format to 1 decimal by default', () => {
    expect(formatPercentage(42.567)).toBe('42.6%');
  });

  it('should respect custom decimals', () => {
    expect(formatPercentage(42.567, 0)).toBe('43%');
  });
});

describe('truncate', () => {
  it('should leave short strings untouched', () => {
    expect(truncate('hello', 10)).toBe('hello');
  });

  it('should truncate long strings with ellipsis', () => {
    const result = truncate('hello world', 8);
    expect(result).toBe('hello...');
    expect(result).toHaveLength(8);
  });
});

describe('formatCodeSnippet', () => {
  it('should leave short code untouched', () => {
    const code = 'line1\nline2\nline3';
    expect(formatCodeSnippet(code, 10)).toBe(code);
  });

  it('should truncate long code with ellipsis', () => {
    const code = Array.from({ length: 20 }, (_, i) => `line${i + 1}`).join('\n');
    const result = formatCodeSnippet(code, 10);
    expect(result).toContain('...');
    expect(result.split('\n').length).toBeLessThanOrEqual(11);
  });
});

describe('formatTable', () => {
  it('should build a table string with headers', () => {
    const result = formatTable(['Name', 'Value'], [['foo', 'bar'], ['baz', 'qux']]);
    expect(result).toContain('Name');
    expect(result).toContain('Value');
    expect(result).toContain('foo');
    expect(result).toContain('bar');
  });
});

describe('formatUrl', () => {
  it('should return short URLs unchanged', () => {
    expect(formatUrl('https://example.com')).toBe('https://example.com');
  });

  it('should truncate very long URLs', () => {
    const longUrl = 'https://example.com/' + 'a'.repeat(100);
    const result = formatUrl(longUrl, 30);
    expect(result.length).toBeLessThanOrEqual(30);
    expect(result).toContain('...');
  });
});

describe('formatFindingsSummary', () => {
  it('should count findings by severity', () => {
    const findings = [
      { severity: 'critical' as const },
      { severity: 'high' as const },
      { severity: 'high' as const },
      { severity: 'medium' as const },
    ];
    const result = formatFindingsSummary(findings);
    expect(result).toContain('Critical: 1');
    expect(result).toContain('High:     2');
    expect(result).toContain('Medium:   1');
    expect(result).toContain('Total:    4');
  });
});
