import { describe, it, expect } from 'vitest';
import { redactTarget, redactError, filterMetadata } from '../analytics/index.js';

describe('analytics G-05 telemetry redaction', () => {
  it('reduces a target URL to a host hash with no scheme, port, path, or query', () => {
    const out = redactTarget('https://internal.corp.example:8443/admin/secret?token=abc');
    expect(out).toMatch(/^host:[0-9a-f]{12}$/);
    expect(out).not.toContain('internal.corp.example');
    expect(out).not.toContain('admin');
    expect(out).not.toContain('secret');
    expect(out).not.toContain('token');
    expect(out).not.toContain('8443');
  });

  it('produces a stable hash for the same host and differs across hosts', () => {
    const a1 = redactTarget('http://a.example/one');
    const a2 = redactTarget('http://a.example/two?x=1');
    const b = redactTarget('http://b.example/one');
    expect(a1).toBe(a2);
    expect(a1).not.toBe(b);
  });

  it('does not throw and omits the raw value for an invalid URL', () => {
    const out = redactTarget('not a url');
    expect(out).toMatch(/^host:[0-9a-f]{12}$/);
    expect(out).not.toContain('not a url');
  });

  it('reduces raw error text to a coarse class and never forwards the message', () => {
    expect(redactError(new Error('Request timed out after 20ms'))).toBe('timeout');
    expect(redactError(new Error('connect ECONNREFUSED 10.0.0.5:5432'))).toBe('network');
    expect(redactError(new Error('Unexpected token < in JSON at position 0'))).toBe('parse');
    expect(redactError(new Error('EACCES: permission denied, open /etc/shadow'))).toBe('permission');
    const secret = redactError(new Error('leaked /srv/app/.env value SECRET=hunter2'));
    expect(secret).toBe('other');
    expect(secret).not.toContain('hunter2');
    expect(secret).not.toContain('.env');
  });

  it('drops metadata keys outside the allow-list and non-scalar values', () => {
    const out = filterMetadata({
      count: 5,
      duration_ms: 1200,
      enabled: true,
      target: 'https://internal.example/app',
      path: '/admin',
      note: 'contains /srv/private detail',
      nested: { leak: true },
      list: [1, 2, 3],
    });
    expect(out).toEqual({ count: 5, duration_ms: 1200, enabled: true });
    expect(Object.keys(out)).not.toContain('target');
    expect(Object.keys(out)).not.toContain('path');
    expect(Object.keys(out)).not.toContain('note');
    expect(Object.keys(out)).not.toContain('nested');
    expect(Object.keys(out)).not.toContain('list');
  });

  it('returns an empty object for undefined metadata', () => {
    expect(filterMetadata(undefined)).toEqual({});
  });
});
