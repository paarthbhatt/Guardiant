import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  privateIpReason,
  assertEgressAllowed,
  EgressBlockedError,
  DEFAULT_EGRESS_POLICY,
} from '../security/egress-policy.js';
import { createHttpClient } from '../http/index.js';

describe('G-02 egress policy classification', () => {
  it('classifies loopback, RFC1918, link-local, and metadata addresses as private', () => {
    expect(privateIpReason('127.0.0.1')).toBe('loopback');
    expect(privateIpReason('10.1.2.3')).toBe('rfc1918');
    expect(privateIpReason('172.16.0.1')).toBe('rfc1918');
    expect(privateIpReason('172.31.255.255')).toBe('rfc1918');
    expect(privateIpReason('192.168.1.1')).toBe('rfc1918');
    expect(privateIpReason('169.254.169.254')).toBe('link-local'); // cloud metadata
    expect(privateIpReason('::1')).toBe('loopback');
    expect(privateIpReason('fe80::1')).toBe('link-local');
    expect(privateIpReason('fd00::1')).toBe('unique-local');
    expect(privateIpReason('::ffff:127.0.0.1')).toBe('loopback');
  });

  it('does not flag ordinary public addresses', () => {
    expect(privateIpReason('8.8.8.8')).toBeNull();
    expect(privateIpReason('93.184.216.34')).toBeNull();
    expect(privateIpReason('2606:2800:220:1:248:1893:25c8:1946')).toBeNull();
  });

  it('rejects a literal private-IP URL before any socket opens', async () => {
    await expect(assertEgressAllowed('http://169.254.169.254/latest/meta-data/'))
      .rejects.toBeInstanceOf(EgressBlockedError);
    await expect(assertEgressAllowed('http://127.0.0.1:8080/'))
      .rejects.toBeInstanceOf(EgressBlockedError);
  });

  it('rejects localhost and non-http schemes', async () => {
    await expect(assertEgressAllowed('http://localhost/')).rejects.toBeInstanceOf(EgressBlockedError);
    await expect(assertEgressAllowed('file:///etc/passwd')).rejects.toBeInstanceOf(EgressBlockedError);
    await expect(assertEgressAllowed('gopher://10.0.0.1/')).rejects.toBeInstanceOf(EgressBlockedError);
  });

  it('rejects a hostname that resolves to a private address', async () => {
    const dns = await import('dns');
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue([{ address: '10.0.0.5', family: 4 }] as any);
    await expect(assertEgressAllowed('http://sneaky.example/')).rejects.toBeInstanceOf(EgressBlockedError);
    vi.restoreAllMocks();
  });

  it('allows a hostname that resolves to a public address', async () => {
    const dns = await import('dns');
    vi.spyOn(dns.promises, 'lookup').mockResolvedValue([{ address: '93.184.216.34', family: 4 }] as any);
    await expect(assertEgressAllowed('http://public.example/')).resolves.toBeUndefined();
    vi.restoreAllMocks();
  });

  it('honors the allowPrivate opt-out for local testing', async () => {
    await expect(assertEgressAllowed('http://127.0.0.1/', { allowPrivate: true })).resolves.toBeUndefined();
  });

  it('default policy is deny unless GUARDIANT_ALLOW_PRIVATE_EGRESS is set', () => {
    // In the test env the var is unset, so the default must be deny.
    expect(DEFAULT_EGRESS_POLICY.allowPrivate).toBe(false);
  });
});

describe('G-02 HTTP client enforcement', () => {
  afterEach(() => vi.restoreAllMocks());

  it('blocks a direct request to a private IP and never calls fetch', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    await expect(createHttpClient(1000).get('http://169.254.169.254/latest/meta-data/'))
      .rejects.toBeInstanceOf(EgressBlockedError);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('blocks a redirect that points at a private address after a public first hop', async () => {
    const dns = await import('dns');
    vi.spyOn(dns.promises, 'lookup').mockImplementation((async (host: string) => {
      if (host === 'public.example') return [{ address: '93.184.216.34', family: 4 }];
      return [{ address: '10.0.0.5', family: 4 }];
    }) as any);

    const fetchSpy = vi.fn(async (url: string) => new Response('', {
      status: 302,
      headers: { location: 'http://internal.example/admin' },
    }));
    vi.stubGlobal('fetch', fetchSpy as any);

    await expect(createHttpClient(1000).get('http://public.example/start'))
      .rejects.toBeInstanceOf(EgressBlockedError);
    // First hop was dispatched; the redirect target was rejected before its fetch.
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});
