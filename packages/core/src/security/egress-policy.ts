/**
 * Network egress policy for the scanner's own outbound requests (G-02).
 *
 * The scanner fetches URLs that can originate in hostile remote HTML or in
 * finding evidence, and `fetch` follows redirects, so a safe-looking first hop
 * can redirect to a private address. This module classifies a destination and
 * blocks loopback, RFC1918, link-local, unique-local, and cloud-metadata
 * targets unless an explicit local-test policy opts in.
 */
import { promises as dns } from 'dns';
import { isIP } from 'net';

export interface EgressPolicy {
  /** Allow loopback / private / link-local / metadata destinations. Off by default. */
  allowPrivate: boolean;
}

export const DEFAULT_EGRESS_POLICY: EgressPolicy = {
  allowPrivate: process.env.GUARDIANT_ALLOW_PRIVATE_EGRESS === '1',
};

export class EgressBlockedError extends Error {
  constructor(public readonly url: string, public readonly reason: string) {
    super(`Egress blocked for ${url}: ${reason}`);
    this.name = 'EgressBlockedError';
  }
}

/** Classify an IPv4/IPv6 literal as private/reserved. Returns a reason or null. */
export function privateIpReason(ip: string): string | null {
  const v = isIP(ip);
  if (v === 4) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return 'malformed-ipv4';
    const [a, b] = parts as [number, number, number, number];
    if (a === 127) return 'loopback';
    if (a === 10) return 'rfc1918';
    if (a === 172 && b >= 16 && b <= 31) return 'rfc1918';
    if (a === 192 && b === 168) return 'rfc1918';
    if (a === 169 && b === 254) return 'link-local'; // includes 169.254.169.254 metadata
    if (a === 0) return 'unspecified';
    if (a >= 224) return 'multicast-or-reserved';
    if (a === 100 && b >= 64 && b <= 127) return 'cgnat';
    return null;
  }
  if (v === 6) {
    const lower = ip.toLowerCase().replace(/^\[|\]$/g, '');
    if (lower === '::1' || lower === '::') return 'loopback';
    if (lower.startsWith('fe80')) return 'link-local';
    if (lower.startsWith('fc') || lower.startsWith('fd')) return 'unique-local';
    if (lower.startsWith('ff')) return 'multicast';
    // IPv4-mapped (::ffff:a.b.c.d)
    const mapped = lower.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped && mapped[1]) return privateIpReason(mapped[1]);
    return null;
  }
  return 'not-an-ip';
}

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal',
]);

/**
 * Assert a URL is allowed under the policy. Throws EgressBlockedError when a
 * destination is private/reserved. DNS resolution failures are NOT fatal here:
 * an unresolvable host cannot be a private pivot, and the subsequent fetch
 * surfaces the real network error. Only successfully-resolved private IPs block.
 */
export async function assertEgressAllowed(
  url: string,
  policy: EgressPolicy = DEFAULT_EGRESS_POLICY
): Promise<void> {
  if (policy.allowPrivate) return;

  let host: string;
  let protocol: string;
  try {
    const u = new URL(url);
    host = u.hostname.replace(/^\[|\]$/g, '');
    protocol = u.protocol;
  } catch {
    throw new EgressBlockedError(url, 'invalid-url');
  }

  if (protocol !== 'http:' && protocol !== 'https:') {
    throw new EgressBlockedError(url, `disallowed-scheme:${protocol}`);
  }

  if (BLOCKED_HOSTNAMES.has(host.toLowerCase())) {
    throw new EgressBlockedError(url, 'blocked-hostname');
  }

  // Literal IP: classify directly, no DNS.
  if (isIP(host)) {
    const reason = privateIpReason(host);
    if (reason) throw new EgressBlockedError(url, reason);
    return;
  }

  // Hostname: resolve and reject if ANY resolved address is private.
  let addresses: { address: string }[];
  try {
    addresses = await dns.lookup(host, { all: true });
  } catch {
    // Unresolvable — not a private pivot; let fetch report the failure.
    return;
  }
  for (const { address } of addresses) {
    const reason = privateIpReason(address);
    if (reason) throw new EgressBlockedError(url, `${reason} (${host} -> ${address})`);
  }
}
