/**
 * In-memory recon data cache
 *
 * Avoids re-running the Recon agent for the same target within a configurable
 * TTL. Useful when running multiple scans against the same host in quick
 * succession (e.g. repeated CLI invocations during development, or integration
 * tests).
 */

import type { ReconData } from '@guardiant/shared';

interface CacheEntry {
  data: ReconData;
  expiresAt: number;
}

export class ReconCache {
  private store: Map<string, CacheEntry> = new Map();
  private readonly ttlMs: number;

  /**
   * @param ttlMs Time-to-live in milliseconds (default: 5 minutes)
   */
  constructor(ttlMs = 5 * 60 * 1000) {
    this.ttlMs = ttlMs;
  }

  /**
   * Return cached recon data for a target URL if it exists and is not expired.
   */
  get(target: string): ReconData | null {
    const entry = this.store.get(this.key(target));
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(this.key(target));
      return null;
    }
    return entry.data;
  }

  /**
   * Store recon data for a target URL.
   */
  set(target: string, data: ReconData): void {
    this.store.set(this.key(target), {
      data,
      expiresAt: Date.now() + this.ttlMs,
    });
  }

  /**
   * Explicitly remove a target from the cache.
   */
  invalidate(target: string): void {
    this.store.delete(this.key(target));
  }

  /**
   * Remove all expired entries.
   */
  prune(): void {
    const now = Date.now();
    for (const [key, entry] of this.store) {
      if (now > entry.expiresAt) this.store.delete(key);
    }
  }

  /**
   * Clear the entire cache.
   */
  clear(): void {
    this.store.clear();
  }

  /**
   * Returns the number of live (non-expired) entries.
   */
  get size(): number {
    this.prune();
    return this.store.size;
  }

  private key(target: string): string {
    // Normalise: strip trailing slash, lowercase scheme+host
    try {
      const url = new URL(target);
      return `${url.protocol}//${url.host}${url.pathname}`.toLowerCase().replace(/\/$/, '');
    } catch {
      return target.toLowerCase();
    }
  }
}

/** Singleton cache shared across orchestrator instances in the same process */
export const reconCache = new ReconCache();
