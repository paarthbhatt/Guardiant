import { PostHog } from 'posthog-node';

let posthog: PostHog | null = null;

function getPostHog(): PostHog | null {
  if (!process.env.POSTHOG_API_KEY) {
    return null;
  }
  
  if (!posthog) {
    posthog = new PostHog(
      process.env.POSTHOG_API_KEY,
      { 
        host: process.env.POSTHOG_HOST || 'https://app.posthog.com',
        flushAt: 20,
        flushInterval: 10000
      }
    );
  }
  
  return posthog;
}

export interface ScanEvent {
  target: string;
  agents: string[];
  userId?: string;
}

export interface ScanCompletedEvent extends ScanEvent {
  findingsCount: number;
  duration: number;
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  lowCount?: number;
}

export interface FeatureEvent {
  featureName: string;
  userId?: string;
  metadata?: Record<string, any>;
}

/**
 * Telemetry redaction policy (G-05).
 *
 * Analytics is opt-in via POSTHOG_API_KEY, but even then no scan-identifying
 * value may leave the host. Target identity is reduced to a one-way hash, error
 * text is reduced to a coarse class, and feature metadata is restricted to an
 * allow-list of non-identifying scalar values.
 */
export function redactTarget(url: string): string {
  const crypto = require('crypto');
  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    host = 'invalid';
  }
  // Omit scheme, port, path, query. Emit only a stable short hash of the host
  // so repeat scans of the same target correlate without disclosing it.
  const digest = crypto.createHash('sha256').update(host).digest('hex').substring(0, 12);
  return `host:${digest}`;
}

export function redactError(error: unknown): string {
  const msg = (error instanceof Error ? error.message : String(error ?? '')).toLowerCase();
  if (/timed out|timeout|etimedout/.test(msg)) return 'timeout';
  if (/econnrefused|enotfound|eai_again|network|fetch failed|socket/.test(msg)) return 'network';
  if (/json|parse|unexpected token|yaml/.test(msg)) return 'parse';
  if (/permission|eacces|eperm/.test(msg)) return 'permission';
  // Never forward raw error text; unknown classes collapse to a single label.
  return 'other';
}

const FEATURE_METADATA_ALLOW_LIST = new Set([
  'count',
  'duration_ms',
  'severity_count',
  'phase',
  'enabled',
]);

export function filterMetadata(metadata?: Record<string, unknown>): Record<string, number | boolean> {
  const out: Record<string, number | boolean> = {};
  if (!metadata) return out;
  for (const [key, value] of Object.entries(metadata)) {
    if (!FEATURE_METADATA_ALLOW_LIST.has(key)) continue;
    if (typeof value === 'number' && Number.isFinite(value)) out[key] = value;
    else if (typeof value === 'boolean') out[key] = value;
    // Strings, objects, arrays, and unknown keys are dropped: they can carry
    // target names, paths, or source-derived text.
  }
  return out;
}

export class Analytics {
  /**
   * Track when CLI is first installed
   */
  static trackCLIInstalled(userId?: string) {
    const ph = getPostHog();
    if (!ph) return;

    ph.capture({
      distinctId: userId || this.getAnonymousId(),
      event: 'cli_installed',
      properties: {
        platform: process.platform,
        node_version: process.version,
        cli_version: process.env.npm_package_version || 'unknown',
        timestamp: new Date().toISOString(),
      },
    });
  }

  /**
   * Track when a scan starts
   */
  static trackScanStarted(options: ScanEvent) {
    const ph = getPostHog();
    if (!ph) return;

    // # AUDIT-FIX [G-05] resolved: hostname/path and raw error text are no
    // longer sent. Target identity is reduced to a one-way host hash and
    // feature metadata is restricted to a non-identifying allow-list.
    ph.capture({
      distinctId: options.userId || this.getAnonymousId(),
      event: 'scan_started',
      properties: {
        target: redactTarget(options.target),
        agent_count: options.agents.length,
        timestamp: new Date().toISOString(),
      },
    });
  }

  /**
   * Track when a scan completes
   */
  static trackScanCompleted(options: ScanCompletedEvent) {
    const ph = getPostHog();
    if (!ph) return;

    ph.capture({
      distinctId: options.userId || this.getAnonymousId(),
      event: 'scan_completed',
      properties: {
        target: redactTarget(options.target),
        agent_count: options.agents.length,
        findings_count: options.findingsCount,
        critical_count: options.criticalCount || 0,
        high_count: options.highCount || 0,
        medium_count: options.mediumCount || 0,
        low_count: options.lowCount || 0,
        duration_seconds: options.duration,
        has_findings: options.findingsCount > 0,
        timestamp: new Date().toISOString(),
      },
    });
  }

  /**
   * Track scan failures
   */
  static trackScanError(options: {
    target: string;
    error: string;
    userId?: string;
  }) {
    const ph = getPostHog();
    if (!ph) return;

    ph.capture({
      distinctId: options.userId || this.getAnonymousId(),
      event: 'scan_error',
      properties: {
        target: redactTarget(options.target),
        error_class: redactError(options.error),
        timestamp: new Date().toISOString(),
      },
    });
  }

  /**
   * Track report generation
   */
  static trackReportGenerated(options: {
    format: 'json' | 'markdown' | 'html';
    findingsCount: number;
    userId?: string;
  }) {
    const ph = getPostHog();
    if (!ph) return;

    ph.capture({
      distinctId: options.userId || this.getAnonymousId(),
      event: 'report_generated',
      properties: {
        format: options.format,
        findings_count: options.findingsCount,
        timestamp: new Date().toISOString(),
      },
    });
  }

  /**
   * Track feature usage
   */
  static trackFeatureUsed(options: FeatureEvent) {
    const ph = getPostHog();
    if (!ph) return;

    ph.capture({
      distinctId: options.userId || this.getAnonymousId(),
      event: 'feature_used',
      properties: {
        feature_name: options.featureName,
        ...filterMetadata(options.metadata),
        timestamp: new Date().toISOString(),
      },
    });
  }

  /**
   * Gracefully shutdown analytics (flush pending events)
   */
  static async shutdown() {
    const ph = getPostHog();
    if (!ph) return;
    
    try {
      await ph.shutdown();
    } catch (error) {
      console.debug('Analytics shutdown error:', error);
    }
  }

  /**
   * Get anonymous ID (machine-based)
   */
  private static getAnonymousId(): string {
    const crypto = require('crypto');
    const os = require('os');
    
    const identifier = `${os.hostname()}-${os.platform()}-${os.arch()}`;
    return crypto.createHash('sha256').update(identifier).digest('hex').substring(0, 16);
  }
}
