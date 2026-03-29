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

    ph.capture({
      distinctId: options.userId || this.getAnonymousId(),
      event: 'scan_started',
      properties: {
        target: this.sanitizeUrl(options.target),
        agents: options.agents,
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
        target: this.sanitizeUrl(options.target),
        agents: options.agents,
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
        target: this.sanitizeUrl(options.target),
        error_message: options.error,
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
        ...options.metadata,
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

  /**
   * Sanitize URL to remove sensitive data
   */
  private static sanitizeUrl(url: string): string {
    try {
      const parsed = new URL(url);
      return `${parsed.protocol}//${parsed.hostname}${parsed.pathname}`;
    } catch {
      return 'invalid-url';
    }
  }
}
