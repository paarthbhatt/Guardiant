import type { Finding, AppContext } from '@guardiant/shared';

/**
 * A suppression rule that filters out known false positive patterns.
 */
export interface SuppressionRule {
  /** Unique rule ID */
  id: string;
  /** Human-readable description */
  description: string;
  /** Returns true if the finding should be suppressed */
  matches: (finding: Finding, appContext?: AppContext) => boolean;
}

/**
 * Suppresses findings that flag NEXT_PUBLIC_*, REACT_APP_*, VITE_*, EXPO_PUBLIC_*
 * environment variables as secrets. These are intentionally public by framework design.
 */
const nextPublicNotSecret: SuppressionRule = {
  id: 'next_public_not_secret',
  description: 'Framework public env vars (NEXT_PUBLIC_*, REACT_APP_*, VITE_*) are intentionally exposed',
  matches: (finding) => {
    if (finding.discoveredBy !== 'secrets') return false;

    const snippet = finding.evidence.snippet ?? finding.evidence.pattern ?? '';
    const file = finding.evidence.file ?? '';
    const context = finding.evidence.context;
    const keyType = (context as Record<string, unknown>)?.keyType as string ?? '';

    const publicPrefixes = /NEXT_PUBLIC_|REACT_APP_|VITE_|EXPO_PUBLIC_/;

    // Check the snippet, file path, keyType, and title for public env var patterns
    return (
      publicPrefixes.test(snippet) ||
      publicPrefixes.test(file) ||
      publicPrefixes.test(keyType) ||
      (publicPrefixes.test(finding.title) && /env.*var/i.test(finding.title))
    );
  },
};

/**
 * Suppresses findings that only have VCVF pattern evidence and no actual
 * code location, HTTP evidence, or payload data.
 *
 * This is the #1 source of false positives: agents generate findings from
 * VCVF pattern presence alone without verifying the vulnerability exists.
 */
const vcvfPatternOnly: SuppressionRule = {
  id: 'vcvf_pattern_only',
  description: 'Findings with only VCVF pattern context and no concrete evidence',
  matches: (finding) => {
    // Only apply to agents that are known to generate speculative findings
    const speculativeAgents = ['auth', 'business_logic', 'race_condition'];
    if (!speculativeAgents.includes(finding.discoveredBy)) return false;

    const ev = finding.evidence;

    // Check if the finding has ANY concrete evidence beyond VCVF pattern context
    const hasFileLocation = Boolean(ev.file && ev.line);
    const hasSnippet = Boolean(ev.snippet && ev.snippet.length > 20);
    const hasRequestResponse = Boolean(ev.request || ev.response);
    const hasPayload = Boolean(ev.payload);
    const hasEndpoints = Boolean(ev.endpoints && ev.endpoints.length > 0);

    const hasConcreteEvidence = hasFileLocation || hasSnippet || hasRequestResponse || hasPayload || hasEndpoints;

    // If the only "evidence" is a VCVF pattern in context, suppress
    if (!hasConcreteEvidence && ev.context && typeof ev.context === 'object') {
      const ctx = ev.context as Record<string, unknown>;
      if (ctx.pattern && typeof ctx.pattern === 'string') {
        return true;
      }
    }

    return false;
  },
};

/**
 * Suppresses findings where the app context indicates the finding is
 * not relevant (e.g., payment manipulation on a blog app).
 */
const appTypeMismatch: SuppressionRule = {
  id: 'app_type_mismatch',
  description: 'Finding is irrelevant to the detected application type',
  matches: (finding, appContext) => {
    if (!appContext) return false;

    // Check if the finding's rule is in the app's suppressions list
    const findingKey = `${finding.discoveredBy}.${finding.tags.find(t =>
      t.includes('payment') || t.includes('quantity') || t.includes('coupon') ||
      t.includes('workflow') || t.includes('feature-flag') || t.includes('idor') ||
      t.includes('session') || t.includes('oauth') || t.includes('jwt') ||
      t.includes('password-reset') || t.includes('double-spend') ||
      t.includes('counter') || t.includes('toctou') || t.includes('race')
    ) ?? ''}`;

    return appContext.suppressions.some(s => findingKey.includes(s.split('.')[1] ?? '__none__'));
  },
};

/**
 * All suppression rules, evaluated in order.
 * First match wins — the finding is suppressed.
 */
export const SUPPRESSION_RULES: SuppressionRule[] = [
  nextPublicNotSecret,
  vcvfPatternOnly,
  appTypeMismatch,
];
