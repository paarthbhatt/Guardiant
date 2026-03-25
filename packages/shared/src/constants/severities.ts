import type { Severity } from '../types/vulnerability.js';

/**
 * Severity level configuration
 */
export const SEVERITY_CONFIG: Record<Severity, {
  score: number;
  color: string;
  label: string;
  icon: string;
  description: string;
}> = {
  critical: {
    score: 10,
    color: '#dc2626',
    label: 'Critical',
    icon: '🔴',
    description: 'Exploitation is straightforward and leads to severe impact. Immediate remediation required.',
  },
  high: {
    score: 8,
    color: '#ea580c',
    label: 'High',
    icon: '🟠',
    description: 'Exploitation is possible and could lead to significant data breach or system compromise.',
  },
  medium: {
    score: 5,
    color: '#d97706',
    label: 'Medium',
    icon: '🟡',
    description: 'Exploitation requires specific conditions but could lead to data exposure.',
  },
  low: {
    score: 3,
    color: '#059669',
    label: 'Low',
    icon: '🟢',
    description: 'Exploitation is difficult or impact is limited. Remediation recommended.',
  },
  info: {
    score: 0,
    color: '#6b7280',
    label: 'Info',
    icon: 'ℹ️',
    description: 'No direct security impact but represents a best practice deviation.',
  },
};

/**
 * Calculate severity from CVSS score
 */
export function cvssToSeverity(cvssScore: number): Severity {
  if (cvssScore >= 9) return 'critical';
  if (cvssScore >= 7) return 'high';
  if (cvssScore >= 4) return 'medium';
  if (cvssScore >= 1) return 'low';
  return 'info';
}

/**
 * Calculate severity from confidence and impact
 */
export function calculateSeverity(
  impact: 'critical' | 'high' | 'medium' | 'low',
  confidence: number,
  exploitability: 'easy' | 'moderate' | 'difficult' = 'moderate'
): Severity {
  const impactScores = { critical: 10, high: 8, medium: 5, low: 3 } as const;
  const exploitabilityMultipliers = { easy: 1, moderate: 0.8, difficult: 0.6 } as const;

  const baseScore = (impactScores[impact] ?? 5) * (exploitabilityMultipliers[exploitability] ?? 0.8);
  const adjustedScore = baseScore * confidence;

  return cvssToSeverity(adjustedScore);
}

/**
 * Compare severities for sorting
 */
export function compareSeverities(a: Severity, b: Severity): number {
  const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  return order.indexOf(a) - order.indexOf(b);
}

/**
 * Get severity color for terminal output
 */
export function getSeverityColor(severity: Severity): string {
  return SEVERITY_CONFIG[severity].color;
}

/**
 * Get severity icon for display
 */
export function getSeverityIcon(severity: Severity): string {
  return SEVERITY_CONFIG[severity].icon;
}
