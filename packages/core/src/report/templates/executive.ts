import type { ExecutiveSummary, Finding, VulnerabilityChain, TrustInversion } from '@guardiant/shared';
import { SEVERITY_LEVELS } from '@guardiant/shared';

/**
 * Generate executive report content
 */
export function generateExecutiveReport(
	summary: ExecutiveSummary,
	target: string
): string {
	const lines: string[] = [];

	lines.push(`# Executive Security Report`);
	lines.push('');
	lines.push(`**Target:** ${target}`);
	lines.push(`**Date:** ${new Date().toLocaleDateString()}`);
	lines.push('');
	lines.push('---');
	lines.push('');

	// Headline
	lines.push(`## ${summary.headline}`);
	lines.push('');
	lines.push(summary.summary);
	lines.push('');

	// Risk Assessment
	lines.push('## Risk Assessment');
	lines.push('');
	lines.push(`| Risk Score | Risk Level |`);
	lines.push(`|------------|------------|`);
	lines.push(`| ${summary.risk.score}/10 | ${summary.risk.level.toUpperCase()} |`);
	lines.push('');
	lines.push(`**Business Impact:** ${summary.risk.businessImpact}`);
	lines.push('');
	lines.push(`**Data Exposure Risk:** ${summary.risk.dataExposureRisk.toUpperCase()}`);
	lines.push('');

	if (summary.risk.complianceImplications.length > 0) {
		lines.push('**Compliance Implications:**');
		for (const impl of summary.risk.complianceImplications) {
			lines.push(`- ${impl}`);
		}
		lines.push('');
	}

	lines.push(`**Recommended Remediation Timeline:** ${summary.risk.remediationTimeline}`);
	lines.push('');

	// Immediate Actions
	if (summary.immediateActions.length > 0) {
		lines.push('## Immediate Actions Required');
		lines.push('');
		for (const action of summary.immediateActions) {
			lines.push(`- [ ] ${action}`);
		}
		lines.push('');
	}

	// Statistics
	lines.push('## Vulnerability Statistics');
	lines.push('');
	lines.push(`| Severity | Count |`);
	lines.push(`|----------|-------|`);
	lines.push(`| ${SEVERITY_LEVELS.critical.colored} Critical | ${summary.statistics.criticalCount} |`);
	lines.push(`| ${SEVERITY_LEVELS.high.colored} High | ${summary.statistics.highCount} |`);
	lines.push(`| ${SEVERITY_LEVELS.medium.colored} Medium | ${summary.statistics.mediumCount} |`);
	lines.push(`| ${SEVERITY_LEVELS.low.colored} Low | ${summary.statistics.lowCount} |`);
	lines.push('');
	lines.push(`**Total Findings:** ${summary.statistics.totalFindings}`);
	lines.push(`**Chained Vulnerabilities:** ${summary.statistics.chainedVulnerabilities}`);
	lines.push('');

	// Top Vulnerabilities
	if (summary.topVulnerabilities.length > 0) {
		lines.push('## Top Vulnerabilities');
		lines.push('');
		for (const finding of summary.topVulnerabilities) {
			lines.push(`### ${finding.title} [${finding.severity.toUpperCase()}]`);
			lines.push('');
			lines.push(finding.description);
			lines.push('');
			lines.push(`**CVSS Score:** ${finding.cvssScore}/10`);
			lines.push(`**Confidence:** ${(finding.confidence * 100).toFixed(0)}%`);
			lines.push('');
		}
	}

	return lines.join('\n');
}
