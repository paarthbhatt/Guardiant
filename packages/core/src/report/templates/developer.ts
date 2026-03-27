import type { DeveloperReport, OWASPCategory, Finding, Severity } from '@guardiant/shared';
import { OWASP_CATEGORIES } from '@guardiant/shared';

/**
 * Generate developer report content
 */
export function generateDeveloperReport(report: DeveloperReport): string {
	const lines: string[] = [];

	lines.push(`# Developer Security Report`);
	lines.push('');
	lines.push(`**Generated:** ${new Date().toLocaleString()}`);
	lines.push('');
	lines.push('---');
	lines.push('');

	// Summary
	lines.push('## Summary');
	lines.push('');
	const total = report.vulnerabilities.length;
	const bySev = report.bySeverity;
	lines.push(`Total vulnerabilities: **${total}**`);
	lines.push(`- Critical: ${bySev.critical.length}`);
	lines.push(`- High: ${bySev.high.length}`);
	lines.push(`- Medium: ${bySev.medium.length}`);
	lines.push(`- Low: ${bySev.low.length}`);
	lines.push(`- Info: ${bySev.info.length}`);
	lines.push('');

	// By Severity
	lines.push('## Findings by Severity');
	lines.push('');

	for (const severity of ['critical', 'high', 'medium', 'low', 'info'] as Severity[]) {
		const findings = report.bySeverity[severity];
		if (findings.length === 0) continue;

		lines.push(`### ${severity.toUpperCase()} (${findings.length})`);
		lines.push('');

		for (const finding of findings) {
			lines.push(`#### ${finding.title}`);
			lines.push('');
			lines.push(`**Category:** ${getCategoryName(finding.category)}`);
			lines.push(`**CVSS:** ${finding.cvssScore}/10`);
			lines.push(`**Confidence:** ${(finding.confidence * 100).toFixed(0)}%`);
			lines.push('');
			lines.push('**Description:**');
			lines.push(finding.description);
			lines.push('');

			if (finding.evidence.file) {
				lines.push(`**Location:** ${finding.evidence.file}${finding.evidence.line ? `:${finding.evidence.line}` : ''}`);
				lines.push('');
			}

			lines.push('**Remediation:**');
			lines.push(finding.remediation.summary);
			lines.push('');
			for (const step of finding.remediation.steps) {
				lines.push(`1. ${step}`);
			}
			lines.push('');

			if (finding.remediation.effort) {
				lines.push(`**Estimated Effort:** ${finding.remediation.effort}`);
				lines.push('');
			}
		}
	}

	// By Category
	lines.push('## Findings by OWASP Category');
	lines.push('');

	for (const [category, findings] of Object.entries(report.byCategory)) {
		const categoryInfo = OWASP_CATEGORIES[category as OWASPCategory];
		lines.push(`### ${categoryInfo?.name ?? category} (${findings.length})`);
		lines.push('');
		lines.push(categoryInfo?.description ?? '');
		lines.push('');

		for (const finding of findings) {
			lines.push(`- **${finding.title}** [${finding.severity}] - ${getLocation(finding)}`);
		}
		lines.push('');
	}

	// Affected Files
	if (report.affectedFiles.length > 0) {
		lines.push('## Affected Files');
		lines.push('');
		lines.push(`| File | Risk Level | Findings |`);
		lines.push(`|------|------------|----------|`);
		for (const file of report.affectedFiles) {
			lines.push(`| \`${file.path}\` | ${file.riskLevel.toUpperCase()} | ${file.findings.length} |`);
		}
		lines.push('');
	}

	// Priority Queue
	if (report.priorityQueue.length > 0) {
		lines.push('## Remediation Priority Queue');
		lines.push('');
		lines.push('Vulnerabilities are ordered by severity (highest first), then by remediation effort (lowest first).');
		lines.push('');

		for (let i = 0; i < Math.min(10, report.priorityQueue.length); i++) {
			const item = report.priorityQueue[i];
			if (!item) continue;
			lines.push(`### ${i + 1}. ${item.finding.title}`);
			lines.push('');
			lines.push(`**Severity:** ${item.finding.severity}`);
			lines.push(`**Reason:** ${item.reason}`);
			lines.push(`**Impact:** ${item.impact}`);
			lines.push(`**Effort:** ${item.effort}`);
			lines.push('');
		}
	}

	return lines.join('\n');
}

/**
 * Get category name
 */
function getCategoryName(category: string): string {
	const info = OWASP_CATEGORIES[category as OWASPCategory];
	return info ? `${info.code} - ${info.name}` : category;
}

/**
 * Get finding location
 */
function getLocation(finding: Finding): string {
	if (finding.evidence.file) {
		return `${finding.evidence.file}${finding.evidence.line ? `:${finding.evidence.line}` : ''}`;
	}
	return 'Unknown location';
}
