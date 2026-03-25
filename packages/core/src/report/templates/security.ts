import type { SecurityReport, Finding, VulnerabilityChain, VCVFFingerprint, TrustInversion } from '@guardiant/shared';
import { SEVERITY_LEVELS, OWASP_CATEGORIES, type OWASPCategory } from '@guardiant/shared';

/**
 * Generate security report content
 */
export function generateSecurityReport(report: SecurityReport): string {
	const lines: string[] = [];

	lines.push(`# Security Report`);
	lines.push('');
	lines.push(`**Generated:** ${new Date().toLocaleString()}`);
	lines.push('');
	lines.push('---');
	lines.push('');

	// Executive Summary
	lines.push('## Vulnerability Summary');
	lines.push('');
	lines.push(`| Severity | Count |`);
	lines.push(`|----------|-------|`);
	const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
	for (const f of report.findings) counts[f.severity]++;
	for (const sev of ['critical', 'high', 'medium', 'low', 'info'] as const) {
		if (counts[sev] > 0) lines.push(`| ${sev.toUpperCase()} | ${counts[sev]} |`);
	}
	lines.push('');

	// Compound Vulnerability Chains
	if (report.chains.length > 0) {
		lines.push('## Compound Vulnerability Chains (CVC)');
		lines.push('');
		lines.push('These vulnerabilities are chained together, creating compound exploit paths.');
		lines.push('');

		for (const chain of report.chains) {
			lines.push(`### Chain: ${chain.id}`);
			lines.push('');
			lines.push(`**Compound Severity:** ${chain.compoundSeverity.toUpperCase()}`);
			lines.push(`**Compound CVSS:** ${chain.compoundCvssScore.toFixed(1)}/10`);
			lines.push('');
			lines.push('**Attack Path:**');
			lines.push(chain.exploitPath);
			lines.push('');
			lines.push('**Attack Steps:**');
			for (const step of chain.attackSteps) {
				lines.push(`${step.order}. [${step.findingId}] ${step.action}`);
				lines.push(`   └── ${step.result}`);
			}
			lines.push('');
		}
	}

	// VCVF Fingerprints
	if (report.vcvfFingerprints.length > 0) {
		lines.push('## VCVF Pattern Detection');
		lines.push('');
		lines.push('Vibe Code Vulnerability Fingerprints indicate patterns common in AI-generated code.');
		lines.push('');

		for (const fp of report.vcvfFingerprints) {
			lines.push(`### ${formatPatternType(fp.patternType)}`);
			lines.push('');
			lines.push(`**Confidence:** ${(fp.confidence * 100).toFixed(0)}%`);
			lines.push('');
			lines.push('**Evidence:**');
			for (const e of fp.evidence) {
				lines.push(`- ${e}`);
			}
			lines.push('');
			lines.push('**Locations:**');
			for (const loc of fp.locations) {
				lines.push(`- ${loc.file}${loc.line ? `:${loc.line}` : ''}`);
				if (loc.snippet) lines.push(`  \`\`\`\n  ${loc.snippet}\n  \`\`\``);
			}
			lines.push('');
			lines.push('**Predicted Vulnerabilities:**');
			for (const pred of fp.predictedVulnerabilities) {
				lines.push(`- ${pred.type} (${(pred.probability * 100).toFixed(0)}% probability)`);
				lines.push(`  - ${pred.reason}`);
			}
			lines.push('');
		}
	}

	// Trust Inversions
	if (report.trustInversions.length > 0) {
		lines.push('## Trust Inversions Detected (TIEF)');
		lines.push('');
		lines.push('Trust boundaries are incorrectly placed, allowing client-side exploitation.');
		lines.push('');

		for (const inversion of report.trustInversions) {
			lines.push(`### ${formatInversionType(inversion.type)}`);
			lines.push('');
			lines.push(`**Severity:** ${inversion.severity.toUpperCase()}`);
			lines.push(`**Misplaced Trust:** ${inversion.misplacedTrust}`);
			lines.push(`**Expected Boundary:** ${inversion.expectedBoundary}`);
			lines.push(`**Actual Boundary:** ${inversion.actualBoundary}`);
			lines.push('');
			lines.push('**Affected Findings:**');
			for (const fid of inversion.findingIds) {
				lines.push(`- ${fid}`);
			}
			lines.push('');
		}
	}

	// Attack Surface
	if (report.attackSurface.entryPoints.length > 0) {
		lines.push('## Attack Surface Map');
		lines.push('');

		lines.push('### Entry Points');
		lines.push('');
		lines.push(`| Entry Point | Type | Risk | Findings |`);
		lines.push(`|-------------|------|------|----------|`);
		for (const ep of report.attackSurface.entryPoints) {
			lines.push(`| ${ep.location} | ${ep.type} | ${ep.risk.toUpperCase()} | ${ep.associatedFindings.length} |`);
		}
		lines.push('');
	}

	if (report.attackSurface.trustBoundaries.length > 0) {
		lines.push('### Trust Boundaries');
		lines.push('');
		for (const tb of report.attackSurface.trustBoundaries) {
			lines.push(`**${tb.name}**`);
			lines.push(tb.description);
			lines.push('');
		}
	}

	if (report.attackSurface.riskAreas.length > 0) {
		lines.push('### Risk Areas');
		lines.push('');
		lines.push(`| Risk Area | Severity | Findings |`);
		lines.push(`|-----------|----------|----------|`);
		for (const ra of report.attackSurface.riskAreas) {
			lines.push(`| ${ra.name} | ${ra.severity.toUpperCase()} | ${ra.findings.length} |`);
		}
		lines.push('');
	}

	// Proof of Concepts
	if (report.proofOfConcepts.length > 0) {
		lines.push('## Proof of Concepts');
		lines.push('');

		for (const poc of report.proofOfConcepts) {
			lines.push(`### ${poc.title}`);
			lines.push('');
			lines.push(poc.description);
			lines.push('');
			lines.push('**Steps:**');
			for (const step of poc.steps) {
				lines.push(`${step.order}. ${step.action}`);
				if (step.code) {
					lines.push('   ```');
					lines.push(step.code);
					lines.push('   ```');
				}
				lines.push(`   **Expected:** ${step.expectedResult}`);
				lines.push('');
			}
			lines.push(`**Impact:** ${poc.impact}`);
			lines.push('');
		}
	}

	// Remediation Code
	if (report.remediationCode.length > 0) {
		lines.push('## Remediation Examples');
		lines.push('');

		for (const rem of report.remediationCode) {
			lines.push(`### ${rem.title}`);
			lines.push('');
			lines.push(rem.explanation);
			lines.push('');
			lines.push('**Before (Vulnerable):**');
			lines.push('```' + rem.language);
			lines.push(rem.beforeCode);
			lines.push('```');
			lines.push('');
			lines.push('**After (Fixed):**');
			lines.push('```' + rem.language);
			lines.push(rem.afterCode);
			lines.push('```');
			lines.push('');
		}
	}

	// All Findings
	lines.push('## Complete Vulnerability List');
	lines.push('');

	for (const finding of report.findings) {
		const categoryInfo = OWASP_CATEGORIES[finding.category as OWASPCategory];
		lines.push(`### ${finding.id}: ${finding.title}`);
		lines.push('');
		lines.push(`| Property | Value |`);
		lines.push(`|----------|-------|`);
		lines.push(`| Severity | ${finding.severity.toUpperCase()} |`);
		lines.push(`| CVSS | ${finding.cvssScore}/10 |`);
		lines.push(`| Confidence | ${(finding.confidence * 100).toFixed(0)}% |`);
		lines.push(`| Category | ${categoryInfo?.name ?? finding.category} |`);
		lines.push(`| Discovered By | ${finding.discoveredBy} |`);
		if (finding.cvcChainId) lines.push(`| CVC Chain | ${finding.cvcChainId} |`);
		if (finding.vcvfPattern) lines.push(`| VCVF Pattern | ${finding.vcvfPattern} |`);
		lines.push('');
		lines.push('**Description:**');
		lines.push(finding.description);
		lines.push('');

		if (finding.evidence.request) {
			lines.push('**Request:**');
			lines.push('```');
			lines.push(finding.evidence.request);
			lines.push('```');
			lines.push('');
		}

		if (finding.evidence.payload) {
			lines.push('**Payload:**');
			lines.push('```');
			lines.push(finding.evidence.payload);
			lines.push('```');
			lines.push('');
		}

		lines.push('**Remediation:**');
		lines.push(finding.remediation.summary);
		lines.push('');
		for (const step of finding.remediation.steps) {
			lines.push(`1. ${step}`);
		}
		lines.push('');
		lines.push('---');
		lines.push('');
	}

	return lines.join('\n');
}

/**
 * Format pattern type
 */
function formatPatternType(pattern: string): string {
	return pattern
		.split('_')
		.map(word => word.charAt(0).toUpperCase() + word.slice(1))
		.join(' ');
}

/**
 * Format inversion type
 */
function formatInversionType(type: string): string {
	return type
		.split('_')
		.map(word => word.charAt(0).toUpperCase() + word.slice(1))
		.join(' ');
}
