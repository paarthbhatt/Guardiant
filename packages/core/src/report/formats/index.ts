import type { Report, ReportAudience } from '@guardiant/shared';

/**
 * Format report as JSON
 */
export function formatAsJson(report: Report): string {
	return JSON.stringify(report, null, 2);
}

/**
 * Format report as Markdown
 */
export function formatAsMarkdown(report: Report, audience: ReportAudience): string {
	const lines: string[] = [];

	lines.push(`# Security Scan Report`);
	lines.push('');
	lines.push(`| Property | Value |`);
	lines.push(`|----------|-------|`);
	lines.push(`| Scan ID | ${report.scanId} |`);
	lines.push(`| Target | ${report.target} |`);
	lines.push(`| Timestamp | ${new Date(report.timestamp).toLocaleString()} |`);
	lines.push(`| Duration | ${formatDuration(report.duration)} |`);
	lines.push(`| Total Findings | ${report.findings.length} |`);
	lines.push('');

	// Statistics
	const stats = {
		critical: report.findings.filter(f => f.severity === 'critical').length,
		high: report.findings.filter(f => f.severity === 'high').length,
		medium: report.findings.filter(f => f.severity === 'medium').length,
		low: report.findings.filter(f => f.severity === 'low').length,
		info: report.findings.filter(f => f.severity === 'info').length,
	};

	lines.push('## Summary');
	lines.push('');
	lines.push(`- **Critical:** ${stats.critical}`);
	lines.push(`- **High:** ${stats.high}`);
	lines.push(`- **Medium:** ${stats.medium}`);
	lines.push(`- **Low:** ${stats.low}`);
	lines.push(`- **Info:** ${stats.info}`);
	lines.push('');

	// Agent Results
	lines.push('## Agent Results');
	lines.push('');
	lines.push(`| Agent | Status | Findings | Duration |`);
	lines.push(`|-------|--------|----------|----------|`);
	for (const [agentId, result] of Object.entries(report.agentResults)) {
		lines.push(`| ${agentId} | ${result.status} | ${result.findings.length} | ${formatDuration(result.duration)} |`);
	}
	lines.push('');

	// Chains
	if (report.chains.length > 0) {
		lines.push('## Compound Vulnerability Chains');
		lines.push('');
		for (const chain of report.chains) {
			lines.push(`### ${chain.id}`);
			lines.push(`**Severity:** ${chain.compoundSeverity.toUpperCase()}`);
			lines.push(`**CVSS:** ${chain.compoundCvssScore.toFixed(1)}`);
			lines.push('');
			lines.push('**Findings:**');
			for (const f of chain.findings) {
				lines.push(`- ${f.title} [${f.severity}]`);
			}
			lines.push('');
		}
	}

	// Trust Inversions
	if (report.trustInversions.length > 0) {
		lines.push('## Trust Inversions');
		lines.push('');
		for (const inv of report.trustInversions) {
			lines.push(`### ${inv.type}`);
			lines.push(`**Severity:** ${inv.severity.toUpperCase()}`);
			lines.push(`**Misplaced Trust:** ${inv.misplacedTrust}`);
			lines.push(`**Expected:** ${inv.expectedBoundary}`);
			lines.push(`**Actual:** ${inv.actualBoundary}`);
			lines.push('');
		}
	}

	// VCVF Patterns
	if (report.vcvfFingerprints.length > 0) {
		lines.push('## VCVF Patterns Detected');
		lines.push('');
		for (const fp of report.vcvfFingerprints) {
			lines.push(`### ${fp.patternType}`);
			lines.push(`**Confidence:** ${(fp.confidence * 100).toFixed(0)}%`);
			lines.push('');
		}
	}

	// Findings (by audience)
	if (audience === 'security') {
		// Full details for security
		lines.push('## Detailed Findings');
		for (const finding of report.findings) {
			lines.push('');
			lines.push(`### ${finding.title}`);
			lines.push(`**Severity:** ${finding.severity.toUpperCase()} | **CVSS:** ${finding.cvssScore} | **Confidence:** ${(finding.confidence * 100).toFixed(0)}%`);
			lines.push('');
			lines.push(finding.description);
			lines.push('');
			if (finding.evidence.payload) {
				lines.push('**Payload:**');
				lines.push('```');
				lines.push(finding.evidence.payload);
				lines.push('```');
				lines.push('');
			}
			lines.push('**Remediation:**');
			lines.push(finding.remediation.summary);
		}
	} else if (audience === 'developer') {
		// Developer-friendly format
		lines.push('## Findings');
		for (const finding of report.findings) {
			lines.push('');
			lines.push(`### ${finding.title} [${finding.severity.toUpperCase()}]`);
			lines.push('');
			lines.push(finding.description);
			lines.push('');
			lines.push('**Remediation:**');
			for (const step of finding.remediation.steps) {
				lines.push(`1. ${step}`);
			}
		}
	} else {
		// Executive summary only
		const critical = report.findings.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 5);
		if (critical.length > 0) {
			lines.push('## Top Findings');
			for (const finding of critical) {
				lines.push(`- **${finding.title}** [${finding.severity.toUpperCase()}]: ${finding.description.slice(0, 100)}...`);
			}
		}
	}

	return lines.join('\n');
}

/**
 * Format report as HTML
 */
export function formatAsHtml(report: Report, audience: ReportAudience): string {
	const stats = {
		critical: report.findings.filter(f => f.severity === 'critical').length,
		high: report.findings.filter(f => f.severity === 'high').length,
		medium: report.findings.filter(f => f.severity === 'medium').length,
		low: report.findings.filter(f => f.severity === 'low').length,
		info: report.findings.filter(f => f.severity === 'info').length,
	};

	const severityColor = (sev: string): string => {
		switch (sev) {
			case 'critical': return '#dc2626';
			case 'high': return '#ea580c';
			case 'medium': return '#d97706';
			case 'low': return '#059669';
			default: return '#6b7280';
		}
	};

	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Security Scan Report - ${report.target}</title>
	<style>
		* { box-sizing: border-box; margin: 0; padding: 0; }
		body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1f2937; background: #f9fafb; }
		.container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
		h1 { font-size: 2rem; margin-bottom: 0.5rem; }
		h2 { font-size: 1.5rem; margin: 2rem 0 1rem; color: #111827; }
		h3 { font-size: 1.25rem; margin: 1.5rem 0 0.75rem; }
		.header { background: linear-gradient(135deg, #1f2937 0%, #374151 100%); color: white; padding: 2rem; border-radius: 0.5rem; margin-bottom: 2rem; }
		.header h1 { color: white; }
		.meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-top: 1rem; }
		.meta-item { background: rgba(255,255,255,0.1); padding: 0.75rem; border-radius: 0.25rem; }
		.meta-label { font-size: 0.75rem; text-transform: uppercase; color: #9ca3af; }
		.meta-value { font-size: 1.125rem; font-weight: 600; }
		.card { background: white; border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
		.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: 1rem; }
		.stat { text-align: center; padding: 1rem; border-radius: 0.5rem; }
		.stat-value { font-size: 2rem; font-weight: 700; }
		.stat-label { font-size: 0.75rem; text-transform: uppercase; }
		.critical { background: #fef2f2; }
		.critical .stat-value { color: #dc2626; }
		.high { background: #fff7ed; }
		.high .stat-value { color: #ea580c; }
		.medium { background: #fffbeb; }
		.medium .stat-value { color: #d97706; }
		.low { background: #ecfdf5; }
		.low .stat-value { color: #059669; }
		.severity { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 600; color: white; }
		.severity.critical { background: #dc2626; }
		.severity.high { background: #ea580c; }
		.severity.medium { background: #d97706; }
		.severity.low { background: #059669; }
		.severity.info { background: #6b7280; }
		.finding { border-left: 4px solid; margin-bottom: 1rem; padding-left: 1rem; }
		.finding.critical { border-color: #dc2626; }
		.finding.high { border-color: #ea580c; }
		.finding.medium { border-color: #d97706; }
		.finding.low { border-color: #059669; }
		.finding.info { border-color: #6b7280; }
		.finding-header { display: flex; justify-content: space-between; align-items: start; margin-bottom: 0.5rem; }
		.finding-title { font-weight: 600; }
		.finding-meta { font-size: 0.875rem; color: #6b7280; }
		code { background: #f3f4f6; padding: 0.125rem 0.25rem; border-radius: 0.25rem; font-size: 0.875rem; }
		pre { background: #1f2937; color: #f9fafb; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; margin: 1rem 0; }
		pre code { background: none; padding: 0; color: inherit; }
		ul { margin-left: 1.5rem; }
		.badge { display: inline-block; padding: 0.125rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; background: #e5e7eb; margin-right: 0.5rem; }
		.section { margin-top: 2rem; }
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>Security Scan Report</h1>
			<p>Target: <strong>${report.target}</strong></p>
			<div class="meta">
				<div class="meta-item">
					<div class="meta-label">Scan ID</div>
					<div class="meta-value">${report.scanId}</div>
				</div>
				<div class="meta-item">
					<div class="meta-label">Timestamp</div>
					<div class="meta-value">${new Date(report.timestamp).toLocaleString()}</div>
				</div>
				<div class="meta-item">
					<div class="meta-label">Duration</div>
					<div class="meta-value">${formatDuration(report.duration)}</div>
				</div>
				<div class="meta-item">
					<div class="meta-label">Total Findings</div>
					<div class="meta-value">${report.findings.length}</div>
				</div>
			</div>
		</div>

		<div class="card">
			<h2>Vulnerability Summary</h2>
			<div class="stats">
				<div class="stat critical">
					<div class="stat-value">${stats.critical}</div>
					<div class="stat-label">Critical</div>
				</div>
				<div class="stat high">
					<div class="stat-value">${stats.high}</div>
					<div class="stat-label">High</div>
				</div>
				<div class="stat medium">
					<div class="stat-value">${stats.medium}</div>
					<div class="stat-label">Medium</div>
				</div>
				<div class="stat low">
					<div class="stat-value">${stats.low}</div>
					<div class="stat-label">Low</div>
				</div>
				<div class="stat">
					<div class="stat-value" style="color: #6b7280">${stats.info}</div>
					<div class="stat-label">Info</div>
				</div>
			</div>
		</div>

		${report.chains.length > 0 ? `
		<div class="card section">
			<h2>Compound Vulnerability Chains</h2>
			${report.chains.map(chain => `
				<div style="margin-bottom: 1rem; padding: 1rem; background: #fef2f2; border-radius: 0.5rem;">
					<h3>${chain.id}</h3>
					<p><strong>Compound Severity:</strong> <span class="severity ${chain.compoundSeverity}">${chain.compoundSeverity.toUpperCase()}</span></p>
					<p><strong>CVSS:</strong> ${chain.compoundCvssScore.toFixed(1)}</p>
					<ul>
						${chain.findings.map(f => `<li>${f.title}</li>`).join('')}
					</ul>
				</div>
			`).join('')}
		</div>
		` : ''}

		${report.trustInversions.length > 0 ? `
		<div class="card section">
			<h2>Trust Inversions Detected</h2>
			${report.trustInversions.map(inv => `
				<div style="margin-bottom: 1rem; padding: 1rem; background: #fff7ed; border-radius: 0.5rem;">
					<h3>${inv.type}</h3>
					<p><span class="severity ${inv.severity}">${inv.severity.toUpperCase()}</span></p>
					<p><strong>Misplaced Trust:</strong> ${inv.misplacedTrust}</p>
					<p><strong>Expected Boundary:</strong> ${inv.expectedBoundary}</p>
					<p><strong>Actual Boundary:</strong> ${inv.actualBoundary}</p>
				</div>
			`).join('')}
		</div>
		` : ''}

		${report.findings.length > 0 ? `
		<div class="card section">
			<h2>Findings</h2>
			${report.findings.map(finding => `
				<div class="finding ${finding.severity}">
					<div class="finding-header">
						<div class="finding-title">${finding.title}</div>
						<div><span class="severity ${finding.severity}">${finding.severity.toUpperCase()}</span></div>
					</div>
					<div class="finding-meta">
						CVSS: ${finding.cvssScore} | Confidence: ${(finding.confidence * 100).toFixed(0)}% | ${finding.category}
					</div>
					<p style="margin-top: 0.5rem;">${finding.description}</p>
					${finding.evidence.payload ? `
						<pre><code>${escapeHtml(finding.evidence.payload)}</code></pre>
					` : ''}
					<div style="margin-top: 0.5rem;">
						<strong>Remediation:</strong> ${finding.remediation.summary}
					</div>
				</div>
			`).join('')}
		</div>
		` : ''}
	</div>
</body>
</html>`;
}

/**
 * Format duration
 */
function formatDuration(ms: number): string {
	const seconds = Math.floor(ms / 1000);
	if (seconds < 60) return `${seconds}s`;
	const minutes = Math.floor(seconds / 60);
	if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
	const hours = Math.floor(minutes / 60);
	return `${hours}h ${minutes % 60}m`;
}

/**
 * Escape HTML
 */
function escapeHtml(text: string): string {
	return text
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#039;');
}
