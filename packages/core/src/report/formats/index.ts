import type { Report, ReportAudience } from '@guardiant/shared';

/**
 * Format report as JSON
 */
export function formatAsJson(report: Report): string {
	return JSON.stringify(report, null, 2);
}

export * from './sarif.js';

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
			if (inv.findingIds && inv.findingIds.length > 0) {
				lines.push('**Underlying Findings:**');
				for (const fid of inv.findingIds) {
					const finding = report.findings.find(f => f.id === fid);
					if (finding) {
						const location = finding.evidence.file
							? ` (in \`${finding.evidence.file}:${finding.evidence.line ?? '?'}\`)`
							: '';
						lines.push(`- **[${finding.severity.toUpperCase()}]** ${finding.title}${location}`);
					}
				}
			}
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
 * Format report as HTML (Premium Dark Mode Interactive)
 */
export function formatAsHtml(report: Report, _audience: ReportAudience): string {
	const stats = {
		critical: report.findings.filter(f => f.severity === 'critical').length,
		high: report.findings.filter(f => f.severity === 'high').length,
		medium: report.findings.filter(f => f.severity === 'medium').length,
		low: report.findings.filter(f => f.severity === 'low').length,
		info: report.findings.filter(f => f.severity === 'info').length,
	};
    
    const total = report.findings.length;
    // Donut chart stroke-dasharray calculations (circumference = 100)
    let offset = 0;
    const criticalPct = total ? (stats.critical / total) * 100 : 0;
    const highPct = total ? (stats.high / total) * 100 : 0;
    const mediumPct = total ? (stats.medium / total) * 100 : 0;
    const lowPct = total ? (stats.low / total) * 100 : 0;

	return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Guardiant Security Report - ${report.target}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
	<style>
		:root {
            --bg-base: #0f172a;
            --bg-surface: #1e293b;
            --bg-card: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #3b82f6;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --info: #64748b;
        }
		* { box-sizing: border-box; margin: 0; padding: 0; }
		body { font-family: 'Inter', sans-serif; line-height: 1.6; color: var(--text-main); background: var(--bg-base); }
		.container { max-width: 1400px; margin: 0 auto; padding: 2rem; display: grid; grid-template-columns: 250px 1fr; gap: 2rem; }
		@media (max-width: 768px) { .container { grid-template-columns: 1fr; } }
        
        /* Sidebar Navigation */
        nav { position: sticky; top: 2rem; align-self: start; background: var(--bg-surface); padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.05); }
        nav h3 { font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 1rem; }
        nav ul { list-style: none; }
        nav li { margin-bottom: 0.5rem; }
        nav a { color: var(--text-main); text-decoration: none; display: block; padding: 0.5rem; border-radius: 6px; transition: background 0.2s; font-size: 0.95rem; }
        nav a:hover { background: var(--bg-card); }
        
        /* Main Content */
        .content { min-width: 0; }
        
		h1 { font-size: 2.5rem; font-weight: 700; margin-bottom: 0.5rem; letter-spacing: -0.02em; }
		h2 { font-size: 1.75rem; margin: 3rem 0 1.5rem; color: var(--text-main); font-weight: 600; border-bottom: 1px solid var(--bg-card); padding-bottom: 0.5rem; }
		
		.header-card { background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); padding: 2.5rem; border-radius: 16px; border: 1px solid rgba(255,255,255,0.1); margin-bottom: 2rem; position: relative; overflow: hidden; }
        .header-card::before { content: ''; position: absolute; top: -50%; left: -50%; width: 200%; height: 200%; background: radial-gradient(circle, rgba(59,130,246,0.1) 0%, transparent 50%); pointer-events: none; }
        
		.meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-top: 2rem; }
		.meta-item { background: rgba(0,0,0,0.2); padding: 1rem; border-radius: 8px; border: 1px solid rgba(255,255,255,0.05); }
		.meta-label { font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; letter-spacing: 0.05em; margin-bottom: 0.25rem; }
		.meta-value { font-size: 1.25rem; font-weight: 600; font-family: monospace; }
        
        /* Dashboard Layout */
        .dashboard-grid { display: grid; grid-template-columns: 300px 1fr; gap: 2rem; margin-bottom: 3rem; }
        @media (max-width: 1024px) { .dashboard-grid { grid-template-columns: 1fr; } }
        
        /* Donut Chart */
        .chart-card { background: var(--bg-surface); padding: 2rem; border-radius: 16px; border: 1px solid rgba(255,255,255,0.05); display: flex; flex-direction: column; align-items: center; justify-content: center; }
        svg.donut { width: 100%; max-width: 200px; height: 100%; transform: rotate(-90deg); border-radius: 50%; }
        .donut-segment { fill: transparent; stroke-width: 15; }
        .chart-legend { display: flex; flex-wrap: wrap; gap: 1rem; justify-content: center; margin-top: 1.5rem; }
        .legend-item { display: flex; align-items: center; font-size: 0.875rem; color: var(--text-muted); }
        .legend-color { width: 12px; height: 12px; border-radius: 50%; margin-right: 6px; }
        
		.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 1rem; align-content: start; }
		.stat { padding: 1.5rem; border-radius: 12px; background: var(--bg-surface); border: 1px solid rgba(255,255,255,0.05); text-align: center; transition: transform 0.2s; }
        .stat:hover { transform: translateY(-2px); }
		.stat-value { font-size: 2.5rem; font-weight: 700; margin-bottom: 0.5rem; line-height: 1; }
		.stat-label { font-size: 0.875rem; text-transform: uppercase; font-weight: 600; letter-spacing: 0.05em; }
        
        /* Severities */
		.critical { border-top: 3px solid var(--critical) !important; }
		.critical .stat-value { color: var(--critical); }
		.high { border-top: 3px solid var(--high) !important; }
		.high .stat-value { color: var(--high); }
		.medium { border-top: 3px solid var(--medium) !important; }
		.medium .stat-value { color: var(--medium); }
		.low { border-top: 3px solid var(--low) !important; }
		.low .stat-value { color: var(--low); }
        
		.severity-badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }
		.badge-critical { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }
		.badge-high { background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.3); }
		.badge-medium { background: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid rgba(234, 179, 8, 0.3); }
		.badge-low { background: rgba(34, 197, 94, 0.2); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.3); }
		.badge-info { background: rgba(100, 116, 139, 0.2); color: #cbd5e1; border: 1px solid rgba(100, 116, 139, 0.3); }

        /* Finding Cards */
		.finding { background: var(--bg-surface); border-radius: 12px; margin-bottom: 1.5rem; overflow: hidden; border: 1px solid rgba(255,255,255,0.05); transition: all 0.2s; }
        .finding:hover { border-color: rgba(255,255,255,0.1); box-shadow: 0 4px 20px rgba(0,0,0,0.2); }
        .finding-summary { padding: 1.5rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
		.finding-title { font-weight: 600; font-size: 1.125rem; display: flex; align-items: center; gap: 1rem; }
		.finding-meta { font-size: 0.875rem; color: var(--text-muted); display: flex; gap: 1rem; margin-top: 0.5rem; }
        
        .finding-details { padding: 0 1.5rem 1.5rem; display: none; border-top: 1px solid var(--bg-card); margin-top: 1rem; padding-top: 1.5rem; }
        .finding.expanded .finding-details { display: block; animation: slideDown 0.3s ease-out; }
        @keyframes slideDown { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }

        /* Code Blocks */
		pre { background: #0f172a; color: #e2e8f0; padding: 1.25rem; border-radius: 8px; overflow-x: auto; margin: 1rem 0; border: 1px solid rgba(255,255,255,0.05); font-family: 'JetBrains Mono', monospace; font-size: 0.875rem; line-height: 1.5; }
		code { font-family: 'JetBrains Mono', monospace; }
        :not(pre) > code { background: rgba(255,255,255,0.1); padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.875rem; }
        
        .remediation { background: rgba(59, 130, 246, 0.1); border-left: 4px solid var(--accent); padding: 1.5rem; border-radius: 0 8px 8px 0; margin-top: 1.5rem; }
        .remediation h4 { color: #93c5fd; margin-bottom: 0.5rem; }
        .remediation ul { margin-left: 1.5rem; margin-top: 0.5rem; }

        /* Controls */
        .controls { display: flex; gap: 1rem; margin-bottom: 1.5rem; }
        select, input { background: var(--bg-card); color: white; border: 1px solid rgba(255,255,255,0.1); padding: 0.5rem 1rem; border-radius: 6px; font-family: inherit; }
        select:focus, input:focus { outline: none; border-color: var(--accent); }

	</style>
    <script>
        function toggleFinding(element) {
            element.closest('.finding').classList.toggle('expanded');
        }
        function filterFindings() {
            const severity = document.getElementById('severity-filter').value;
            const search = document.getElementById('search-input').value.toLowerCase();
            const findings = document.querySelectorAll('.finding');
            
            findings.forEach(f => {
                const isSeverity = severity === 'all' || f.dataset.severity === severity;
                const isSearch = f.textContent.toLowerCase().includes(search);
                f.style.display = isSeverity && isSearch ? 'block' : 'none';
            });
        }
    </script>
</head>
<body>
	<div class="container">
        <nav>
            <h3>Navigation</h3>
            <ul>
                <li><a href="#summary">Summary Dashboard</a></li>
                ${report.chains.length > 0 ? '<li><a href="#chains">Exploit Chains</a></li>' : ''}
                ${report.trustInversions.length > 0 ? '<li><a href="#trust">Trust Inversions</a></li>' : ''}
                <li><a href="#findings">Detailed Findings</a></li>
            </ul>
        </nav>

        <div class="content">
            <div class="header-card">
                <h1>Guardiant Security Report</h1>
                <p style="color: var(--text-muted); font-size: 1.125rem;">Target: <strong>${report.target}</strong></p>
                <div class="meta">
                    <div class="meta-item">
                        <div class="meta-label">Scan ID</div>
                        <div class="meta-value">${report.scanId.split('-').slice(0, 2).join('-')}</div>
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

            <h2 id="summary">Vulnerability Summary</h2>
            <div class="dashboard-grid">
                <div class="chart-card">
                    <svg class="donut" viewBox="0 0 42 42">
                        <circle cx="21" cy="21" r="15.91549430918954" fill="transparent" stroke="rgba(255,255,255,0.05)" stroke-width="6"></circle>
                        ${criticalPct > 0 ? `<circle class="donut-segment" cx="21" cy="21" r="15.91549430918954" stroke="var(--critical)" stroke-dasharray="${criticalPct} ${100 - criticalPct}" stroke-dashoffset="${100 - offset}"></circle>` : ''}
                        ${(offset += criticalPct) !== undefined ? '' : ''}
                        ${highPct > 0 ? `<circle class="donut-segment" cx="21" cy="21" r="15.91549430918954" stroke="var(--high)" stroke-dasharray="${highPct} ${100 - highPct}" stroke-dashoffset="${100 - offset}"></circle>` : ''}
                        ${(offset += highPct) !== undefined ? '' : ''}
                        ${mediumPct > 0 ? `<circle class="donut-segment" cx="21" cy="21" r="15.91549430918954" stroke="var(--medium)" stroke-dasharray="${mediumPct} ${100 - mediumPct}" stroke-dashoffset="${100 - offset}"></circle>` : ''}
                        ${(offset += mediumPct) !== undefined ? '' : ''}
                        ${lowPct > 0 ? `<circle class="donut-segment" cx="21" cy="21" r="15.91549430918954" stroke="var(--low)" stroke-dasharray="${lowPct} ${100 - lowPct}" stroke-dashoffset="${100 - offset}"></circle>` : ''}
                    </svg>
                    <div class="chart-legend">
                        <div class="legend-item"><div class="legend-color" style="background: var(--critical)"></div> Critical</div>
                        <div class="legend-item"><div class="legend-color" style="background: var(--high)"></div> High</div>
                        <div class="legend-item"><div class="legend-color" style="background: var(--medium)"></div> Medium</div>
                        <div class="legend-item"><div class="legend-color" style="background: var(--low)"></div> Low</div>
                    </div>
                </div>

                <div class="stats-grid">
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
                        <div class="stat-value" style="color: var(--info)">${stats.info}</div>
                        <div class="stat-label">Info</div>
                    </div>
                </div>
            </div>

            ${report.chains.length > 0 ? `
            <h2 id="chains">Exploit Chains</h2>
            ${report.chains.map(chain => `
                <div class="finding ${chain.compoundSeverity}">
                    <div class="finding-summary" style="cursor: default;">
                        <div>
                            <div class="finding-title">
                                <span class="severity-badge badge-${chain.compoundSeverity}">${chain.compoundSeverity}</span>
                                ${chain.id}
                            </div>
                            <div class="finding-meta">CVSS: ${chain.compoundCvssScore.toFixed(1)}</div>
                        </div>
                    </div>
                    <div style="padding: 0 1.5rem 1.5rem;">
                        <ul style="margin-left: 1.5rem; color: var(--text-muted);">
                            ${chain.findings.map(f => `<li><strong>${f.title}</strong> (${f.severity})</li>`).join('')}
                        </ul>
                    </div>
                </div>
            `).join('')}
            ` : ''}

            <h2 id="findings">Detailed Findings</h2>
            
            <div class="controls">
                <select id="severity-filter" onchange="filterFindings()">
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                </select>
                <input type="text" id="search-input" placeholder="Search findings..." onkeyup="filterFindings()" style="flex: 1;">
            </div>

            <div id="findings-list">
                ${report.findings.map(finding => `
                    <div class="finding ${finding.severity}" data-severity="${finding.severity}">
                        <div class="finding-summary" onclick="toggleFinding(this)">
                            <div>
                                <div class="finding-title">
                                    <span class="severity-badge badge-${finding.severity}">${finding.severity}</span>
                                    ${finding.title}
                                </div>
                                <div class="finding-meta">
                                    <span><strong>Category:</strong> ${finding.category}</span>
                                    <span><strong>CVSS:</strong> ${finding.cvssScore}</span>
                                    <span><strong>Confidence:</strong> ${(finding.confidence * 100).toFixed(0)}%</span>
                                </div>
                            </div>
                            <div style="color: var(--text-muted);">&#9660;</div>
                        </div>
                        <div class="finding-details">
                            <p style="margin-bottom: 1.5rem; font-size: 1.05rem;">${finding.description}</p>
                            
                            ${finding.evidence.payload ? `
                                <h4>Exploit Payload</h4>
                                <pre><code>${escapeHtml(finding.evidence.payload)}</code></pre>
                            ` : ''}
                            
                            ${finding.evidence.file ? `
                                <p style="color: var(--text-muted); font-size: 0.875rem;">
                                    Found in: <code>${finding.evidence.file}</code>${finding.evidence.line ? `:${finding.evidence.line}` : ''}
                                </p>
                            ` : ''}
                            
                            <div class="remediation">
                                <h4>Remediation</h4>
                                <p>${finding.remediation.summary}</p>
                                <ul>
                                    ${finding.remediation.steps.map(s => `<li>${s}</li>`).join('')}
                                </ul>
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
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
