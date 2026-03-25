import type {
	Report,
	ExecutiveSummary,
	DeveloperReport,
	SecurityReport,
	ReportOptions,
	Finding,
	VulnerabilityChain,
	VCVFFingerprint,
	TrustInversion,
	RiskAssessment,
	AttackSurfaceMap,
	ProofOfConcept,
	AffectedFile,
	PriorityItem,
	AgentResult,
	AgentId,
} from '@guardiant/shared';
import { OWASP_CATEGORIES, SEVERITY_LEVELS, type Severity, type OWASPCategory } from '@guardiant/shared';
import { generateExecutiveReport } from './templates/executive.js';
import { generateDeveloperReport } from './templates/developer.js';
import { generateSecurityReport } from './templates/security.js';
import { formatAsJson, formatAsMarkdown, formatAsHtml } from './formats/index.js';

export class ReportGenerator {
	private options: ReportOptions;

	constructor(options: ReportOptions) {
		this.options = options;
	}

	/**
	 * Generate a complete report
	 */
	generate(params: {
		scanId: string;
		target: string;
		duration: number;
		findings: Finding[];
		agentResults: Record<AgentId, AgentResult>;
		chains: VulnerabilityChain[];
		vcvfFingerprints: VCVFFingerprint[];
		trustInversions: TrustInversion[];
		reconData?: {
			endpoints?: string[];
			techStack?: string[];
			dataFlows?: Array<{ source: string; sink: string }>;
		};
	}): Report {
		const { scanId, target, duration, findings, agentResults, chains, vcvfFingerprints, trustInversions, reconData } = params;

		// Generate report sections based on audience
		const executive = this.options.audience !== 'security'
			? this.generateExecutiveSummary(findings, chains, trustInversions, target)
			: undefined;

		const developer = this.options.audience !== 'executive'
			? this.generateDeveloperSummary(findings)
			: undefined;

		const security = this.options.audience === 'security'
			? this.generateSecuritySummary(findings, chains, vcvfFingerprints, trustInversions, reconData)
			: undefined;

		const report: Report = {
			id: `report_${scanId}`,
			scanId,
			target,
			timestamp: new Date().toISOString(),
			duration,
			agentResults,
			executive,
			developer,
			security,
			findings,
			chains,
			vcvfFingerprints,
			trustInversions,
		};

		return report;
	}

	/**
	 * Generate executive summary
	 */
	private generateExecutiveSummary(
		findings: Finding[],
		chains: VulnerabilityChain[],
		trustInversions: TrustInversion[],
		target: string
	): ExecutiveSummary {
		const stats = this.calculateStatistics(findings, chains);

		return {
			headline: this.generateHeadline(stats, target),
			summary: this.generateSummary(stats, trustInversions),
			risk: this.assessRisk(stats, findings),
			immediateActions: this.generateImmediateActions(findings, chains),
			statistics: stats,
			topVulnerabilities: this.getTopVulnerabilities(findings),
		};
	}

	/**
	 * Generate developer report
	 */
	private generateDeveloperSummary(findings: Finding[]): DeveloperReport {
		return {
			vulnerabilities: findings,
			bySeverity: this.groupBySeverity(findings),
			byCategory: this.groupByCategory(findings),
			affectedFiles: this.getAffectedFiles(findings),
			priorityQueue: this.getPriorityQueue(findings),
		};
	}

	/**
	 * Generate security report
	 */
	private generateSecuritySummary(
		findings: Finding[],
		chains: VulnerabilityChain[],
		vcvfFingerprints: VCVFFingerprint[],
		trustInversions: TrustInversion[],
		reconData?: { endpoints?: string[]; techStack?: string[]; dataFlows?: Array<{ source: string; sink: string }> }
	): SecurityReport {
		return {
			findings,
			chains,
			vcvfFingerprints,
			trustInversions,
			attackSurface: this.generateAttackSurface(findings, reconData),
			proofOfConcepts: this.generateProofOfConcepts(findings),
			remediationCode: this.generateRemediationCode(findings),
		};
	}

	/**
	 * Calculate statistics
	 */
	private calculateStatistics(findings: Finding[], chains: VulnerabilityChain[]): ExecutiveSummary['statistics'] {
		return {
			totalFindings: findings.length,
			criticalCount: findings.filter(f => f.severity === 'critical').length,
			highCount: findings.filter(f => f.severity === 'high').length,
			mediumCount: findings.filter(f => f.severity === 'medium').length,
			lowCount: findings.filter(f => f.severity === 'low').length,
			chainedVulnerabilities: chains.reduce((sum, c) => sum + c.findings.length, 0),
		};
	}

	/**
	 * Generate headline
	 */
	private generateHeadline(stats: ExecutiveSummary['statistics'], target: string): string {
		if (stats.criticalCount > 0) {
			return `Critical security vulnerabilities found in ${target}`;
		}
		if (stats.highCount > 0) {
			return `High severity issues detected in ${target}`;
		}
		if (stats.mediumCount > 0) {
			return `Moderate security concerns in ${target}`;
		}
		return `No critical vulnerabilities found in ${target}`;
	}

	/**
	 * Generate summary
	 */
	private generateSummary(stats: ExecutiveSummary['statistics'], trustInversions: TrustInversion[]): string {
		const parts: string[] = [];

		if (stats.criticalCount > 0) {
			parts.push(`${stats.criticalCount} critical severity issue${stats.criticalCount > 1 ? 's' : ''}`);
		}
		if (stats.highCount > 0) {
			parts.push(`${stats.highCount} high severity issue${stats.highCount > 1 ? 's' : ''}`);
		}
		if (stats.mediumCount > 0) {
			parts.push(`${stats.mediumCount} medium severity issue${stats.mediumCount > 1 ? 's' : ''}`);
		}
		if (stats.chainedVulnerabilities > 0) {
			parts.push(`${stats.chainedVulnerabilities} chained vulnerabilities`);
		}
		if (trustInversions.length > 0) {
			parts.push(`${trustInversions.length} trust boundary misconfiguration${trustInversions.length > 1 ? 's' : ''}`);
		}

		if (parts.length === 0) {
			return `No significant security issues were identified. The application appears to follow security best practices.`;
		}

		return `Analysis identified ${parts.join(', ')}. These issues require attention to secure the application.`;
	}

	/**
	 * Assess risk
	 */
	private assessRisk(stats: ExecutiveSummary['statistics'], findings: Finding[]): RiskAssessment {
		let score = 0;
		let level: RiskAssessment['level'] = 'low';

		score += stats.criticalCount * 3;
		score += stats.highCount * 2;
		score += stats.mediumCount * 1;
		score = Math.min(10, score);

		if (stats.criticalCount > 0 || score >= 8) {
			level = 'critical';
		} else if (stats.highCount > 0 || score >= 5) {
			level = 'high';
		} else if (stats.mediumCount > 0 || score >= 2) {
			level = 'medium';
		}

		const businessImpact = this.generateBusinessImpact(stats);
		const dataExposureRisk = this.calculateDataExposureRisk(findings);

		return {
			score,
			level,
			businessImpact,
			dataExposureRisk,
			complianceImplications: this.generateComplianceImplications(findings),
			remediationTimeline: this.generateRemediationTimeline(level),
		};
	}

	/**
	 * Generate business impact
	 */
	private generateBusinessImpact(stats: ExecutiveSummary['statistics']): string {
		if (stats.criticalCount > 0) {
			return 'Critical risk of data breach, service disruption, or complete system compromise. Immediate action required.';
		}
		if (stats.highCount > 0) {
			return 'Significant risk of unauthorized access, data leakage, or service degradation. Prompt remediation needed.';
		}
		if (stats.mediumCount > 0) {
			return 'Moderate risk that could lead to security incidents under specific conditions. Should be addressed.';
		}
		return 'Minimal direct risk. Consider addressing for defense-in-depth.';
	}

	/**
	 * Calculate data exposure risk
	 */
	private calculateDataExposureRisk(findings: Finding[]): RiskAssessment['dataExposureRisk'] {
		const hasDataExposure = findings.some(f =>
			f.category === 'A02_CRYPTOGRAPHIC_FAILURES' ||
			f.category === 'A01_BROKEN_ACCESS_CONTROL' ||
			f.tags.includes('data-breach') ||
			f.tags.includes('pii') ||
			f.tags.includes('credentials')
		);

		if (!hasDataExposure) return 'none';

		const critical = findings.filter(f => f.severity === 'critical').length;
		const high = findings.filter(f => f.severity === 'high').length;

		if (critical > 0) return 'critical';
		if (high > 0) return 'high';

		return 'medium';
	}

	/**
	 * Generate compliance implications
	 */
	private generateComplianceImplications(findings: Finding[]): string[] {
		const implications: string[] = [];

		if (findings.some(f => f.category === 'A02_CRYPTOGRAPHIC_FAILURES')) {
			implications.push('PCI-DSS: Sensitive data may not be properly protected');
		}
		if (findings.some(f => f.category === 'A07_AUTH_FAILURES')) {
			implications.push('SOC 2: Authentication controls may be inadequate');
		}
		if (findings.some(f => f.category === 'A09_LOGGING_FAILURES')) {
			implications.push('SOC 2: Audit logging may be insufficient');
		}
		if (findings.some(f => f.tags.includes('pii'))) {
			implications.push('GDPR/CCPA: Personal data may be improperly protected');
		}

		return implications;
	}

	/**
	 * Generate remediation timeline
	 */
	private generateRemediationTimeline(level: RiskAssessment['level']): string {
		switch (level) {
			case 'critical':
				return 'Immediately (within 24-48 hours)';
			case 'high':
				return 'Within 1 week';
			case 'medium':
				return 'Within 1 month';
			case 'low':
				return 'Within 3 months';
		}
	}

	/**
	 * Generate immediate actions
	 */
	private generateImmediateActions(findings: Finding[], chains: VulnerabilityChain[]): string[] {
		const actions: string[] = [];

		// Critical findings
		const criticalFindings = findings.filter(f => f.severity === 'critical');
		if (criticalFindings.length > 0) {
			actions.push(`Address ${criticalFindings.length} critical severity issue${criticalFindings.length > 1 ? 's' : ''} immediately`);
		}

		// Chained vulnerabilities
		if (chains.length > 0) {
			actions.push('Review compound vulnerability chains - they represent elevated risk');
		}

		// Auth issues
		if (findings.some(f => f.category === 'A07_AUTH_FAILURES')) {
			actions.push('Review and strengthen authentication mechanisms');
		}

		// Injection issues
		if (findings.some(f => f.category === 'A03_INJECTION')) {
			actions.push('Implement input validation and parameterized queries');
		}

		// Access control
		if (findings.some(f => f.category === 'A01_BROKEN_ACCESS_CONTROL')) {
			actions.push('Audit access control policies and enforce server-side authorization');
		}

		// Secrets
		if (findings.some(f => f.tags.includes('secret') || f.tags.includes('api-key'))) {
			actions.push('Rotate exposed secrets and implement secrets management');
		}

		return actions.slice(0, 5);
	}

	/**
	 * Get top vulnerabilities
	 */
	private getTopVulnerabilities(findings: Finding[]): Finding[] {
		const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
		return [...findings]
			.sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity))
			.slice(0, 5);
	}

	/**
	 * Group by severity
	 */
	private groupBySeverity(findings: Finding[]): Record<Severity, Finding[]> {
		const grouped: Record<Severity, Finding[]> = {
			critical: [],
			high: [],
			medium: [],
			low: [],
			info: [],
		};

		for (const finding of findings) {
			grouped[finding.severity].push(finding);
		}

		return grouped;
	}

	/**
	 * Group by category
	 */
	private groupByCategory(findings: Finding[]): Record<string, Finding[]> {
		const grouped: Record<string, Finding[]> = {};

		for (const finding of findings) {
			if (!grouped[finding.category]) {
				grouped[finding.category] = [];
			}
			grouped[finding.category].push(finding);
		}

		return grouped;
	}

	/**
	 * Get affected files
	 */
	private getAffectedFiles(findings: Finding[]): AffectedFile[] {
		const fileMap = new Map<string, Finding[]>();

		for (const finding of findings) {
			if (finding.evidence.file) {
				const existing = fileMap.get(finding.evidence.file) ?? [];
				existing.push(finding);
				fileMap.set(finding.evidence.file, existing);
			}
		}

		const affectedFiles: AffectedFile[] = [];

		for (const [path, fileFindings] of fileMap) {
			const severities = fileFindings.map(f => f.severity);
			const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
			const highestSeverity = severityOrder.find(s => severities.includes(s)) ?? 'info';

			affectedFiles.push({
				path,
				findings: fileFindings,
				riskLevel: highestSeverity,
			});
		}

		// Sort by risk level
		const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
		return affectedFiles.sort(
			(a, b) => severityOrder.indexOf(a.riskLevel) - severityOrder.indexOf(b.riskLevel)
		);
	}

	/**
	 * Get priority queue
	 */
	private getPriorityQueue(findings: Finding[]): PriorityItem[] {
		return findings
			.map(finding => ({
				finding,
				reason: this.getPriorityReason(finding),
				impact: this.getImpactDescription(finding),
				effort: finding.remediation.effort,
			}))
			.sort((a, b) => {
				// Sort by severity first
				const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
				const severityDiff = severityOrder.indexOf(a.finding.severity) - severityOrder.indexOf(b.finding.severity);
				if (severityDiff !== 0) return severityDiff;

				// Then by effort
				const effortOrder = ['trivial', 'low', 'medium', 'high'];
				return effortOrder.indexOf(a.effort) - effortOrder.indexOf(b.effort);
			});
	}

	/**
	 * Get priority reason
	 */
	private getPriorityReason(finding: Finding): string {
		const reasons: string[] = [];

		if (finding.severity === 'critical' || finding.severity === 'high') {
			reasons.push(`Severity: ${finding.severity}`);
		}
		if (finding.confidence > 0.8) {
			reasons.push('High confidence');
		}
		if (finding.cvcChainId) {
			reasons.push('Part of compound vulnerability chain');
		}
		if (finding.vcvfPattern) {
			reasons.push('Matches known AI-generated code vulnerability pattern');
		}

		return reasons.join(' | ') || 'Standard priority';
	}

	/**
	 * Get impact description
	 */
	private getImpactDescription(finding: Finding): string {
		const category = OWASP_CATEGORIES[finding.category as OWASPCategory];
		return category?.description ?? 'Security vulnerability';
	}

	/**
	 * Generate attack surface
	 */
	private generateAttackSurface(
		findings: Finding[],
		reconData?: { endpoints?: string[]; techStack?: string[]; dataFlows?: Array<{ source: string; sink: string }> }
	): AttackSurfaceMap {
		const entryPoints = this.generateEntryPoints(findings, reconData?.endpoints);
		const trustBoundaries = this.generateTrustBoundaries(findings);
		const dataFlows = this.generateDataFlows(findings, reconData?.dataFlows);
		const riskAreas = this.generateRiskAreas(findings);

		return { entryPoints, trustBoundaries, dataFlows, riskAreas };
	}

	/**
	 * Generate entry points
	 */
	private generateEntryPoints(findings: Finding[], endpoints?: string[]): SecurityReport['attackSurface']['entryPoints'] {
		const entryPoints: SecurityReport['attackSurface']['entryPoints'] = [];

		// API endpoints
		if (endpoints) {
			for (const endpoint of endpoints) {
				const relatedFindings = findings.filter(f =>
					f.evidence.request?.includes(endpoint) ||
					f.description.includes(endpoint)
				);
				const severities = relatedFindings.map(f => f.severity);
				const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
				const highestSeverity = severityOrder.find(s => severities.includes(s)) ?? 'info';

				entryPoints.push({
					id: `ep_${endpoint.replace(/[^a-z0-9]/gi, '_')}`,
					type: 'api',
					location: endpoint,
					risk: highestSeverity,
					associatedFindings: relatedFindings.map(f => f.id),
				});
			}
		}

		// Auth entry points
		const authFindings = findings.filter(f =>
			f.category === 'A07_AUTH_FAILURES' ||
			f.tags.includes('auth')
		);
		if (authFindings.length > 0) {
			entryPoints.push({
				id: 'ep_auth',
				type: 'auth',
				location: 'Authentication endpoints',
				risk: authFindings.some(f => f.severity === 'critical') ? 'critical' : 'high',
				associatedFindings: authFindings.map(f => f.id),
			});
		}

		return entryPoints;
	}

	/**
	 * Generate trust boundaries
	 */
	private generateTrustBoundaries(findings: Finding[]): SecurityReport['attackSurface']['trustBoundaries'] {
		const boundaries: SecurityReport['attackSurface']['trustBoundaries'] = [];

		// Client-Server boundary
		const clientServerIssues = findings.filter(f =>
			f.tags.includes('client-side') ||
			f.tags.includes('frontend') ||
			f.vcvfPattern === 'frontend_auth_logic'
		);
		if (clientServerIssues.length > 0) {
			boundaries.push({
				id: 'tb_client_server',
				name: 'Client-Server Boundary',
				description: 'Trust boundary between frontend client and backend server',
				inversions: clientServerIssues.map(f => f.id),
			});
		}

		// Database boundary
		const dbIssues = findings.filter(f =>
			f.category === 'A01_BROKEN_ACCESS_CONTROL' ||
			f.vcvfPattern === 'baas_bypass_architecture'
		);
		if (dbIssues.length > 0) {
			boundaries.push({
				id: 'tb_database',
				name: 'Database Boundary',
				description: 'Trust boundary for database access controls',
				inversions: dbIssues.map(f => f.id),
			});
		}

		return boundaries;
	}

	/**
	 * Generate data flows
	 */
	private generateDataFlows(
		findings: Finding[],
		reconDataFlows?: Array<{ source: string; sink: string }>
	): SecurityReport['attackSurface']['dataFlows'] {
		if (reconDataFlows) {
			return reconDataFlows.map((flow, i) => ({
				id: `df_${i}`,
				source: flow.source,
				sink: flow.sink,
				dataType: 'unknown',
				risks: findings
					.filter(f => f.description.includes(flow.source) || f.description.includes(flow.sink))
					.map(f => f.title),
			}));
		}

		// Generate from findings
		return findings.map((f, i) => ({
			id: `df_${i}`,
			source: f.evidence.file ?? 'unknown',
			sink: f.category,
			dataType: 'user-controlled',
			risks: [f.title],
		}));
	}

	/**
	 * Generate risk areas
	 */
	private generateRiskAreas(findings: Finding[]): SecurityReport['attackSurface']['riskAreas'] {
		const categories = this.groupByCategory(findings);
		const riskAreas: SecurityReport['attackSurface']['riskAreas'] = [];

		for (const [category, categoryFindings] of Object.entries(categories)) {
			const severities = categoryFindings.map(f => f.severity);
			const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
			const highestSeverity = severityOrder.find(s => severities.includes(s)) ?? 'info';

			const categoryInfo = OWASP_CATEGORIES[category as OWASPCategory];

			riskAreas.push({
				name: categoryInfo?.name ?? category,
				description: categoryInfo?.description ?? '',
				severity: highestSeverity,
				findings: categoryFindings.map(f => f.id),
			});
		}

		return riskAreas.sort(
			(a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
		);
	}

	/**
	 * Generate proof of concepts
	 */
	private generateProofOfConcepts(findings: Finding[]): ProofOfConcept[] {
		return findings
			.filter(f => f.severity === 'critical' || f.severity === 'high')
			.map(finding => ({
				findingId: finding.id,
				title: `Proof of Concept: ${finding.title}`,
				description: `Step-by-step exploitation of ${finding.title}`,
				steps: this.generatePoCSteps(finding),
				impact: finding.description,
			}));
	}

	/**
	 * Generate PoC steps
	 */
	private generatePoCSteps(finding: Finding): ProofOfConcept['steps'] {
		const steps: ProofOfConcept['steps'] = [
			{
				order: 1,
				action: 'Identify the vulnerable endpoint or component',
				code: finding.evidence.request,
				expectedResult: 'Vulnerable component is identified',
			},
		];

		if (finding.evidence.payload) {
			steps.push({
				order: 2,
				action: 'Craft and send the malicious request',
				code: finding.evidence.payload,
				expectedResult: 'Request is processed without proper validation',
			});
		}

		steps.push({
			order: steps.length + 1,
			action: 'Verify the vulnerability was successfully exploited',
			expectedResult: finding.remediation.summary,
		});

		return steps;
	}

	/**
	 * Generate remediation code
	 */
	private generateRemediationCode(findings: Finding[]): SecurityReport['remediationCode'] {
		return findings
			.filter(f => f.severity === 'critical' || f.severity === 'high')
			.map(finding => ({
				findingId: finding.id,
				title: finding.title,
				language: this.detectLanguage(finding),
				beforeCode: finding.evidence.request ?? '// Vulnerable code not available',
				afterCode: finding.remediation.codeExample ?? '// Remediation code not available',
				explanation: finding.remediation.summary,
			}));
	}

	/**
	 * Detect language from finding
	 */
	private detectLanguage(finding: Finding): string {
		if (finding.evidence.file) {
			const ext = finding.evidence.file.split('.').pop()?.toLowerCase();
			switch (ext) {
				case 'ts':
				case 'tsx':
					return 'typescript';
				case 'js':
				case 'jsx':
					return 'javascript';
				case 'py':
					return 'python';
				case 'go':
					return 'go';
				case 'rs':
					return 'rust';
				case 'java':
					return 'java';
				case 'rb':
					return 'ruby';
				case 'php':
					return 'php';
				default:
					return 'plaintext';
			}
		}
		return 'plaintext';
	}

	/**
	 * Format report for output
	 */
	format(report: Report): string {
		switch (this.options.format) {
			case 'json':
				return formatAsJson(report);
			case 'markdown':
				return formatAsMarkdown(report, this.options.audience);
			case 'html':
				return formatAsHtml(report, this.options.audience);
			default:
				return formatAsMarkdown(report, this.options.audience);
		}
	}
}

/**
 * Create report generator
 */
export function createReportGenerator(options: ReportOptions): ReportGenerator {
	return new ReportGenerator(options);
}
