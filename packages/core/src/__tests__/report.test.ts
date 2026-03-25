import { describe, it, expect } from 'vitest';
import { ReportGenerator } from '../report/generator.js';

describe('ReportGenerator', () => {
	const createMockData = () => ({
		scanId: 'test-scan-123',
		target: 'https://example.com',
		duration: 60000,
		findings: [
			{
				id: 'f1',
				title: 'SQL Injection',
				description: 'SQL injection vulnerability in user input',
				severity: 'critical' as const,
				category: 'A03_INJECTION' as const,
				cvssScore: 9.8,
				confidence: 0.9,
				discoveredBy: 'injection-agent',
				timestamp: new Date().toISOString(),
				evidence: {
					request: 'GET /api/users?id=1\' OR 1=1 --',
					payload: "' OR 1=1 --",
				},
				remediation: {
					summary: 'Use parameterized queries',
					steps: ['Use ORM', 'Validate input'],
					effort: 'low' as const,
					priority: 1,
				},
				status: 'open' as const,
				tags: ['injection', 'sql'],
			},
			{
				id: 'f2',
				title: 'Exposed API Key',
				description: 'API key found in client-side code',
				severity: 'high' as const,
				category: 'A02_CRYPTOGRAPHIC_FAILURES' as const,
				cvssScore: 7.5,
				confidence: 0.95,
				discoveredBy: 'secrets-agent',
				timestamp: new Date().toISOString(),
				evidence: {
					file: 'src/app.ts',
					line: 42,
				},
				remediation: {
					summary: 'Move secrets to server-side',
					steps: ['Remove from client code', 'Use environment variables'],
					effort: 'trivial' as const,
					priority: 1,
				},
				status: 'open' as const,
				tags: ['secret', 'api-key'],
			},
		],
		agentResults: {
			recon: {
				agentId: 'recon',
				status: 'completed' as const,
				findings: [],
				metadata: {},
				duration: 5000,
			},
			injection: {
				agentId: 'injection',
				status: 'completed' as const,
				findings: [],
				metadata: {},
				duration: 30000,
			},
		},
		chains: [
			{
				id: 'chain_1',
				findings: [],
				compoundSeverity: 'critical' as const,
				compoundCvssScore: 10.0,
				exploitPath: 'SQL Injection leads to data exfiltration',
				attackSteps: [
					{ order: 1, findingId: 'f1', action: 'Inject SQL', result: 'Database access' },
				],
			},
		],
		vcvfFingerprints: [
			{
				id: 'vcvf_1',
				patternType: 'auth_authz_conflation' as const,
				confidence: 0.75,
				evidence: ['Auth check used for authorization'],
				locations: [{ file: 'src/auth.ts', line: 25 }],
				predictedVulnerabilities: [
					{ type: 'A01_BROKEN_ACCESS_CONTROL', probability: 0.7, location: 'src/auth.ts', reason: 'Auth used for authz' },
				],
			},
		],
		trustInversions: [
			{
				id: 'tief_1',
				type: 'frontend_auth_logic' as const,
				misplacedTrust: 'Frontend JavaScript',
				expectedBoundary: 'Backend server',
				actualBoundary: 'Client-side checks',
				severity: 'high' as const,
				findingIds: ['f2'],
			},
		],
	});

	describe('generate', () => {
		it('should generate executive report', () => {
			const generator = new ReportGenerator({
				audience: 'executive',
				format: 'markdown',
				includePocs: false,
				includeCodeSnippets: false,
			});

			const data = createMockData();
			const report = generator.generate(data);

			expect(report.executive).toBeDefined();
			expect(report.executive?.headline).toContain('example.com');
			expect(report.executive?.statistics.totalFindings).toBe(2);
			expect(report.executive?.statistics.criticalCount).toBe(1);
			expect(report.executive?.statistics.highCount).toBe(1);
			expect(report.executive?.risk.score).toBeGreaterThan(0);
		});

		it('should generate developer report', () => {
			const generator = new ReportGenerator({
				audience: 'developer',
				format: 'markdown',
				includePocs: true,
				includeCodeSnippets: true,
			});

			const data = createMockData();
			const report = generator.generate(data);

			expect(report.developer).toBeDefined();
			expect(report.developer?.vulnerabilities).toHaveLength(2);
			expect(report.developer?.bySeverity.critical).toHaveLength(1);
			expect(report.developer?.bySeverity.high).toHaveLength(1);
		});

		it('should generate security report with all details', () => {
			const generator = new ReportGenerator({
				audience: 'security',
				format: 'markdown',
				includePocs: true,
				includeCodeSnippets: true,
			});

			const data = createMockData();
			const report = generator.generate(data);

			expect(report.security).toBeDefined();
			expect(report.security?.chains).toHaveLength(1);
			expect(report.security?.vcvfFingerprints).toHaveLength(1);
			expect(report.security?.trustInversions).toHaveLength(1);
			expect(report.security?.proofOfConcepts).toHaveLength(2);
			expect(report.security?.remediationCode).toHaveLength(2);
		});

		it('should calculate correct risk score', () => {
			const generator = new ReportGenerator({
				audience: 'executive',
				format: 'markdown',
				includePocs: false,
				includeCodeSnippets: false,
			});

			const data = createMockData();
			const report = generator.generate(data);

			// Critical + High should give high risk score
			expect(report.executive?.risk.score).toBeGreaterThanOrEqual(5);
			expect(['critical', 'high']).toContain(report.executive?.risk.level);
		});
	});

	describe('format', () => {
		it('should format as JSON', () => {
			const generator = new ReportGenerator({
				audience: 'developer',
				format: 'json',
				includePocs: false,
				includeCodeSnippets: false,
			});

			const data = createMockData();
			const report = generator.generate(data);
			const output = generator.format(report);

			expect(() => JSON.parse(output)).not.toThrow();
		});

		it('should format as Markdown', () => {
			const generator = new ReportGenerator({
				audience: 'developer',
				format: 'markdown',
				includePocs: false,
				includeCodeSnippets: false,
			});

			const data = createMockData();
			const report = generator.generate(data);
			const output = generator.format(report);

			expect(output).toContain('# Security Scan Report');
			expect(output).toContain('SQL Injection');
			expect(output).toContain('Critical');
		});

		it('should format as HTML', () => {
			const generator = new ReportGenerator({
				audience: 'developer',
				format: 'html',
				includePocs: false,
				includeCodeSnippets: false,
			});

			const data = createMockData();
			const report = generator.generate(data);
			const output = generator.format(report);

			expect(output).toContain('<!DOCTYPE html>');
			expect(output).toContain('Security Scan Report');
			expect(output).toContain('SQL Injection');
		});
	});
});
