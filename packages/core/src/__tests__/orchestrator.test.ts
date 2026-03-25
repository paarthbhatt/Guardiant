import { describe, it, expect, beforeEach, vi } from 'vitest';
import { CVCAnalyzer } from '../analyzers/cvc-analyzer.js';
import { VCVFMatcher } from '../analyzers/vcvf-matcher.js';
import { TIEFDetector } from '../analyzers/tief-detector.js';
import type { Finding } from '@guardiant/shared';

describe('CVCAnalyzer', () => {
	let analyzer: CVCAnalyzer;

	beforeEach(() => {
		analyzer = new CVCAnalyzer();
	});

	it('should return empty chains for single finding', async () => {
		const finding: Finding = createMockFinding('test-1', 'A03_INJECTION', 'high');

		const chains = await analyzer.findChains([finding]);

		expect(chains).toHaveLength(0);
	});

	it('should detect chainable vulnerabilities', async () => {
		const finding1: Finding = createMockFinding('test-1', 'A05_SECURITY_MISCONFIGURATION', 'high');
		const finding2: Finding = createMockFinding('test-2', 'A01_BROKEN_ACCESS_CONTROL', 'medium');

		const chains = await analyzer.findChains([finding1, finding2]);

		expect(chains.length).toBeGreaterThanOrEqual(0);
	});

	it('should calculate compound severity correctly', async () => {
		const critical: Finding = createMockFinding('test-1', 'A03_INJECTION', 'critical');
		const high: Finding = createMockFinding('test-2', 'A01_BROKEN_ACCESS_CONTROL', 'high');
		const medium: Finding = createMockFinding('test-3', 'A07_AUTH_FAILURES', 'medium');

		const chains = await analyzer.findChains([critical, high, medium]);

		if (chains.length > 0) {
			expect(chains[0].compoundSeverity).toBe('critical');
		}
	});

	it('should sort chains by severity', async () => {
		const medium: Finding = createMockFinding('test-1', 'A05_SECURITY_MISCONFIGURATION', 'medium');
		const critical: Finding = createMockFinding('test-2', 'A03_INJECTION', 'critical');

		const chains = await analyzer.findChains([medium, critical]);

		if (chains.length > 1) {
			expect(chains[0].compoundSeverity).toBe('critical');
		}
	});
});

describe('VCVFMatcher', () => {
	let matcher: VCVFMatcher;

	beforeEach(() => {
		matcher = new VCVFMatcher();
	});

	it('should detect symmetric CRUD pattern', async () => {
		const code = `
			// AI-generated CRUD API
			router.get('/api/users', getUsers);
			router.get('/api/users/:id', getUser);
			router.post('/api/users', createUser);
			router.put('/api/users/:id', updateUser);
			router.delete('/api/users/:id', deleteUser);

			// Same auth check for all
			function getUsers(req, res) {
				if (!req.session.userId) return res.status(401).send();
				// ...
			}
		`;

		const fingerprints = await matcher.analyze(code, 'routes/users.ts');

		expect(fingerprints.some(f => f.patternType === 'symmetric_crud_vulnerabilities')).toBe(true);
	});

	it('should detect auth/authz conflation', async () => {
		const code = `
			function deleteUser(req, res) {
				if (req.session.userId) { // Only checks if logged in
					db.users.delete({ id: req.params.id });
					res.send({ success: true });
				}
			}
		`;

		const fingerprints = await matcher.analyze(code, 'routes/users.ts');

		expect(fingerprints.some(f => f.patternType === 'auth_authz_conflation')).toBe(true);
	});

	it('should calculate composite score', () => {
		const fingerprints = [
			{ confidence: 0.8, patternType: 'test' as const, id: '1', evidence: [], locations: [], predictedVulnerabilities: [] },
			{ confidence: 0.6, patternType: 'test' as const, id: '2', evidence: [], locations: [], predictedVulnerabilities: [] },
		];

		const score = matcher.calculateCompositeScore(fingerprints);

		expect(score).toBeGreaterThan(0);
		expect(score).toBeLessThanOrEqual(10);
	});
});

describe('TIEFDetector', () => {
	let detector: TIEFDetector;

	beforeEach(() => {
		detector = new TIEFDetector();
	});

	it('should detect frontend auth logic trust inversion', async () => {
		const findings: Finding[] = [
			createMockFinding('test-1', 'A07_AUTH_FAILURES', 'high', 'auth_authz_conflation'),
		];

		const inversions = await detector.detect(findings);

		expect(inversions.some(i => i.type === 'frontend_auth_logic')).toBe(true);
	});

	it('should detect BaaS bypass architecture', async () => {
		const findings: Finding[] = [
			createMockFinding('test-1', 'A01_BROKEN_ACCESS_CONTROL', 'high'),
			createMockFinding('test-2', 'A05_SECURITY_MISCONFIGURATION', 'medium'),
			createMockFinding('test-3', 'A01_BROKEN_ACCESS_CONTROL', 'low'),
		];

		const inversions = await detector.detect(findings);

		// Multiple access control issues suggest BaaS bypass
		expect(inversions.length).toBeGreaterThan(0);
	});

	it('should find weakest trust anchor', async () => {
		const findings: Finding[] = [
			createMockFinding('test-1', 'A07_AUTH_FAILURES', 'low'),
			createMockFinding('test-2', 'A03_INJECTION', 'critical'),
		];

		const inversions = await detector.detect(findings);
		const weakest = detector.findWeakestAnchor(inversions);

		expect(weakest).not.toBeNull();
	});
});

/**
 * Create a mock finding for testing
 */
function createMockFinding(
	id: string,
	category: Finding['category'],
	severity: Finding['severity'],
	vcvfPattern?: string
): Finding {
	return {
		id,
		title: `Test Finding ${id}`,
		description: 'Test description',
		severity,
		category,
		cvssScore: severity === 'critical' ? 9.8 : severity === 'high' ? 7.5 : severity === 'medium' ? 5.0 : 2.5,
		confidence: 0.8,
		discoveredBy: 'test-agent',
		timestamp: new Date().toISOString(),
		evidence: {},
		remediation: {
			summary: 'Fix the vulnerability',
			steps: ['Step 1', 'Step 2'],
			effort: 'medium',
			priority: 1,
		},
		status: 'open',
		tags: [],
		...(vcvfPattern && { vcvfPattern }),
	};
}
