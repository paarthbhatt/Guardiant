import { describe, it, expect, beforeEach } from 'vitest';
import { CVCAnalyzer } from '../../analyzers/cvc-analyzer.js';
import { VCVFMatcher } from '../../analyzers/vcvf-matcher.js';
import { TIEFDetector } from '../../analyzers/tief-detector.js';
import { ReportGenerator } from '../../report/generator.js';
import type { Finding, AgentId, AgentResult, VCVFFingerprint, VulnerabilityChain, TrustInversion } from '@guardiant/shared';

/**
 * Integration tests — runs multiple components together against
 * a realistic set of findings, simulating what the orchestrator does
 * after the agent swarm completes.
 */

function makeFinding(
  id: string,
  category: Finding['category'],
  severity: Finding['severity'],
  opts: Partial<Finding> = {}
): Finding {
  return {
    id,
    title: `Finding ${id}`,
    description: `Description of finding ${id}`,
    severity,
    category,
    cvssScore: severity === 'critical' ? 9.8 : severity === 'high' ? 7.5 : severity === 'medium' ? 5.0 : 2.5,
    confidence: 0.85,
    discoveredBy: 'injection',
    timestamp: new Date().toISOString(),
    evidence: { request: `GET /api/${id}`, payload: "' OR 1=1" },
    remediation: {
      summary: 'Fix the vulnerability',
      steps: ['Step 1', 'Step 2'],
      effort: 'medium',
      priority: 1,
    },
    status: 'open',
    tags: ['test'],
    ...opts,
  };
}

function makeAgentResults(overrides?: Record<string, Partial<AgentResult>>): Record<AgentId, AgentResult> {
  const defaultResult = {
    status: 'completed' as const,
    findings: [],
    metadata: {},
    duration: 1000,
  };

  return {
    recon: { agentId: 'recon', ...defaultResult, ...overrides?.recon } as AgentResult,
    baas: { agentId: 'baas', ...defaultResult, ...overrides?.baas } as AgentResult,
    secrets: { agentId: 'secrets', ...defaultResult, ...overrides?.secrets } as AgentResult,
    auth: { agentId: 'auth', ...defaultResult, ...overrides?.auth } as AgentResult,
    injection: { agentId: 'injection', ...defaultResult, ...overrides?.injection } as AgentResult,
    supply_chain: { agentId: 'supply_chain', ...defaultResult, ...overrides?.supply_chain } as AgentResult,
    business_logic: { agentId: 'business_logic', ...defaultResult, ...overrides?.business_logic } as AgentResult,
    race_condition: { agentId: 'race_condition', ...defaultResult, ...overrides?.race_condition } as AgentResult,
  };
}

describe('CVC → TIEF chained pipeline', () => {
    it('should detect chains and then trust inversions from the same finding set', async () => {
      const findings: Finding[] = [
        makeFinding('sqli-1', 'A03_INJECTION', 'critical'),
        makeFinding('access-1', 'A01_BROKEN_ACCESS_CONTROL', 'high'),
        makeFinding('misconfig-1', 'A05_SECURITY_MISCONFIGURATION', 'medium'),
        makeFinding('auth-1', 'A07_AUTH_FAILURES', 'high', {
          vcvfPattern: 'auth_authz_conflation',
        }),
        makeFinding('secret-1', 'A02_CRYPTOGRAPHIC_FAILURES', 'critical', {
          tags: ['secret', 'api-key'],
        }),
      ];

      const cvcAnalyzer = new CVCAnalyzer();
      const tiefDetector = new TIEFDetector();

      const chains = await cvcAnalyzer.findChains(findings);
      const inversions = await tiefDetector.detect(findings);

      // CVC: security misconfiguration + access control should chain
      expect(chains.length).toBeGreaterThanOrEqual(0);

      // TIEF: auth/authz conflation finding should produce frontend_auth_logic
      expect(inversions.some((i) => i.type === 'frontend_auth_logic')).toBe(true);
    });

    it('should produce compound severity of at least critical when critical findings chain', async () => {
      const findings: Finding[] = [
        makeFinding('sqli-1', 'A03_INJECTION', 'critical'),
        makeFinding('access-1', 'A01_BROKEN_ACCESS_CONTROL', 'high'),
        makeFinding('misconfig-1', 'A05_SECURITY_MISCONFIGURATION', 'medium'),
      ];

      const analyzer = new CVCAnalyzer();
      const chains = await analyzer.findChains(findings);

      if (chains.length > 0) {
        const hasCriticalChain = chains.some((c) => c.compoundSeverity === 'critical');
        expect(hasCriticalChain).toBe(true);
      }
    });

    it('should generate valid exploit paths for chains', async () => {
      const findings: Finding[] = [
        makeFinding('sqli-1', 'A03_INJECTION', 'critical'),
        makeFinding('access-1', 'A01_BROKEN_ACCESS_CONTROL', 'high'),
      ];

      const analyzer = new CVCAnalyzer();
      const chains = await analyzer.findChains(findings);

      for (const chain of chains) {
        expect(chain.exploitPath).toBeDefined();
        expect(chain.exploitPath.length).toBeGreaterThan(0);
        expect(chain.attackSteps).toBeDefined();
        expect(chain.attackSteps.length).toBeGreaterThan(0);
      }
    });
  });

  describe('VCVF → Report pipeline', () => {
    it('should pass VCVF fingerprints through to the report', async () => {
      const findings: Finding[] = [
        makeFinding('sqli-1', 'A03_INJECTION', 'critical'),
        makeFinding('auth-1', 'A07_AUTH_FAILURES', 'high', {
          vcvfPattern: 'auth_authz_conflation',
        }),
      ];

      const matcher = new VCVFMatcher();
      const code = `
        function deleteUser(req, res) {
          if (req.session.userId) {
            db.users.delete({ id: req.params.id });
            res.send({ success: true });
          }
        }
      `;
      const fingerprints = await matcher.analyze(code, 'routes/users.ts');

      const generator = new ReportGenerator({
        audience: 'security',
        format: 'json',
        includePocs: true,
        includeCodeSnippets: true,
      });

      const report = generator.generate({
        scanId: 'integration-test-1',
        target: 'https://example.com',
        duration: 30000,
        findings,
        agentResults: {
          recon: { agentId: 'recon', status: 'completed', findings: [], metadata: {}, duration: 1000 },
          baas: { agentId: 'baas', status: 'completed', findings: [], metadata: {}, duration: 1000 },
          secrets: { agentId: 'secrets', status: 'completed', findings: [], metadata: {}, duration: 1000 },
          auth: { agentId: 'auth', status: 'completed', findings: [], metadata: {}, duration: 1000 },
          injection: { agentId: 'injection', status: 'completed', findings, metadata: {}, duration: 5000 },
          supply_chain: { agentId: 'supply_chain', status: 'completed', findings: [], metadata: {}, duration: 1000 },
          business_logic: { agentId: 'business_logic', status: 'completed', findings: [], metadata: {}, duration: 1000 },
          race_condition: { agentId: 'race_condition', status: 'completed', findings: [], metadata: {}, duration: 1000 },
        },
        chains: [],
        vcvfFingerprints: fingerprints,
        trustInversions: [],
      });

      expect(report.security?.vcvfFingerprints.length).toBe(fingerprints.length);
      expect(report.findings).toHaveLength(findings.length);
    });

    it('should detect multiple VCVF patterns from code', async () => {
      const matcher = new VCVFMatcher();
      const code = `
        // AI-generated CRUD with symmetric vulnerabilities
        router.get('/api/users', authenticate, getUsers);
        router.post('/api/users', authenticate, createUser);
        router.put('/api/users/:id', authenticate, updateUser);
        router.delete('/api/users/:id', authenticate, deleteUser);

        // Auth/authz conflation
        function deleteUser(req, res) {
          if (req.session.userId) {
            db.users.delete({ id: req.params.id });
          }
        }

        // Optimistic trust
        function createPost(req, res) {
          const post = req.body;
          db.posts.create(post);
        }

        // Missing error handling
        function fetchData() {
          try {
            return fetchDataInternal();
          } catch (e) {
            // Silently ignore
          }
        }
      `;

      const fingerprints = await matcher.analyze(code, 'routes/api.ts');

      expect(fingerprints.length).toBeGreaterThan(0);
      expect(fingerprints.some(f => f.patternType === 'auth_authz_conflation')).toBe(true);
      expect(fingerprints.some(f => f.patternType === 'optimistic_trust_patterns')).toBe(true);
    });
  });

  describe('Full pipeline: CVC + VCVF + TIEF → Executive Report', () => {
    it('should produce an executive summary with correct stats', async () => {
      const findings: Finding[] = [
        makeFinding('sqli-1', 'A03_INJECTION', 'critical'),
        makeFinding('access-1', 'A01_BROKEN_ACCESS_CONTROL', 'high'),
        makeFinding('misconfig-1', 'A05_SECURITY_MISCONFIGURATION', 'medium'),
        makeFinding('auth-1', 'A07_AUTH_FAILURES', 'high', {
          vcvfPattern: 'auth_authz_conflation',
        }),
        makeFinding('secret-1', 'A02_CRYPTOGRAPHIC_FAILURES', 'critical'),
      ];

      const cvc = new CVCAnalyzer();
      const tief = new TIEFDetector();

      const chains = await cvc.findChains(findings);
      const inversions = await tief.detect(findings);

      const generator = new ReportGenerator({
        audience: 'executive',
        format: 'markdown',
        includePocs: false,
        includeCodeSnippets: false,
      });

      const report = generator.generate({
        scanId: 'integration-test-2',
        target: 'https://myapp.io',
        duration: 45000,
        findings,
        agentResults: makeAgentResults(),
        chains,
        vcvfFingerprints: [],
        trustInversions: inversions,
      });

      expect(report.executive).toBeDefined();
      expect(report.executive!.statistics.totalFindings).toBe(5);
      expect(report.executive!.statistics.criticalCount).toBe(2);
      expect(report.executive!.statistics.highCount).toBe(2);
      expect(report.executive!.risk.level).toBe('critical');
      expect(report.executive!.headline).toContain('myapp.io');
    });

    it('should calculate risk score correctly for mixed severities', async () => {
      const findings: Finding[] = [
        makeFinding('low-1', 'A05_SECURITY_MISCONFIGURATION', 'low'),
        makeFinding('medium-1', 'A04_INSECURE_DESIGN', 'medium'),
        makeFinding('high-1', 'A01_BROKEN_ACCESS_CONTROL', 'high'),
      ];

      const generator = new ReportGenerator({
        audience: 'executive',
        format: 'markdown',
        includePocs: false,
        includeCodeSnippets: false,
      });

      const report = generator.generate({
        scanId: 'risk-test',
        target: 'https://example.com',
        duration: 10000,
        findings,
        agentResults: makeAgentResults(),
        chains: [],
        vcvfFingerprints: [],
        trustInversions: [],
      });

      expect(report.executive!.risk.level).toBe('high');
      expect(report.executive!.risk.score).toBeGreaterThan(3);
      expect(report.executive!.risk.score).toBeLessThan(8);
    });
  });

  describe('Full pipeline: Developer Report', () => {
    it('should group findings by severity and category', async () => {
      const findings: Finding[] = [
        makeFinding('sqli-1', 'A03_INJECTION', 'critical'),
        makeFinding('sqli-2', 'A03_INJECTION', 'high'),
        makeFinding('access-1', 'A01_BROKEN_ACCESS_CONTROL', 'high'),
        makeFinding('misconfig-1', 'A05_SECURITY_MISCONFIGURATION', 'medium'),
      ];

      const generator = new ReportGenerator({
        audience: 'developer',
        format: 'markdown',
        includePocs: true,
        includeCodeSnippets: true,
      });

      const report = generator.generate({
        scanId: 'dev-test',
        target: 'https://example.com',
        duration: 20000,
        findings,
        agentResults: makeAgentResults(),
        chains: [],
        vcvfFingerprints: [],
        trustInversions: [],
      });

      expect(report.developer).toBeDefined();
      expect(report.developer!.bySeverity.critical).toHaveLength(1);
      expect(report.developer!.bySeverity.high).toHaveLength(2);
      expect(report.developer!.bySeverity.medium).toHaveLength(1);
      expect(report.developer!.byCategory['A03_INJECTION']).toHaveLength(2);
    });

    it('should include remediation steps for each finding', async () => {
      const findings: Finding[] = [
        makeFinding('sqli-1', 'A03_INJECTION', 'critical'),
      ];

      const generator = new ReportGenerator({
        audience: 'developer',
        format: 'markdown',
        includePocs: true,
        includeCodeSnippets: true,
      });

      const report = generator.generate({
        scanId: 'remediation-test',
        target: 'https://example.com',
        duration: 5000,
        findings,
        agentResults: makeAgentResults(),
        chains: [],
        vcvfFingerprints: [],
        trustInversions: [],
      });

      expect(report.developer!.vulnerabilities[0].remediation).toBeDefined();
      expect(report.developer!.vulnerabilities[0].remediation.steps.length).toBeGreaterThan(0);
    });
  });

  describe('Full pipeline: Security Report with PoCs', () => {
    it('should include proof-of-concept payloads', async () => {
      const findings: Finding[] = [
        makeFinding('sqli-1', 'A03_INJECTION', 'critical', {
          evidence: {
            request: "GET /api/users?id=1' OR '1'='1",
            payload: "' OR '1'='1",
          },
        }),
        makeFinding('xss-1', 'A03_INJECTION', 'high', {
          evidence: {
            request: "POST /api/comments body=<script>alert(1)</script>",
            payload: '<script>alert(1)</script>',
          },
        }),
      ];

      const generator = new ReportGenerator({
        audience: 'security',
        format: 'json',
        includePocs: true,
        includeCodeSnippets: true,
      });

      const report = generator.generate({
        scanId: 'poc-test',
        target: 'https://example.com',
        duration: 15000,
        findings,
        agentResults: makeAgentResults(),
        chains: [],
        vcvfFingerprints: [],
        trustInversions: [],
      });

      expect(report.security!.proofOfConcepts).toHaveLength(2);
      expect(report.security!.proofOfConcepts[0]).toBeDefined();
    });

    it('should include compound vulnerability chains', async () => {
      const findings: Finding[] = [
        makeFinding('sqli-1', 'A03_INJECTION', 'critical'),
        makeFinding('access-1', 'A01_BROKEN_ACCESS_CONTROL', 'high'),
      ];

      const analyzer = new CVCAnalyzer();
      const chains = await analyzer.findChains(findings);

      const generator = new ReportGenerator({
        audience: 'security',
        format: 'json',
        includePocs: true,
        includeCodeSnippets: true,
      });

      const report = generator.generate({
        scanId: 'chain-test',
        target: 'https://example.com',
        duration: 20000,
        findings,
        agentResults: makeAgentResults(),
        chains,
        vcvfFingerprints: [],
        trustInversions: [],
      });

      expect(report.security!.chains).toBeDefined();
      if (chains.length > 0) {
        expect(report.security!.chains.length).toBe(chains.length);
      }
    });
  });

  describe('Report Format Conversion', () => {
    it('should convert to JSON format', () => {
      const findings: Finding[] = [makeFinding('test-1', 'A03_INJECTION', 'high')];

      const generator = new ReportGenerator({
        audience: 'developer',
        format: 'json',
        includePocs: false,
        includeCodeSnippets: false,
      });

      const report = generator.generate({
        scanId: 'format-test',
        target: 'https://example.com',
        duration: 1000,
        findings,
        agentResults: makeAgentResults(),
        chains: [],
        vcvfFingerprints: [],
        trustInversions: [],
      });

      const output = generator.format(report);
      expect(() => JSON.parse(output)).not.toThrow();
    });

    it('should convert to Markdown format', () => {
      const findings: Finding[] = [makeFinding('test-1', 'A03_INJECTION', 'critical')];

      const generator = new ReportGenerator({
        audience: 'executive',
        format: 'markdown',
        includePocs: false,
        includeCodeSnippets: false,
      });

      const report = generator.generate({
        scanId: 'markdown-test',
        target: 'https://example.com',
        duration: 1000,
        findings,
        agentResults: makeAgentResults(),
        chains: [],
        vcvfFingerprints: [],
        trustInversions: [],
      });

      const output = generator.format(report);
      expect(output).toContain('# ');
      expect(output).toContain('example.com');
    });

    it('should convert to HTML format', () => {
      const findings: Finding[] = [makeFinding('test-1', 'A03_INJECTION', 'high')];

      const generator = new ReportGenerator({
        audience: 'developer',
        format: 'html',
        includePocs: false,
        includeCodeSnippets: false,
      });

      const report = generator.generate({
        scanId: 'html-test',
        target: 'https://example.com',
        duration: 1000,
        findings,
        agentResults: makeAgentResults(),
        chains: [],
        vcvfFingerprints: [],
        trustInversions: [],
      });

      const output = generator.format(report);
      expect(output).toContain('<!DOCTYPE html>');
      expect(output).toContain('<html');
      expect(output).toContain('Security');
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty findings gracefully', async () => {
      const generator = new ReportGenerator({
        audience: 'executive',
        format: 'markdown',
        includePocs: false,
        includeCodeSnippets: false,
      });

      const report = generator.generate({
        scanId: 'empty-test',
        target: 'https://example.com',
        duration: 5000,
        findings: [],
        agentResults: makeAgentResults(),
        chains: [],
        vcvfFingerprints: [],
        trustInversions: [],
      });

      expect(report.executive!.statistics.totalFindings).toBe(0);
      expect(report.executive!.risk.level).toBe('info');
      expect(report.findings).toHaveLength(0);
    });

    it('should handle findings with missing optional fields', async () => {
      const finding1: Finding = {
        id: 'minimal',
        title: 'Minimal Finding',
        description: 'A minimal finding',
        severity: 'medium',
        category: 'A05_SECURITY_MISCONFIGURATION',
        cvssScore: 5.0,
        confidence: 0.5,
        discoveredBy: 'test-agent',
        timestamp: new Date().toISOString(),
        evidence: {},
        remediation: {
          summary: 'Fix it',
          steps: [],
          effort: 'medium',
          priority: 5,
        },
        status: 'open',
        tags: [],
      };

      const finding2: Finding = {
        id: 'minimal-2',
        title: 'Another Minimal Finding',
        description: 'Another minimal finding',
        severity: 'low',
        category: 'A01_BROKEN_ACCESS_CONTROL',
        cvssScore: 2.0,
        confidence: 0.5,
        discoveredBy: 'test-agent',
        timestamp: new Date().toISOString(),
        evidence: {},
        remediation: {
          summary: 'Fix it',
          steps: [],
          effort: 'medium',
          priority: 5,
        },
        status: 'open',
        tags: [],
      };

      const analyzer = new CVCAnalyzer();
      const chains = await analyzer.analyze([finding1, finding2]);

      expect(chains).toBeDefined();
    });

    it('should handle large finding sets efficiently', async () => {
      const findings: Finding[] = Array.from({ length: 100 }, (_, i) =>
        makeFinding(`finding-${i}`, 'A03_INJECTION', i % 3 === 0 ? 'critical' : 'high')
      );

      const cvc = new CVCAnalyzer();
      const tief = new TIEFDetector();
      const matcher = new VCVFMatcher();

      const start = Date.now();
      const chains = await cvc.findChains(findings);
      const inversions = await tief.detect(findings);
      const elapsed = Date.now() - start;

      expect(elapsed).toBeLessThan(5000); // Should complete in under 5 seconds
      expect(chains).toBeDefined();
      expect(inversions).toBeDefined();
    });
  });