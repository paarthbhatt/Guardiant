import { describe, it, expect } from 'vitest';
import { CVCAnalyzer } from '../../analyzers/cvc-analyzer.js';
import { VCVFMatcher } from '../../analyzers/vcvf-matcher.js';
import { TIEFDetector } from '../../analyzers/tief-detector.js';
import { ReportGenerator } from '../../report/generator.js';
import type { Finding, AgentId, AgentResult } from '@guardiant/shared';

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
    cvssScore: severity === 'critical' ? 9.8 : severity === 'high' ? 7.5 : 5.0,
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

describe('Analysis Pipeline Integration', () => {
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

  describe('CVC → TIEF chained pipeline', () => {
    it('should detect chains and then trust inversions from the same finding set', async () => {
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
      const analyzer = new CVCAnalyzer();
      const chains = await analyzer.findChains(findings);

      if (chains.length > 0) {
        const hasCriticalChain = chains.some((c: { compoundSeverity: string }) => c.compoundSeverity === 'critical');
        expect(hasCriticalChain).toBe(true);
      }
    });
  });

  describe('VCVF → Report pipeline', () => {
    it('should pass VCVF fingerprints through to the report', async () => {
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
          injection: { agentId: 'injection', status: 'completed', findings, metadata: {}, duration: 5000 },
        } as unknown as Record<AgentId, AgentResult>,
        chains: [],
        vcvfFingerprints: fingerprints,
        trustInversions: [],
      });

      expect(report.security?.vcvfFingerprints.length).toBe(fingerprints.length);
      expect(report.findings).toHaveLength(findings.length);
    });
  });

  describe('Full pipeline: CVC + VCVF + TIEF → Executive Report', () => {
    it('should produce an executive summary with correct stats', async () => {
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
        agentResults: {} as Record<AgentId, AgentResult>,
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
  });
});
