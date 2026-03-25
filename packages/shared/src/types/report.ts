import { z } from 'zod';
import type { Finding, VulnerabilityChain, VCVFFingerprint, TrustInversion, Severity } from './vulnerability.js';
import type { AgentResult, AgentId } from './agent.js';

/**
 * Report audience type
 */
export type ReportAudience = 'executive' | 'developer' | 'security';

/**
 * Report format
 */
export type ReportFormat = 'json' | 'markdown' | 'html' | 'pdf';

/**
 * Risk assessment for executive reports
 */
export interface RiskAssessment {
  /** Overall risk score (1-10) */
  score: number;
  /** Risk level */
  level: 'critical' | 'high' | 'medium' | 'low';
  /** Business impact summary */
  businessImpact: string;
  /** Data exposure risk */
  dataExposureRisk: 'critical' | 'high' | 'medium' | 'low' | 'none';
  /** Compliance implications */
  complianceImplications: string[];
  /** Recommended timeline for remediation */
  remediationTimeline: string;
}

/**
 * Executive summary section
 */
export interface ExecutiveSummary {
  /** One-line summary */
  headline: string;
  /** Plain language summary */
  summary: string;
  /** Risk assessment */
  risk: RiskAssessment;
  /** Immediate action items */
  immediateActions: string[];
  /** Key statistics */
  statistics: {
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    chainedVulnerabilities: number;
  };
  /** Top vulnerabilities */
  topVulnerabilities: Finding[];
}

/**
 * Developer report section
 */
export interface DeveloperReport {
  /** Vulnerability list */
  vulnerabilities: Finding[];
  /** Grouped by severity */
  bySeverity: Record<Severity, Finding[]>;
  /** Grouped by category */
  byCategory: Record<string, Finding[]>;
  /** Affected files */
  affectedFiles: AffectedFile[];
  /** Fix priority queue */
  priorityQueue: PriorityItem[];
}

export interface AffectedFile {
  path: string;
  findings: Finding[];
  riskLevel: Severity;
}

export interface PriorityItem {
  finding: Finding;
  reason: string;
  impact: string;
  effort: 'trivial' | 'low' | 'medium' | 'high';
}

/**
 * Security report section
 */
export interface SecurityReport {
  /** Full technical findings */
  findings: Finding[];
  /** Compound vulnerability chains */
  chains: VulnerabilityChain[];
  /** VCVF fingerprints detected */
  vcvfFingerprints: VCVFFingerprint[];
  /** Trust inversions detected */
  trustInversions: TrustInversion[];
  /** Attack surface map */
  attackSurface: AttackSurfaceMap;
  /** Proof of concepts */
  proofOfConcepts: ProofOfConcept[];
  /** Detailed remediation code */
  remediationCode: RemediationCode[];
}

export interface AttackSurfaceMap {
  /** Entry points */
  entryPoints: EntryPoint[];
  /** Trust boundaries */
  trustBoundaries: TrustBoundary[];
  /** Data flows */
  dataFlows: DataFlow[];
  /** Risk areas */
  riskAreas: RiskArea[];
}

export interface EntryPoint {
  id: string;
  type: 'api' | 'ui' | 'auth' | 'file' | 'other';
  location: string;
  risk: Severity;
  associatedFindings: string[];
}

export interface TrustBoundary {
  id: string;
  name: string;
  description: string;
  inversions: string[];
}

export interface DataFlow {
  id: string;
  source: string;
  sink: string;
  dataType: string;
  risks: string[];
}

export interface RiskArea {
  name: string;
  description: string;
  severity: Severity;
  findings: string[];
}

export interface ProofOfConcept {
  findingId: string;
  title: string;
  description: string;
  steps: ProofOfConceptStep[];
  impact: string;
}

export interface ProofOfConceptStep {
  order: number;
  action: string;
  code?: string;
  expectedResult: string;
}

export interface RemediationCode {
  findingId: string;
  title: string;
  language: string;
  beforeCode: string;
  afterCode: string;
  explanation: string;
}

/**
 * Complete scan report
 */
export interface Report {
  /** Report ID */
  id: string;
  /** Scan ID */
  scanId: string;
  /** Target scanned */
  target: string;
  /** Scan timestamp */
  timestamp: string;
  /** Duration in milliseconds */
  duration: number;
  /** Agent results */
  agentResults: Record<AgentId, AgentResult>;
  /** Executive summary (for business audience) */
  executive?: ExecutiveSummary;
  /** Developer report (for technical team) */
  developer?: DeveloperReport;
  /** Security report (for security team) */
  security?: SecurityReport;
  /** All findings */
  findings: Finding[];
  /** Vulnerability chains */
  chains: VulnerabilityChain[];
  /** VCVF patterns */
  vcvfFingerprints: VCVFFingerprint[];
  /** Trust inversions */
  trustInversions: TrustInversion[];
}

/**
 * Report generator options
 */
export interface ReportOptions {
  /** Target audience */
  audience: ReportAudience;
  /** Output format */
  format: ReportFormat;
  /** Include proof of concepts */
  includePocs: boolean;
  /** Include code snippets */
  includeCodeSnippets: boolean;
  /** Custom template path */
  templatePath?: string;
}

/**
 * Zod schemas for validation
 */
export const ReportOptionsSchema = z.object({
  audience: z.enum(['executive', 'developer', 'security']),
  format: z.enum(['json', 'markdown', 'html', 'pdf']),
  includePocs: z.boolean().default(true),
  includeCodeSnippets: z.boolean().default(true),
  templatePath: z.string().optional(),
});