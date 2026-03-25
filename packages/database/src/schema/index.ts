import { sqliteTable, text, integer, real, index } from 'drizzle-orm/sqlite-core';
import { relations } from 'drizzle-orm';

/**
 * Scans table - tracks security scans
 */
export const scans = sqliteTable('scans', {
  id: text('id').primaryKey(),
  target: text('target').notNull(),
  type: text('type', { enum: ['url', 'directory', 'repository'] }).notNull(),
  status: text('status', { enum: ['pending', 'running', 'completed', 'failed', 'cancelled'] }).notNull().default('pending'),
  createdAt: text('created_at').notNull(),
  startedAt: text('started_at'),
  completedAt: text('completed_at'),
  config: text('config', { mode: 'json' }).$type<{
    agents?: string[];
    maxConcurrency?: number;
    timeout?: number;
    stopOnCritical?: boolean;
    llm?: { provider: string; model?: string };
  }>(),
  error: text('error'),
  duration: integer('duration'),
}, (table) => ({
  statusIdx: index('scans_status_idx').on(table.status),
  createdAtIdx: index('scans_created_at_idx').on(table.createdAt),
}));

/**
 * Findings table - individual vulnerability findings
 */
export const findings = sqliteTable('findings', {
  id: text('id').primaryKey(),
  scanId: text('scan_id').notNull().references(() => scans.id, { onDelete: 'cascade' }),
  agentId: text('agent_id').notNull(),
  title: text('title').notNull(),
  description: text('description').notNull(),
  severity: text('severity', { enum: ['critical', 'high', 'medium', 'low', 'info'] }).notNull(),
  category: text('category').notNull(),
  cvssScore: real('cvss_score').notNull(),
  confidence: real('confidence').notNull(),
  status: text('status', { enum: ['open', 'confirmed', 'false_positive', 'fixed', 'wont_fix'] }).notNull().default('open'),
  timestamp: text('timestamp').notNull(),

  // Evidence (JSON)
  evidence: text('evidence', { mode: 'json' }).$type<{
    request?: string;
    response?: string;
    file?: string;
    line?: number;
    column?: number;
    screenshot?: string;
    references?: string[];
    payload?: string;
    context?: Record<string, unknown>;
  }>().notNull(),

  // Remediation (JSON)
  remediation: text('remediation', { mode: 'json' }).$type<{
    summary: string;
    steps: string[];
    codeExample?: string;
    references?: string[];
    effort: 'trivial' | 'low' | 'medium' | 'high';
    priority: number;
  }>().notNull(),

  // Tags
  tags: text('tags', { mode: 'json' }).$type<string[]>().notNull().default([]),

  // CVC chain reference
  cvcChainId: text('cvc_chain_id').references(() => compoundChains.id),

  // VCVF pattern match
  vcvfPattern: text('vcvf_pattern'),

  // TIEF indicator
  tiefIndicator: text('tief_indicator'),

  // Metadata
  metadata: text('metadata', { mode: 'json' }).$type<Record<string, unknown>>(),
}, (table) => ({
  scanIdx: index('findings_scan_idx').on(table.scanId),
  severityIdx: index('findings_severity_idx').on(table.severity),
  categoryIdx: index('findings_category_idx').on(table.category),
  agentIdx: index('findings_agent_idx').on(table.agentId),
}));

/**
 * Agent runs table - tracks individual agent executions
 */
export const agentRuns = sqliteTable('agent_runs', {
  id: text('id').primaryKey(),
  scanId: text('scan_id').notNull().references(() => scans.id, { onDelete: 'cascade' }),
  agentId: text('agent_id').notNull(),
  status: text('status', { enum: ['pending', 'running', 'completed', 'failed', 'skipped'] }).notNull().default('pending'),
  startedAt: text('started_at'),
  completedAt: text('completed_at'),
  duration: integer('duration'),

  // Metrics
  tokensUsed: integer('tokens_used'),
  requestsMade: integer('requests_made').default(0),
  filesAnalyzed: integer('files_analyzed').default(0),
  endpointsTested: integer('endpoints_tested').default(0),
  findingsCount: integer('findings_count').default(0),

  // Error
  error: text('error'),
  stackTrace: text('stack_trace'),

  // Metadata
  metadata: text('metadata', { mode: 'json' }).$type<Record<string, unknown>>(),
}, (table) => ({
  scanIdx: index('agent_runs_scan_idx').on(table.scanId),
  agentIdx: index('agent_runs_agent_idx').on(table.agentId),
  statusIdx: index('agent_runs_status_idx').on(table.status),
}));

/**
 * Compound chains table - CVC vulnerability chains
 */
export const compoundChains = sqliteTable('compound_chains', {
  id: text('id').primaryKey(),
  scanId: text('scan_id').notNull().references(() => scans.id, { onDelete: 'cascade' }),
  findingIds: text('finding_ids', { mode: 'json' }).$type<string[]>().notNull(),
  compoundSeverity: text('compound_severity', { enum: ['critical', 'high', 'medium', 'low', 'info'] }).notNull(),
  compoundCvssScore: real('compound_cvss_score').notNull(),
  exploitPath: text('exploit_path').notNull(),

  // Attack steps (JSON)
  attackSteps: text('attack_steps', { mode: 'json' }).$type<{
    order: number;
    findingId: string;
    action: string;
    result: string;
  }[]>().notNull(),

  createdAt: text('created_at').notNull(),
}, (table) => ({
  scanIdx: index('compound_chains_scan_idx').on(table.scanId),
  severityIdx: index('compound_chains_severity_idx').on(table.compoundSeverity),
}));

/**
 * VCVF fingerprints table - detected VCVF patterns
 */
export const vcvfFingerprints = sqliteTable('vcvf_fingerprints', {
  id: text('id').primaryKey(),
  scanId: text('scan_id').notNull().references(() => scans.id, { onDelete: 'cascade' }),
  patternType: text('pattern_type').notNull(),
  confidence: real('confidence').notNull(),

  // Evidence (JSON)
  evidence: text('evidence', { mode: 'json' }).$type<string[]>().notNull(),

  // Locations (JSON)
  locations: text('locations', { mode: 'json' }).$type<{
    file: string;
    line?: number;
    snippet?: string;
  }[]>().notNull(),

  // Predicted vulnerabilities (JSON)
  predictedVulnerabilities: text('predicted_vulnerabilities', { mode: 'json' }).$type<{
    type: string;
    probability: number;
    location: string;
    reason: string;
  }[]>().notNull(),

  createdAt: text('created_at').notNull(),
}, (table) => ({
  scanIdx: index('vcvf_fingerprints_scan_idx').on(table.scanId),
  patternIdx: index('vcvf_fingerprints_pattern_idx').on(table.patternType),
}));

/**
 * Trust inversions table - TIEF detections
 */
export const trustInversions = sqliteTable('trust_inversions', {
  id: text('id').primaryKey(),
  scanId: text('scan_id').notNull().references(() => scans.id, { onDelete: 'cascade' }),
  type: text('type', { enum: [
    'frontend_auth_logic',
    'direct_database_access',
    'client_secrets',
    'missing_server_validation',
    'over_permissive_cors',
    'insecure_defaults'
  ] }).notNull(),

  misplacedTrust: text('misplaced_trust').notNull(),
  expectedBoundary: text('expected_boundary').notNull(),
  actualBoundary: text('actual_boundary').notNull(),
  severity: text('severity', { enum: ['critical', 'high', 'medium', 'low', 'info'] }).notNull(),

  // Associated findings
  findingIds: text('finding_ids', { mode: 'json' }).$type<string[]>().notNull(),

  createdAt: text('created_at').notNull(),
}, (table) => ({
  scanIdx: index('trust_inversions_scan_idx').on(table.scanId),
  typeIdx: index('trust_inversions_type_idx').on(table.type),
}));

/**
 * Reports table - generated reports
 */
export const reports = sqliteTable('reports', {
  id: text('id').primaryKey(),
  scanId: text('scan_id').notNull().references(() => scans.id, { onDelete: 'cascade' }),
  audience: text('audience', { enum: ['executive', 'developer', 'security'] }).notNull(),
  format: text('format', { enum: ['json', 'markdown', 'html', 'pdf'] }).notNull(),
  content: text('content').notNull(),
  createdAt: text('created_at').notNull(),
}, (table) => ({
  scanIdx: index('reports_scan_idx').on(table.scanId),
}));

/**
 * Relations
 */
export const scansRelations = relations(scans, ({ many }) => ({
  findings: many(findings),
  agentRuns: many(agentRuns),
  compoundChains: many(compoundChains),
  vcvfFingerprints: many(vcvfFingerprints),
  trustInversions: many(trustInversions),
  reports: many(reports),
}));

export const findingsRelations = relations(findings, ({ one }) => ({
  scan: one(scans, {
    fields: [findings.scanId],
    references: [scans.id],
  }),
  chain: one(compoundChains, {
    fields: [findings.cvcChainId],
    references: [compoundChains.id],
  }),
}));

export const agentRunsRelations = relations(agentRuns, ({ one }) => ({
  scan: one(scans, {
    fields: [agentRuns.scanId],
    references: [scans.id],
  }),
}));

export const compoundChainsRelations = relations(compoundChains, ({ one, many }) => ({
  scan: one(scans, {
    fields: [compoundChains.scanId],
    references: [scans.id],
  }),
  findings: many(findings),
}));

export const vcvfFingerprintsRelations = relations(vcvfFingerprints, ({ one }) => ({
  scan: one(scans, {
    fields: [vcvfFingerprints.scanId],
    references: [scans.id],
  }),
}));

export const trustInversionsRelations = relations(trustInversions, ({ one }) => ({
  scan: one(scans, {
    fields: [trustInversions.scanId],
    references: [scans.id],
  }),
}));

export const reportsRelations = relations(reports, ({ one }) => ({
  scan: one(scans, {
    fields: [reports.scanId],
    references: [scans.id],
  }),
}));

/**
 * Type exports
 */
export type Scan = typeof scans.$inferSelect;
export type NewScan = typeof scans.$inferInsert;
export type Finding = typeof findings.$inferSelect;
export type NewFinding = typeof findings.$inferInsert;
export type AgentRun = typeof agentRuns.$inferSelect;
export type NewAgentRun = typeof agentRuns.$inferInsert;
export type CompoundChain = typeof compoundChains.$inferSelect;
export type NewCompoundChain = typeof compoundChains.$inferInsert;
export type VCVFFingerprint = typeof vcvfFingerprints.$inferSelect;
export type NewVCVFFingerprint = typeof vcvfFingerprints.$inferInsert;
export type TrustInversionRecord = typeof trustInversions.$inferSelect;
export type NewTrustInversionRecord = typeof trustInversions.$inferInsert;
export type Report = typeof reports.$inferSelect;
export type NewReport = typeof reports.$inferInsert;