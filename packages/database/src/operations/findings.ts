import { eq, and, desc, asc, sql } from 'drizzle-orm';
import type { Database } from '../connection.js';
import { findings, type Finding, type NewFinding } from '../schema/index.js';
import { generateFindingId } from '@guardiant/shared';
import type { Severity } from '@guardiant/shared';

/**
 * Create a new finding
 */
export async function createFinding(
  db: Database,
  data: Omit<NewFinding, 'id' | 'timestamp'>
): Promise<Finding> {
  const id = generateFindingId(data.agentId, data.category);
  const now = new Date().toISOString();

  const [finding] = await db.insert(findings).values({
    id,
    timestamp: now,
    ...data,
  }).returning();

  if (!finding) {
    throw new Error('Failed to create finding');
  }

  return finding;
}

/**
 * Create multiple findings
 */
export async function createFindings(
  db: Database,
  data: Array<Omit<NewFinding, 'id' | 'timestamp'>>
): Promise<Finding[]> {
  if (data.length === 0) return [];

  const now = new Date().toISOString();
  const findingsWithIds = data.map(f => ({
    ...f,
    id: generateFindingId(f.agentId, f.category),
    timestamp: now,
  }));

  const results = await db.insert(findings).values(findingsWithIds).returning();
  return results;
}

/**
 * Get a finding by ID
 */
export async function getFinding(db: Database, id: string): Promise<Finding | undefined> {
  const [finding] = await db.select().from(findings).where(eq(findings.id, id));
  return finding;
}

/**
 * Update a finding
 */
export async function updateFinding(
  db: Database,
  id: string,
  data: Partial<Omit<NewFinding, 'id'>>
): Promise<Finding | undefined> {
  const [finding] = await db
    .update(findings)
    .set(data)
    .where(eq(findings.id, id))
    .returning();
  return finding;
}

/**
 * Get all findings for a scan
 */
export async function getFindingsByScan(
  db: Database,
  scanId: string,
  options: {
    severity?: Severity;
    category?: string;
    agentId?: string;
    status?: Finding['status'];
    limit?: number;
    offset?: number;
    orderBy?: 'severity' | 'timestamp' | 'cvssScore';
    order?: 'asc' | 'desc';
  } = {}
): Promise<Finding[]> {
  const {
    severity,
    category,
    agentId,
    status,
    limit = 100,
    offset = 0,
    orderBy: orderByField = 'severity',
    order = 'desc',
  } = options;

  const conditions = [eq(findings.scanId, scanId)];

  if (severity) conditions.push(eq(findings.severity, severity));
  if (category) conditions.push(eq(findings.category, category));
  if (agentId) conditions.push(eq(findings.agentId, agentId));
  if (status) conditions.push(eq(findings.status, status));

  const orderColumn =
    orderByField === 'severity'
      ? findings.severity
      : orderByField === 'cvssScore'
        ? findings.cvssScore
        : findings.timestamp;
  const orderFn = order === 'asc' ? asc : desc;

  return db
    .select()
    .from(findings)
    .where(and(...conditions))
    .orderBy(orderFn(orderColumn))
    .limit(limit)
    .offset(offset);
}

/**
 * Count findings for a scan
 */
export async function countFindingsByScan(
  db: Database,
  scanId: string,
  options: { severity?: Severity; category?: string } = {}
): Promise<number> {
  const { severity, category } = options;

  const conditions = [eq(findings.scanId, scanId)];

  if (severity) conditions.push(eq(findings.severity, severity));
  if (category) conditions.push(eq(findings.category, category));

  const [result] = await db
    .select({ count: sql<number>`count(*)` })
    .from(findings)
    .where(and(...conditions));

  return result?.count ?? 0;
}

/**
 * Get findings by severity counts
 */
export async function getFindingsSummary(
  db: Database,
  scanId: string
): Promise<Record<Severity, number>> {
  const [summary] = await db
    .select({
      critical: sql<number>`sum(case when severity = 'critical' then 1 else 0 end)`,
      high: sql<number>`sum(case when severity = 'high' then 1 else 0 end)`,
      medium: sql<number>`sum(case when severity = 'medium' then 1 else 0 end)`,
      low: sql<number>`sum(case when severity = 'low' then 1 else 0 end)`,
      info: sql<number>`sum(case when severity = 'info' then 1 else 0 end)`,
    })
    .from(findings)
    .where(eq(findings.scanId, scanId));

  return {
    critical: Number(summary?.critical ?? 0),
    high: Number(summary?.high ?? 0),
    medium: Number(summary?.medium ?? 0),
    low: Number(summary?.low ?? 0),
    info: Number(summary?.info ?? 0),
  };
}

/**
 * Get findings by CVC chain
 */
export async function getFindingsByChain(
  db: Database,
  chainId: string
): Promise<Finding[]> {
  return db
    .select()
    .from(findings)
    .where(eq(findings.cvcChainId, chainId));
}

/**
 * Update finding status
 */
export async function updateFindingStatus(
  db: Database,
  id: string,
  status: Finding['status']
): Promise<Finding | undefined> {
  return updateFinding(db, id, { status });
}

/**
 * Delete findings for a scan
 */
export async function deleteFindingsByScan(db: Database, scanId: string): Promise<number> {
  const results = await db.delete(findings).where(eq(findings.scanId, scanId)).returning();
  return results.length;
}