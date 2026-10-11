import { eq, desc, asc, sql } from 'drizzle-orm';
import type { Database } from '../connection.js';
import { scans, type Scan, type NewScan } from '../schema/index.js';
import { generateScanId } from '@guardiant/shared';
import { type AuthScope, LOCAL_SCOPE, scanScopePredicate } from './auth-scope.js';

/**
 * Create a new scan
 *
 * # AUDIT-FIX [G-03] resolved: the scan is stamped with the caller's tenant.
 */
export async function createScan(
  db: Database,
  data: {
    target: string;
    type: 'url' | 'directory' | 'repository';
    config?: NewScan['config'];
  },
  scope: AuthScope = LOCAL_SCOPE
): Promise<Scan> {
  const id = generateScanId();
  const now = new Date().toISOString();

  const [scan] = await db.insert(scans).values({
    id,
    tenantId: scope.tenantId,
    target: data.target,
    type: data.type,
    status: 'pending',
    createdAt: now,
    config: data.config,
  }).returning();

  if (!scan) {
    throw new Error('Failed to create scan');
  }

  return scan;
}

/**
 * Get a scan by ID
 *
 * # AUDIT-FIX [G-03] resolved: the lookup is constrained to the caller's tenant,
 * so a known-but-foreign scan ID returns undefined rather than another tenant's
 * data.
 */
export async function getScan(db: Database, id: string, scope: AuthScope = LOCAL_SCOPE): Promise<Scan | undefined> {
  const [scan] = await db.select().from(scans).where(scanScopePredicate(scope, eq(scans.id, id)));
  return scan;
}

/**
 * Update a scan
 *
 * # AUDIT-FIX [G-03] resolved: the update predicate includes the tenant scope,
 * and tenantId can never be reassigned through the data payload.
 */
export async function updateScan(
  db: Database,
  id: string,
  data: Partial<Omit<NewScan, 'id' | 'tenantId'>>,
  scope: AuthScope = LOCAL_SCOPE
): Promise<Scan | undefined> {
  const [scan] = await db
    .update(scans)
    .set(data)
    .where(scanScopePredicate(scope, eq(scans.id, id)))
    .returning();
  return scan;
}

/**
 * Start a scan
 */
export async function startScan(db: Database, id: string, scope: AuthScope = LOCAL_SCOPE): Promise<Scan | undefined> {
  const now = new Date().toISOString();
  return updateScan(db, id, {
    status: 'running',
    startedAt: now,
  }, scope);
}

/**
 * Complete a scan
 */
export async function completeScan(
  db: Database,
  id: string,
  duration: number,
  scope: AuthScope = LOCAL_SCOPE
): Promise<Scan | undefined> {
  const now = new Date().toISOString();
  return updateScan(db, id, {
    status: 'completed',
    completedAt: now,
    duration,
  }, scope);
}

/**
 * Fail a scan
 */
export async function failScan(
  db: Database,
  id: string,
  error: string,
  scope: AuthScope = LOCAL_SCOPE
): Promise<Scan | undefined> {
  const now = new Date().toISOString();
  return updateScan(db, id, {
    status: 'failed',
    completedAt: now,
    error,
  }, scope);
}

/**
 * Cancel a scan
 */
export async function cancelScan(db: Database, id: string, scope: AuthScope = LOCAL_SCOPE): Promise<Scan | undefined> {
  const now = new Date().toISOString();
  return updateScan(db, id, {
    status: 'cancelled',
    completedAt: now,
  }, scope);
}

/**
 * List scans with pagination
 *
 * # AUDIT-FIX [G-03] resolved: results are always filtered to the caller's tenant.
 */
export async function listScans(
  db: Database,
  options: {
    status?: Scan['status'];
    limit?: number;
    offset?: number;
    orderBy?: 'createdAt' | 'updatedAt';
    order?: 'asc' | 'desc';
  } = {},
  scope: AuthScope = LOCAL_SCOPE
): Promise<Scan[]> {
  const {
    status,
    limit = 50,
    offset = 0,
    orderBy = 'createdAt',
    order = 'desc',
  } = options;

  const predicate = scanScopePredicate(scope, status ? eq(scans.status, status) : undefined);

  // Order by
  const orderColumn = orderBy === 'createdAt' ? scans.createdAt : scans.createdAt; // Only createdAt available
  const orderFn = order === 'asc' ? asc : desc;

  return db.select().from(scans).where(predicate).orderBy(orderFn(orderColumn)).limit(limit).offset(offset);
}

/**
 * Count scans
 */
export async function countScans(
  db: Database,
  options: { status?: Scan['status'] } = {},
  scope: AuthScope = LOCAL_SCOPE
): Promise<number> {
  const { status } = options;

  const predicate = scanScopePredicate(scope, status ? eq(scans.status, status) : undefined);

  const [result] = await db.select({ count: sql<number>`count(*)` }).from(scans).where(predicate);
  return result?.count ?? 0;
}

/**
 * Delete a scan
 *
 * # AUDIT-FIX [G-03] resolved: deletion is tenant-scoped; child rows cascade.
 */
export async function deleteScan(db: Database, id: string, scope: AuthScope = LOCAL_SCOPE): Promise<boolean> {
  const [result] = await db.delete(scans).where(scanScopePredicate(scope, eq(scans.id, id))).returning();
  return !!result;
}

/**
 * Get scan statistics
 */
export async function getScanStats(db: Database): Promise<{
  total: number;
  pending: number;
  running: number;
  completed: number;
  failed: number;
}> {
  const [stats] = await db
    .select({
      total: sql<number>`count(*)`,
      pending: sql<number>`sum(case when status = 'pending' then 1 else 0 end)`,
      running: sql<number>`sum(case when status = 'running' then 1 else 0 end)`,
      completed: sql<number>`sum(case when status = 'completed' then 1 else 0 end)`,
      failed: sql<number>`sum(case when status = 'failed' then 1 else 0 end)`,
    })
    .from(scans);

  return {
    total: Number(stats?.total ?? 0),
    pending: Number(stats?.pending ?? 0),
    running: Number(stats?.running ?? 0),
    completed: Number(stats?.completed ?? 0),
    failed: Number(stats?.failed ?? 0),
  };
}