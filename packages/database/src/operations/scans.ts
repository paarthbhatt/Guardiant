import { eq, desc, asc, sql } from 'drizzle-orm';
import type { Database } from '../connection.js';
import { scans, type Scan, type NewScan } from '../schema/index.js';
import { generateScanId } from '@guardiant/shared';

/**
 * Create a new scan
 */
export async function createScan(
  db: Database,
  data: {
    target: string;
    type: 'url' | 'directory' | 'repository';
    config?: NewScan['config'];
  }
): Promise<Scan> {
  const id = generateScanId();
  const now = new Date().toISOString();

  const [scan] = await db.insert(scans).values({
    id,
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
 */
export async function getScan(db: Database, id: string): Promise<Scan | undefined> {
  const [scan] = await db.select().from(scans).where(eq(scans.id, id));
  return scan;
}

/**
 * Update a scan
 */
export async function updateScan(
  db: Database,
  id: string,
  data: Partial<Omit<NewScan, 'id'>>
): Promise<Scan | undefined> {
  const [scan] = await db
    .update(scans)
    .set(data)
    .where(eq(scans.id, id))
    .returning();
  return scan;
}

/**
 * Start a scan
 */
export async function startScan(db: Database, id: string): Promise<Scan | undefined> {
  const now = new Date().toISOString();
  return updateScan(db, id, {
    status: 'running',
    startedAt: now,
  });
}

/**
 * Complete a scan
 */
export async function completeScan(
  db: Database,
  id: string,
  duration: number
): Promise<Scan | undefined> {
  const now = new Date().toISOString();
  return updateScan(db, id, {
    status: 'completed',
    completedAt: now,
    duration,
  });
}

/**
 * Fail a scan
 */
export async function failScan(
  db: Database,
  id: string,
  error: string
): Promise<Scan | undefined> {
  const now = new Date().toISOString();
  return updateScan(db, id, {
    status: 'failed',
    completedAt: now,
    error,
  });
}

/**
 * Cancel a scan
 */
export async function cancelScan(db: Database, id: string): Promise<Scan | undefined> {
  const now = new Date().toISOString();
  return updateScan(db, id, {
    status: 'cancelled',
    completedAt: now,
  });
}

/**
 * List scans with pagination
 */
export async function listScans(
  db: Database,
  options: {
    status?: Scan['status'];
    limit?: number;
    offset?: number;
    orderBy?: 'createdAt' | 'updatedAt';
    order?: 'asc' | 'desc';
  } = {}
): Promise<Scan[]> {
  const {
    status,
    limit = 50,
    offset = 0,
    orderBy = 'createdAt',
    order = 'desc',
  } = options;

  let query = db.select().from(scans);

  if (status) {
    query = query.where(eq(scans.status, status)) as typeof query;
  }

  // Order by
  const orderColumn = orderBy === 'createdAt' ? scans.createdAt : scans.createdAt; // Only createdAt available
  const orderFn = order === 'asc' ? asc : desc;

  return query.orderBy(orderFn(orderColumn)).limit(limit).offset(offset);
}

/**
 * Count scans
 */
export async function countScans(
  db: Database,
  options: { status?: Scan['status'] } = {}
): Promise<number> {
  const { status } = options;

  let query = db.select({ count: sql<number>`count(*)` }).from(scans);

  if (status) {
    query = query.where(eq(scans.status, status)) as typeof query;
  }

  const [result] = await query;
  return result?.count ?? 0;
}

/**
 * Delete a scan
 */
export async function deleteScan(db: Database, id: string): Promise<boolean> {
  const [result] = await db.delete(scans).where(eq(scans.id, id)).returning();
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