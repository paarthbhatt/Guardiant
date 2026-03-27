import { eq, and, asc, sql } from 'drizzle-orm';
import type { Database } from '../connection.js';
import { agentRuns, type AgentRun, type NewAgentRun } from '../schema/index.js';
import { generateId } from '@guardiant/shared';
import type { AgentId, AgentStatus } from '@guardiant/shared';

/**
 * Create a new agent run
 */
export async function createAgentRun(
  db: Database,
  data: {
    scanId: string;
    agentId: AgentId;
  }
): Promise<AgentRun> {
  const id = generateId('agent_run');

  const [run] = await db.insert(agentRuns).values({
    id,
    scanId: data.scanId,
    agentId: data.agentId,
    status: 'pending',
  }).returning();

  if (!run) {
    throw new Error('Failed to create agent run');
  }

  return run;
}

/**
 * Get an agent run by ID
 */
export async function getAgentRun(db: Database, id: string): Promise<AgentRun | undefined> {
  const [run] = await db.select().from(agentRuns).where(eq(agentRuns.id, id));
  return run;
}

/**
 * Get agent run by scan and agent
 */
export async function getAgentRunByScanAndAgent(
  db: Database,
  scanId: string,
  agentId: AgentId
): Promise<AgentRun | undefined> {
  const [run] = await db
    .select()
    .from(agentRuns)
    .where(and(eq(agentRuns.scanId, scanId), eq(agentRuns.agentId, agentId)));
  return run;
}

/**
 * Update an agent run
 */
export async function updateAgentRun(
  db: Database,
  id: string,
  data: Partial<Omit<NewAgentRun, 'id'>>
): Promise<AgentRun | undefined> {
  const [run] = await db
    .update(agentRuns)
    .set(data)
    .where(eq(agentRuns.id, id))
    .returning();
  return run;
}

/**
 * Start an agent run
 */
export async function startAgentRun(db: Database, id: string): Promise<AgentRun | undefined> {
  const now = new Date().toISOString();
  return updateAgentRun(db, id, {
    status: 'running',
    startedAt: now,
  });
}

/**
 * Complete an agent run
 */
export async function completeAgentRun(
  db: Database,
  id: string,
  data: {
    tokensUsed?: number;
    requestsMade?: number;
    filesAnalyzed?: number;
    endpointsTested?: number;
    findingsCount: number;
    metadata?: Record<string, unknown>;
  }
): Promise<AgentRun | undefined> {
  const now = new Date().toISOString();

  // Calculate duration from startedAt
  const run = await getAgentRun(db, id);
  const duration = run?.startedAt
    ? new Date(now).getTime() - new Date(run.startedAt).getTime()
    : 0;

  return updateAgentRun(db, id, {
    status: 'completed',
    completedAt: now,
    duration,
    tokensUsed: data.tokensUsed,
    requestsMade: data.requestsMade,
    filesAnalyzed: data.filesAnalyzed,
    endpointsTested: data.endpointsTested,
    findingsCount: data.findingsCount,
    metadata: data.metadata,
  });
}

/**
 * Fail an agent run
 */
export async function failAgentRun(
  db: Database,
  id: string,
  error: string,
  stackTrace?: string
): Promise<AgentRun | undefined> {
  const now = new Date().toISOString();

  const run = await getAgentRun(db, id);
  const duration = run?.startedAt
    ? new Date(now).getTime() - new Date(run.startedAt).getTime()
    : 0;

  return updateAgentRun(db, id, {
    status: 'failed',
    completedAt: now,
    duration,
    error,
    stackTrace,
  });
}

/**
 * Get all agent runs for a scan
 */
export async function getAgentRunsByScan(
  db: Database,
  scanId: string
): Promise<AgentRun[]> {
  return db
    .select()
    .from(agentRuns)
    .where(eq(agentRuns.scanId, scanId))
    .orderBy(asc(agentRuns.agentId));
}

/**
 * Get agent runs by status
 */
export async function getAgentRunsByStatus(
  db: Database,
  scanId: string,
  status: AgentStatus
): Promise<AgentRun[]> {
  return db
    .select()
    .from(agentRuns)
    .where(and(eq(agentRuns.scanId, scanId), eq(agentRuns.status, status)));
}

/**
 * Get agent run statistics for a scan
 */
export async function getAgentRunStats(
  db: Database,
  scanId: string
): Promise<{
  total: number;
  pending: number;
  running: number;
  completed: number;
  failed: number;
  skipped: number;
  totalFindings: number;
  totalTokens: number;
  totalDuration: number;
}> {
  const [stats] = await db
    .select({
      total: sql<number>`count(*)`,
      pending: sql<number>`sum(case when status = 'pending' then 1 else 0 end)`,
      running: sql<number>`sum(case when status = 'running' then 1 else 0 end)`,
      completed: sql<number>`sum(case when status = 'completed' then 1 else 0 end)`,
      failed: sql<number>`sum(case when status = 'failed' then 1 else 0 end)`,
      skipped: sql<number>`sum(case when status = 'skipped' then 1 else 0 end)`,
      totalFindings: sql<number>`sum(findings_count)`,
      totalTokens: sql<number>`sum(tokens_used)`,
      totalDuration: sql<number>`sum(duration)`,
    })
    .from(agentRuns)
    .where(eq(agentRuns.scanId, scanId));

  return stats ?? {
    total: 0,
    pending: 0,
    running: 0,
    completed: 0,
    failed: 0,
    skipped: 0,
    totalFindings: 0,
    totalTokens: 0,
    totalDuration: 0,
  };
}