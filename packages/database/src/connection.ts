import { drizzle, BetterSQLite3Database } from 'drizzle-orm/better-sqlite3';
import Database from 'better-sqlite3';
import * as schema from './schema/index.js';

/**
 * SQLite database connection type
 */
export type SqliteDatabase = Database.Database;
export type Database = BetterSQLite3Database<typeof schema>;

/**
 * Create a new database connection
 */
export function createDatabase(dbPath: string = ':memory:'): { db: Database; sqlite: SqliteDatabase } {
  const sqlite = new Database(dbPath);

  // Enable WAL mode for better performance
  sqlite.pragma('journal_mode = WAL');

  // Enable foreign keys
  sqlite.pragma('foreign_keys = ON');

  const db = drizzle(sqlite, { schema });

  return { db, sqlite };
}

/**
 * Initialize the database schema
 */
export function initializeDatabase(sqlite: SqliteDatabase): void {
  // Create tables
  sqlite.exec(`
    -- Scans table
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      target TEXT NOT NULL,
      type TEXT NOT NULL CHECK(type IN ('url', 'directory', 'repository')),
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
      created_at TEXT NOT NULL,
      started_at TEXT,
      completed_at TEXT,
      config TEXT,
      error TEXT,
      duration INTEGER
    );

    CREATE INDEX IF NOT EXISTS scans_status_idx ON scans(status);
    CREATE INDEX IF NOT EXISTS scans_created_at_idx ON scans(created_at);

    -- Findings table
    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      agent_id TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
      category TEXT NOT NULL,
      cvss_score REAL NOT NULL,
      confidence REAL NOT NULL,
      status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'confirmed', 'false_positive', 'fixed', 'wont_fix')),
      timestamp TEXT NOT NULL,
      evidence TEXT NOT NULL,
      remediation TEXT NOT NULL,
      tags TEXT NOT NULL DEFAULT '[]',
      cvc_chain_id TEXT REFERENCES compound_chains(id),
      vcvf_pattern TEXT,
      tief_indicator TEXT,
      metadata TEXT
    );

    CREATE INDEX IF NOT EXISTS findings_scan_idx ON findings(scan_id);
    CREATE INDEX IF NOT EXISTS findings_severity_idx ON findings(severity);
    CREATE INDEX IF NOT EXISTS findings_category_idx ON findings(category);
    CREATE INDEX IF NOT EXISTS findings_agent_idx ON findings(agent_id);

    -- Agent runs table
    CREATE TABLE IF NOT EXISTS agent_runs (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      agent_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'running', 'completed', 'failed', 'skipped')),
      started_at TEXT,
      completed_at TEXT,
      duration INTEGER,
      tokens_used INTEGER,
      requests_made INTEGER DEFAULT 0,
      files_analyzed INTEGER DEFAULT 0,
      endpoints_tested INTEGER DEFAULT 0,
      findings_count INTEGER DEFAULT 0,
      error TEXT,
      stack_trace TEXT,
      metadata TEXT
    );

    CREATE INDEX IF NOT EXISTS agent_runs_scan_idx ON agent_runs(scan_id);
    CREATE INDEX IF NOT EXISTS agent_runs_agent_idx ON agent_runs(agent_id);
    CREATE INDEX IF NOT EXISTS agent_runs_status_idx ON agent_runs(status);

    -- Compound chains table
    CREATE TABLE IF NOT EXISTS compound_chains (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      finding_ids TEXT NOT NULL,
      compound_severity TEXT NOT NULL CHECK(compound_severity IN ('critical', 'high', 'medium', 'low', 'info')),
      compound_cvss_score REAL NOT NULL,
      exploit_path TEXT NOT NULL,
      attack_steps TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS compound_chains_scan_idx ON compound_chains(scan_id);
    CREATE INDEX IF NOT EXISTS compound_chains_severity_idx ON compound_chains(compound_severity);

    -- VCVF fingerprints table
    CREATE TABLE IF NOT EXISTS vcvf_fingerprints (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      pattern_type TEXT NOT NULL,
      confidence REAL NOT NULL,
      evidence TEXT NOT NULL,
      locations TEXT NOT NULL,
      predicted_vulnerabilities TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS vcvf_fingerprints_scan_idx ON vcvf_fingerprints(scan_id);
    CREATE INDEX IF NOT EXISTS vcvf_fingerprints_pattern_idx ON vcvf_fingerprints(pattern_type);

    -- Trust inversions table
    CREATE TABLE IF NOT EXISTS trust_inversions (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      type TEXT NOT NULL CHECK(type IN ('frontend_auth_logic', 'direct_database_access', 'client_secrets', 'missing_server_validation', 'over_permissive_cors', 'insecure_defaults')),
      misplaced_trust TEXT NOT NULL,
      expected_boundary TEXT NOT NULL,
      actual_boundary TEXT NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
      finding_ids TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS trust_inversions_scan_idx ON trust_inversions(scan_id);
    CREATE INDEX IF NOT EXISTS trust_inversions_type_idx ON trust_inversions(type);

    -- Reports table
    CREATE TABLE IF NOT EXISTS reports (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      audience TEXT NOT NULL CHECK(audience IN ('executive', 'developer', 'security')),
      format TEXT NOT NULL CHECK(format IN ('json', 'markdown', 'html', 'pdf')),
      content TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS reports_scan_idx ON reports(scan_id);
  `);
}

/**
 * Close database connection
 */
export function closeDatabase(sqlite: SqliteDatabase): void {
  sqlite.close();
}

/**
 * Default database path
 */
export const DEFAULT_DB_PATH = 'guardiant.db';