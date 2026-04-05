import { drizzle, BetterSQLite3Database } from 'drizzle-orm/better-sqlite3';
import * as schema from './schema/index.js';

/**
 * SQLite database connection type
 */
export type SqliteDatabase = any; // Dynamically loaded better-sqlite3 instance
export type Database = BetterSQLite3Database<typeof schema>;

/**
 * Create a new database connection
 * Uses dynamic import to allow optional better-sqlite3 dependency on Windows
 */
export async function createDatabase(dbPath: string = ':memory:'): Promise<{ db: Database; sqlite: SqliteDatabase }> {
  let DatabaseModule: any;
  
  try {
    // Dynamically import better-sqlite3 (may fail on Windows without build tools)
    const betterSqlite = await import('better-sqlite3');
    DatabaseModule = betterSqlite.default || betterSqlite;
  } catch (error) {
    throw new Error(
      'SQLite driver not available. ' +
      'On Windows, install Visual Studio Build Tools or use WSL2. ' +
      'See: https://github.com/WiseLibs/better-sqlite3#installation'
    );
  }

  const sqlite = new DatabaseModule(dbPath);

  // Enable WAL mode for better performance
  sqlite.pragma('journal_mode = WAL');

  // Enable foreign keys
  sqlite.pragma('foreign_keys = ON');

  const db = drizzle(sqlite, { schema });

  return { db, sqlite };
}