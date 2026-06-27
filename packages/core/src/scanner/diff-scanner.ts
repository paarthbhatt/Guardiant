import { execSync } from 'child_process';
import { resolve, isAbsolute } from 'path';
import { existsSync } from 'fs';

/**
 * Scans a git repository to find only files that have changed
 * relative to a base reference (branch, commit, or HEAD).
 */
export class DiffScanner {
  private targetDir: string;

  constructor(targetPath: string) {
    this.targetDir = isAbsolute(targetPath) ? targetPath : resolve(process.cwd(), targetPath);
  }

  /**
   * Check if the target is a git repository
   */
  public isGitRepo(): boolean {
    try {
      if (!existsSync(this.targetDir)) return false;
      execSync('git rev-parse --is-inside-work-tree', { 
        cwd: this.targetDir, 
        stdio: 'ignore' 
      });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get list of changed files relative to baseRef
   */
  public getChangedFiles(baseRef: string = 'HEAD~1'): string[] {
    if (!this.isGitRepo()) {
      return [];
    }

    try {
      // Get files changed in the working directory and staging area
      const uncommitted = execSync('git diff --name-only HEAD', { 
        cwd: this.targetDir,
        encoding: 'utf-8' 
      }).split('\n').filter(Boolean);

      // Get files changed between HEAD and baseRef
      const committed = execSync(`git diff --name-only ${baseRef} HEAD`, {
        cwd: this.targetDir,
        encoding: 'utf-8'
      }).split('\n').filter(Boolean);

      const allChanged = [...new Set([...uncommitted, ...committed])];
      
      // Resolve to absolute paths
      return allChanged.map(file => resolve(this.targetDir, file));
    } catch (e) {
      // If git diff fails (e.g. invalid ref), return empty array
      return [];
    }
  }
}
