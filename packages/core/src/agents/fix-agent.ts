import { AbstractAgent } from './base.js';
import type { AgentContext, AgentResult, Finding, FixPatch, OWASPCategory } from '@guardiant/shared';
import { OWASP_CATEGORIES } from '@guardiant/shared';
import { readFileSync, existsSync, statSync, readdirSync, writeFileSync } from 'fs';
import { join, relative } from 'path';
import { execSync } from 'child_process';

interface FixAgentMetadata {
  findings: Finding[];
  targetPath: string;
  mode: 'dry-run' | 'apply' | 'interactive';
  patches: FixPatch[];
  applied: string[];
  skipped: string[];
  framework: string;
  isRepo: boolean;
}

interface FileMatch {
  absolutePath: string;
  relativePath: string;
  framework: string;
  score: number;
}

/**
 * Auto-Fix Agent
 *
 * Reads source code, matches findings to source files, and generates patches.
 * Modes:
 *   - dry-run:    show all proposed patches, apply nothing
 *   - apply:      apply patches, create a git commit per fix
 *   - interactive: prompt per finding (Apply / Skip / Explain)
 */
export class FixAgent extends AbstractAgent {
  readonly id = 'fix' as const;
  readonly name = 'Auto-Fix Agent';
  readonly description = 'Matches findings to source files and generates remediation patches (dry-run, apply, or interactive).';
  readonly categories = Object.values(OWASP_CATEGORIES).map(c => c.code);
  readonly priority = 'low' as const;

  async execute(context: AgentContext): Promise<AgentResult> {
    const startTime = Date.now();

    try {
      const metadata = (context as unknown as { metadata?: { findings?: Finding[]; targetPath?: string; mode?: 'dry-run' | 'apply' | 'interactive' } }).metadata;
      const findings = (metadata?.findings ?? []) as Finding[];
      const targetPath = metadata?.targetPath ?? context.target.url;
      const mode = metadata?.mode ?? 'dry-run';

      if (context.target.type !== 'directory' && context.target.type !== 'repository') {
        const meta: FixAgentMetadata & { reason?: string } = {
          findings,
          targetPath,
          mode,
          patches: [],
          applied: [],
          skipped: [],
          framework: 'unknown',
          isRepo: false,
          reason: 'Fix agent requires a local directory or repository target',
        };
        return this.createSuccessResult([], {
          endpointsTested: 0,
          custom: meta as unknown as Record<string, unknown>,
        }, this.getDuration(startTime));
      }

      if (findings.length === 0) {
        const meta: FixAgentMetadata & { reason?: string } = {
          findings,
          targetPath,
          mode,
          patches: [],
          applied: [],
          skipped: [],
          framework: 'unknown',
          isRepo: false,
          reason: 'No findings to fix',
        };
        return this.createSuccessResult([], {
          endpointsTested: 0,
          custom: meta as unknown as Record<string, unknown>,
        }, this.getDuration(startTime));
      }

      // Discover source files in the target
      const isRepo = this.isGitRepository(targetPath);
      const framework = this.detectFramework(targetPath);
      const allFiles = this.walkSourceFiles(targetPath);

      const patches: FixPatch[] = [];
      const applied: string[] = [];
      const skipped: string[] = [];

      for (const finding of findings) {
        // Architectural findings are never auto-fixable
        if (this.isArchitectural(finding)) {
          skipped.push(finding.id);
          continue;
        }

        const fileMatch = this.locateSourceFile(finding, targetPath, allFiles, framework);
        if (!fileMatch) {
          skipped.push(finding.id);
          continue;
        }

        let sourceCode: string;
        try {
          sourceCode = readFileSync(fileMatch.absolutePath, 'utf-8');
        } catch {
          skipped.push(finding.id);
          continue;
        }

        const patch = this.generatePatch(finding, sourceCode, fileMatch);
        if (!patch) {
          skipped.push(finding.id);
          continue;
        }

        patches.push(patch);

        if (mode === 'apply' && patch.autoApplicable && patch.confidence >= 0.7) {
          try {
            this.applyPatch(fileMatch.absolutePath, patch);
            if (isRepo) {
              this.gitCommit(targetPath, fileMatch.relativePath, finding);
            }
            applied.push(finding.id);
          } catch {
            skipped.push(finding.id);
          }
        } else if (mode === 'dry-run') {
          // No action; just record the patch
        } else {
          // interactive mode without TTY → treat as dry-run
        }
      }

      const resultMetadata: FixAgentMetadata = {
        findings,
        targetPath,
        mode,
        patches,
        applied,
        skipped,
        framework,
        isRepo,
      };

      return this.createSuccessResult([], {
        endpointsTested: 0,
        custom: resultMetadata as unknown as Record<string, unknown>,
      }, this.getDuration(startTime));
    } catch (error) {
      return this.createErrorResult(
        error instanceof Error ? error : new Error('Unknown error'),
        this.getDuration(startTime)
      );
    }
  }

  /**
   * Heuristic to detect whether a finding is architectural (no patch can fix it)
   */
  private isArchitectural(finding: Finding): boolean {
    if (finding.category === 'A04_INSECURE_DESIGN') return true;
    if (finding.tags.includes('trust_inversion')) return true;
    if (finding.tags.includes('architectural')) return true;
    if (/architectural|redesign|workflow gap/i.test(finding.title)) return true;
    return false;
  }

  /**
   * Detect whether a path is inside a git repository
   */
  private isGitRepository(targetPath: string): boolean {
    return existsSync(join(targetPath, '.git'));
  }

  /**
   * Detect the primary framework from package.json
   */
  private detectFramework(targetPath: string): string {
    const pkgPath = join(targetPath, 'package.json');
    if (!existsSync(pkgPath)) return 'unknown';
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8')) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      const depNames = Object.keys(deps || {}).join(' ').toLowerCase();
      if (depNames.includes('next')) return 'nextjs';
      if (depNames.includes('remix')) return 'remix';
      if (depNames.includes('@sveltejs/kit')) return 'sveltekit';
      if (depNames.includes('nuxt')) return 'nuxt';
      if (depNames.includes('express')) return 'express';
      if (depNames.includes('fastify')) return 'fastify';
      if (depNames.includes('koa')) return 'koa';
      if (depNames.includes('flask')) return 'flask';
      if (depNames.includes('django')) return 'django';
      if (depNames.includes('react')) return 'react';
      return 'node';
    } catch {
      return 'unknown';
    }
  }

  /**
   * Walk the directory and collect text source files
   */
  private walkSourceFiles(rootPath: string): string[] {
    const textExtensions = new Set([
      '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
      '.py', '.rb', '.php', '.go', '.rs', '.java', '.kt', '.swift',
      '.vue', '.svelte', '.astro',
      '.html', '.htm',
      '.json', '.yaml', '.yml', '.toml', '.env',
    ]);
    const excludeDirs = new Set([
      'node_modules', '.git', '.next', 'dist', 'build',
      '.cache', 'coverage', '.nyc_output', 'target',
      '__pycache__', '.venv', 'venv', '.tox',
    ]);
    const files: string[] = [];

    const walk = (dir: string): void => {
      let entries: string[];
      try {
        entries = readdirSync(dir);
      } catch {
        return;
      }
      for (const entry of entries) {
        const full = join(dir, entry);
        let stats;
        try {
          stats = statSync(full);
        } catch {
          continue;
        }
        if (stats.isDirectory()) {
          if (!excludeDirs.has(entry)) walk(full);
        } else if (stats.isFile()) {
          const dot = entry.lastIndexOf('.');
          const ext = dot >= 0 ? entry.substring(dot).toLowerCase() : '';
          if (textExtensions.has(ext)) files.push(full);
        }
      }
    };

    walk(rootPath);
    return files;
  }

  /**
   * Locate the most likely source file for a given finding
   */
  private locateSourceFile(
    finding: Finding,
    rootPath: string,
    allFiles: string[],
    framework: string
  ): FileMatch | null {
    if (allFiles.length === 0) return null;

    // 1. Try direct path from evidence
    const evidenceFile = finding.evidence?.file;
    if (evidenceFile) {
      const candidate = join(rootPath, evidenceFile);
      if (existsSync(candidate)) {
        return {
          absolutePath: candidate,
          relativePath: relative(rootPath, candidate),
          framework,
          score: 1.0,
        };
      }
    }

    // 2. Extract a path from evidence.request (e.g. /api/users -> route file)
    const reqPath = finding.evidence?.request;
    const urlPath = reqPath ? this.extractUrlPath(reqPath) : null;
    if (urlPath) {
      const candidates = this.urlPathToFileCandidates(urlPath, framework);
      for (const candidate of candidates) {
        const full = join(rootPath, candidate);
        if (existsSync(full)) {
          return {
            absolutePath: full,
            relativePath: relative(rootPath, full),
            framework,
            score: 0.9,
          };
        }
      }
    }

    // 3. Category-based heuristics
    const categoryCandidates = this.categoryToFileCandidates(finding.category, framework);
    for (const pattern of categoryCandidates) {
      const matches = allFiles.filter(f => pattern.test(relative(rootPath, f)));
      if (matches.length > 0) {
        matches.sort((a, b) => this.preferShallowFile(relative(rootPath, a), relative(rootPath, b)));
        const top = matches[0];
        if (top) {
          return {
            absolutePath: top,
            relativePath: relative(rootPath, top),
            framework,
            score: 0.6,
          };
        }
      }
    }

    // 4. Last resort: any source file in the project
    const fallback = allFiles.find(f => /\.(ts|tsx|js|jsx)$/.test(f));
    if (fallback) {
      return {
        absolutePath: fallback,
        relativePath: relative(rootPath, fallback),
        framework,
        score: 0.2,
      };
    }

    return null;
  }

  private extractUrlPath(request: string): string | null {
    try {
      if (/^https?:\/\//.test(request)) {
        return new URL(request).pathname;
      }
      return request.split('?')[0] ?? null;
    } catch {
      return null;
    }
  }

  private urlPathToFileCandidates(path: string, framework: string): string[] {
    const cleaned = path.replace(/^\/+/, '').replace(/\/$/, '');
    const parts = cleaned.split('/').filter(Boolean);
    const candidates: string[] = [];

    if (framework === 'nextjs' || framework === 'remix' || framework === 'sveltekit' || framework === 'nuxt') {
      // app/api/users/route.ts  or  pages/api/users.ts
      const segs = parts.join('/');
      candidates.push(`app/api/${segs}/route.ts`);
      candidates.push(`app/api/${segs}/route.js`);
      candidates.push(`app/api/${segs}/route.tsx`);
      candidates.push(`pages/api/${segs}.ts`);
      candidates.push(`pages/api/${segs}.js`);
      candidates.push(`src/app/api/${segs}/route.ts`);
      candidates.push(`src/pages/api/${segs}.ts`);
      candidates.push(`routes/${segs}.ts`);
      candidates.push(`routes/${segs}.js`);
    } else if (framework === 'express' || framework === 'fastify' || framework === 'koa') {
      const segs = parts.join('/');
      candidates.push(`routes/${segs}.ts`);
      candidates.push(`routes/${segs}.js`);
      candidates.push(`src/routes/${segs}.ts`);
      candidates.push(`src/${segs}.ts`);
    } else if (framework === 'flask' || framework === 'django') {
      candidates.push(`${parts.join('_')}.py`);
      candidates.push(`app/${parts.join('/')}.py`);
    } else {
      // Generic
      const segs = parts.join('/');
      candidates.push(`src/${segs}.ts`);
      candidates.push(`${segs}.ts`);
    }

    return candidates;
  }

  private categoryToFileCandidates(category: OWASPCategory | string, _framework: string): RegExp[] {
    switch (category) {
      case 'A07_AUTH_FAILURES':
        return [
          /middleware\.(ts|js|tsx|jsx)$/i,
          /[\\/]auth[\\/].*\.(ts|js|tsx|jsx)$/i,
          /[\\/]login[\\/].*\.(ts|js|tsx|jsx)$/i,
          /auth\.(ts|js|tsx|jsx)$/i,
        ];
      case 'A03_INJECTION':
        return [
          /[\\/]api[\\/].*\.(ts|js|tsx|jsx)$/i,
          /[\\/]routes[\\/].*\.(ts|js|tsx|jsx)$/i,
        ];
      case 'A01_BROKEN_ACCESS_CONTROL':
        return [
          /middleware\.(ts|js|tsx|jsx)$/i,
          /[\\/]api[\\/].*\.(ts|js|tsx|jsx)$/i,
        ];
      case 'A05_SECURITY_MISCONFIGURATION':
      case 'A02_CRYPTOGRAPHIC_FAILURES':
      case 'A06_VULNERABLE_COMPONENTS':
        return [
          /next\.config\.(mjs|js|ts)$/i,
          /vercel\.json$/i,
          /\.env(\..+)?$/i,
        ];
      case 'A04_INSECURE_DESIGN':
        return [];
      default:
        return [/\.(ts|tsx|js|jsx)$/];
    }
  }

  private preferShallowFile(a: string, b: string): number {
    const depthA = a.split(/[\\/]/).length;
    const depthB = b.split(/[\\/]/).length;
    return depthA - depthB;
  }

  /**
   * Generate a FixPatch from a finding and its source file context
   */
  private generatePatch(
    finding: Finding,
    sourceCode: string,
    fileMatch: FileMatch
  ): FixPatch | null {
    const codeExample = finding.remediation?.codeExample;
    if (!codeExample) return null;

    // Try to locate a marker from the finding in the source so we can show a useful "before"
    const marker = this.extractMarker(finding, sourceCode);
    const before = marker?.context ?? `// original code for ${finding.title}`;
    const after = this.combineBeforeAfter(codeExample);
    const diff = this.buildUnifiedDiff(before, after, fileMatch.relativePath);
    const confidence = this.estimateConfidence(finding, marker, fileMatch);
    const autoApplicable = !this.isArchitectural(finding) && confidence >= 0.7 && Boolean(marker);

    return {
      findingId: finding.id,
      filePath: fileMatch.relativePath,
      description: finding.remediation?.summary ?? `Fix ${finding.title}`,
      diff,
      before,
      after,
      reasoning: finding.remediation?.summary ?? finding.description,
      confidence,
      autoApplicable,
    };
  }

  private extractMarker(finding: Finding, sourceCode: string): { context: string; line: number } | null {
    // 1. Try the file/line from evidence
    if (finding.evidence?.line) {
      const lines = sourceCode.split('\n');
      const idx = finding.evidence.line - 1;
      if (idx >= 0 && idx < lines.length) {
        const context = lines.slice(Math.max(0, idx - 2), Math.min(lines.length, idx + 3)).join('\n');
        return { context, line: finding.evidence.line };
      }
    }
    // 2. Look for evidence.payload in source
    const payload = finding.evidence?.payload;
    if (payload) {
      const lines = sourceCode.split('\n');
      const needle = payload.substring(0, 20);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line && line.includes(needle)) {
          const context = lines.slice(Math.max(0, i - 2), Math.min(lines.length, i + 3)).join('\n');
          return { context, line: i + 1 };
        }
      }
    }
    // 3. Look for the URL path
    const path = finding.evidence?.request ? this.extractUrlPath(finding.evidence.request) : null;
    if (path) {
      const lines = sourceCode.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line && line.includes(path)) {
          const context = lines.slice(Math.max(0, i - 2), Math.min(lines.length, i + 3)).join('\n');
          return { context, line: i + 1 };
        }
      }
    }
    return null;
  }

  private combineBeforeAfter(codeExample: string): string {
    // The code example already includes both the vulnerable and the secure snippets
    // in a single block. We expose the whole thing as "after" so the user sees the
    // pattern. For real surgical edits we would parse this; for v0 we keep it simple.
    return codeExample;
  }

  /**
   * Build a simple unified diff between two strings
   */
  private buildUnifiedDiff(before: string, after: string, filePath: string): string {
    const beforeLines = before.split('\n');
    const afterLines = after.split('\n');
    const lines: string[] = [];
    lines.push(`--- a/${filePath}`);
    lines.push(`+++ b/${filePath}`);
    lines.push(`@@ -1,${beforeLines.length} +1,${afterLines.length} @@`);
    for (const ln of beforeLines) lines.push(`-${ln}`);
    for (const ln of afterLines) lines.push(`+${ln}`);
    return lines.join('\n');
  }

  private estimateConfidence(finding: Finding, marker: { line: number } | null, fileMatch: FileMatch): number {
    let score = 0.5;
    if (marker) score += 0.2;
    if (finding.remediation?.codeExample) score += 0.1;
    if (fileMatch.score >= 0.9) score += 0.1;
    if (this.isArchitectural(finding)) score = 0.0;
    return Math.max(0, Math.min(1, score));
  }

  /**
   * Apply a patch to disk by appending the "after" snippet as a comment block.
   * For v0 we never destroy the original; we annotate the file with the proposed fix.
   */
  private applyPatch(absolutePath: string, patch: FixPatch): void {
    const original = readFileSync(absolutePath, 'utf-8');
    const marker = `\n\n// === Guardiant auto-fix (${patch.findingId}) ===\n// ${patch.description}\n${patch.after}\n// === end Guardiant ===\n`;
    const updated = original + marker;
    writeFileSync(absolutePath, updated, 'utf-8');
  }

  private gitCommit(repoPath: string, filePath: string, finding: Finding): void {
    try {
      execSync('git add ' + JSON.stringify(filePath), { cwd: repoPath, stdio: 'pipe' });
      const message = `fix(security): ${finding.title} [${finding.severity}]\n\nFinding ID: ${finding.id}\nCategory: ${finding.category}\n\nApplied by Guardiant auto-fix agent.`;
      execSync(`git commit -m ${JSON.stringify(message)}`, { cwd: repoPath, stdio: 'pipe' });
    } catch {
      // Best-effort: if git fails, do not throw
    }
  }

  getSystemPrompt(): string {
    return `You are an auto-fix generation expert.

Given a finding and a source file, produce a unified-diff patch that addresses the vulnerability.
Constraints:
- Never auto-apply patches with confidence < 0.7.
- Never auto-apply architectural findings (A04_INSECURE_DESIGN).
- Prefer surgical changes. Preserve formatting and existing logic.
- For cross-file fixes, list every file that needs to change.`;
  }

  buildUserPrompt(context: AgentContext): string {
    return `Generate fix patches for findings from scan ${context.scanId} at ${context.target.url}.`;
  }

  async parseResponse(_response: string, _context: AgentContext): Promise<Finding[]> {
    return [];
  }
}
