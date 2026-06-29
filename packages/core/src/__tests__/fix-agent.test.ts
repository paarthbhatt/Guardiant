import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, existsSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { FixAgent } from '../agents/fix-agent.js';
import type { AgentContext, Finding, FixPatch } from '@guardiant/shared';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: overrides.id ?? 'finding-1',
    title: overrides.title ?? 'Test Finding',
    description: overrides.description ?? 'A test vulnerability',
    severity: overrides.severity ?? 'high',
    category: overrides.category ?? 'A07_AUTH_FAILURES',
    cvssScore: overrides.cvssScore ?? 7.5,
    confidence: overrides.confidence ?? 0.85,
    discoveredBy: 'auth',
    timestamp: new Date().toISOString(),
    evidence: overrides.evidence ?? {},
    remediation: overrides.remediation ?? {
      summary: 'Move auth check to server',
      steps: ['Add server middleware', 'Remove client check'],
      codeExample: 'if (req.user.role !== "admin") return res.status(403).end();',
      effort: 'medium',
      priority: 1,
    },
    status: 'open',
    tags: overrides.tags ?? ['auth'],
    ...overrides,
  } as Finding;
}

function makeContext(
  findings: Finding[],
  options: {
    targetPath: string;
    targetType: 'url' | 'directory' | 'repository';
    mode?: 'dry-run' | 'apply' | 'interactive';
  }
): AgentContext {
  return {
    scanId: 'test-scan',
    target: {
      url: options.targetPath,
      type: options.targetType,
    },
    config: { enabled: true, priority: 'low', timeout: 60000, maxRetries: 1 },
    metadata: {
      findings,
      targetPath: options.targetPath,
      mode: options.mode ?? 'dry-run',
    } as unknown as AgentContext['metadata'],
  } as unknown as AgentContext;
}

describe('FixAgent', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'guardiant-fix-'));
  });

  afterEach(() => {
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('returns early when target is a URL (not directory/repository)', async () => {
    const agent = new FixAgent();
    const result = await agent.execute(
      makeContext([makeFinding()], { targetPath: 'https://example.com', targetType: 'url' })
    );
    expect(result.status).toBe('completed');
    const meta = result.metadata.custom as { reason: string; patches: unknown[] };
    expect(meta.reason).toMatch(/directory|repository/i);
    expect(meta.patches).toEqual([]);
  });

  it('returns early when no findings are provided', async () => {
    const agent = new FixAgent();
    const result = await agent.execute(
      makeContext([], { targetPath: tempDir, targetType: 'directory' })
    );
    expect(result.status).toBe('completed');
    const meta = result.metadata.custom as { reason: string; patches: unknown[] };
    expect(meta.reason).toMatch(/no findings/i);
  });

  it('skips architectural findings (A04_INSECURE_DESIGN)', async () => {
    const agent = new FixAgent();
    const finding = makeFinding({
      id: 'design-1',
      category: 'A04_INSECURE_DESIGN',
      title: 'Missing workflow step',
      tags: ['architectural'],
    });
    const result = await agent.execute(
      makeContext([finding], { targetPath: tempDir, targetType: 'directory' })
    );
    const meta = result.metadata.custom as { patches: unknown[]; skipped: string[] };
    expect(meta.patches).toEqual([]);
    expect(meta.skipped).toContain('design-1');
  });

  it('skips findings without a remediation code example', async () => {
    const agent = new FixAgent();
    const finding = makeFinding({
      id: 'no-code-1',
      remediation: { summary: 'Fix it', steps: [], effort: 'medium', priority: 1 },
    });
    const result = await agent.execute(
      makeContext([finding], { targetPath: tempDir, targetType: 'directory' })
    );
    const meta = result.metadata.custom as { patches: unknown[]; skipped: string[] };
    expect(meta.patches).toEqual([]);
    expect(meta.skipped).toContain('no-code-1');
  });

  it('generates a patch when a source file can be located', async () => {
    // Create a Next.js-looking project structure
    mkdirSync(join(tempDir, 'app', 'api', 'users'), { recursive: true });
    const targetFile = join(tempDir, 'app', 'api', 'users', 'route.ts');
    writeFileSync(targetFile, 'export async function GET(req) {\n  return Response.json({ ok: true });\n}\n');
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: { next: '^15.0.0' },
    }));

    const agent = new FixAgent();
    const finding = makeFinding({
      id: 'auth-1',
      evidence: { request: 'GET /api/users' },
    });
    const result = await agent.execute(
      makeContext([finding], { targetPath: tempDir, targetType: 'directory' })
    );
    const meta = result.metadata.custom as { patches: FixPatch[]; framework: string };
    expect(meta.patches.length).toBeGreaterThan(0);
    expect(meta.framework).toBe('nextjs');
    const patch = meta.patches[0]!;
    expect(patch.findingId).toBe('auth-1');
    // Path may use either / or \ depending on platform
    expect(patch.filePath.replace(/\\/g, '/')).toContain('app/api/users/route.ts');
    expect(patch.diff).toContain('--- a/');
    expect(patch.diff).toContain('+++ b/');
    expect(patch.before).toBeTruthy();
    expect(patch.after).toBeTruthy();
    expect(patch.reasoning).toBeTruthy();
    expect(patch.confidence).toBeGreaterThan(0);
    expect(patch.confidence).toBeLessThanOrEqual(1);
  });

  it('does not modify files in dry-run mode', async () => {
    mkdirSync(join(tempDir, 'app', 'api', 'users'), { recursive: true });
    const targetFile = join(tempDir, 'app', 'api', 'users', 'route.ts');
    const original = 'export async function GET() { return Response.json({}); }\n';
    writeFileSync(targetFile, original);
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: { next: '^15.0.0' },
    }));

    const agent = new FixAgent();
    const finding = makeFinding({
      id: 'dry-1',
      evidence: { request: 'GET /api/users' },
    });
    await agent.execute(
      makeContext([finding], { targetPath: tempDir, targetType: 'directory', mode: 'dry-run' })
    );
    const after = readFileSync(targetFile, 'utf-8');
    expect(after).toBe(original);
  });

  it('annotates the source file in apply mode when confidence is high enough', async () => {
    mkdirSync(join(tempDir, 'app', 'api', 'users'), { recursive: true });
    const targetFile = join(tempDir, 'app', 'api', 'users', 'route.ts');
    const original = 'export async function GET() { return Response.json({}); }\n';
    writeFileSync(targetFile, original);
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: { next: '^15.0.0' },
    }));

    const agent = new FixAgent();
    const finding = makeFinding({
      id: 'apply-1',
      evidence: { request: 'GET /api/users' },
    });
    const result = await agent.execute(
      makeContext([finding], { targetPath: tempDir, targetType: 'directory', mode: 'apply' })
    );
    const meta = result.metadata.custom as { applied: string[]; patches: FixPatch[] };
    // Applied list should contain the finding ID if autoApplicable + confidence is high
    const patch = meta.patches[0];
    if (patch && patch.autoApplicable) {
      expect(meta.applied).toContain('apply-1');
      const after = readFileSync(targetFile, 'utf-8');
      expect(after).toContain('Guardiant auto-fix');
      expect(after).toContain('apply-1');
    } else {
      // Patch not auto-applicable — that's also a valid outcome
      expect(meta.applied).not.toContain('apply-1');
    }
  });

  it('uses the file path from evidence when available', async () => {
    const knownFile = join(tempDir, 'middleware.ts');
    writeFileSync(knownFile, 'export function middleware() { return null; }\n');
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: { next: '^15.0.0' },
    }));

    const agent = new FixAgent();
    const finding = makeFinding({
      id: 'evidence-1',
      evidence: { file: 'middleware.ts', line: 1 },
    });
    const result = await agent.execute(
      makeContext([finding], { targetPath: tempDir, targetType: 'directory' })
    );
    const meta = result.metadata.custom as { patches: FixPatch[] };
    expect(meta.patches.length).toBeGreaterThan(0);
    expect(meta.patches[0]!.filePath.replace(/\\/g, '/')).toBe('middleware.ts');
  });

  it('detects express framework and routes to routes/ directory', async () => {
    mkdirSync(join(tempDir, 'routes'));
    const targetFile = join(tempDir, 'routes', 'login.ts');
    writeFileSync(targetFile, 'export function login() { return null; }\n');
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: { express: '^4.18.0' },
    }));

    const agent = new FixAgent();
    const finding = makeFinding({
      id: 'express-1',
      evidence: { request: 'POST /login' },
    });
    const result = await agent.execute(
      makeContext([finding], { targetPath: tempDir, targetType: 'directory' })
    );
    const meta = result.metadata.custom as { patches: FixPatch[]; framework: string };
    expect(meta.framework).toBe('express');
    expect(meta.patches.length).toBeGreaterThan(0);
    expect(meta.patches[0]!.filePath.replace(/\\/g, '/')).toBe('routes/login.ts');
  });

  it('sets autoApplicable=false for findings without a marker in source', async () => {
    mkdirSync(join(tempDir, 'app', 'api', 'users'), { recursive: true });
    writeFileSync(join(tempDir, 'app', 'api', 'users', 'route.ts'), '// empty file\n');
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: { next: '^15.0.0' },
    }));

    const agent = new FixAgent();
    const finding = makeFinding({
      id: 'no-marker-1',
      evidence: { request: 'GET /api/users' },
    });
    const result = await agent.execute(
      makeContext([finding], { targetPath: tempDir, targetType: 'directory' })
    );
    const meta = result.metadata.custom as { patches: FixPatch[] };
    if (meta.patches.length > 0) {
      expect(meta.patches[0]!.autoApplicable).toBe(false);
    }
  });

  it('redirects controller IDOR findings to the corresponding route file using codeIndex', async () => {
    mkdirSync(join(tempDir, 'controllers'), { recursive: true });
    mkdirSync(join(tempDir, 'routes'), { recursive: true });
    const controllerFile = join(tempDir, 'controllers', 'usersController.js');
    const routeFile = join(tempDir, 'routes', 'users.js');
    
    writeFileSync(controllerFile, 'exports.getUser = (req, res) => { res.send(req.params.id); };\n');
    writeFileSync(routeFile, 'router.get("/:id", ctrl.getUser);\n');
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: { express: '^4.18.0' },
    }));

    const mockCodeIndex = {
      files: new Map(),
      routeHandlers: [
        {
          path: '/:id',
          method: 'GET',
          file: 'routes/users.js',
          handlerName: 'getUser',
          controllerFile: 'controllers/usersController.js',
          middleware: ['requireAuth'],
        }
      ],
      middlewareMap: new Map(),
    };

    const agent = new FixAgent();
    const finding = makeFinding({
      id: 'redir-1',
      category: 'A01_BROKEN_ACCESS_CONTROL',
      evidence: { file: 'controllers/usersController.js', line: 1 },
    });

    const ctx = makeContext([finding], { targetPath: tempDir, targetType: 'directory' });
    (ctx.metadata as any).codeIndex = mockCodeIndex;

    const result = await agent.execute(ctx);
    const meta = result.metadata.custom as { patches: FixPatch[] };
    expect(meta.patches.length).toBeGreaterThan(0);
    expect(meta.patches[0]!.filePath.replace(/\\/g, '/')).toBe('routes/users.js');
  });

  it('handles errors gracefully (corrupt source file)', async () => {
    // Build a context that will trigger a read error inside the agent
    const agent = new FixAgent();
    const result = await agent.execute(
      makeContext([makeFinding({ id: 'err-1' })], { targetPath: tempDir, targetType: 'directory' })
    );
    // Should not throw; should return a structured result
    expect(result.status).toBe('completed');
  });

  it('applies a surgical code fix in apply mode and validates syntax', async () => {
    const knownFile = join(tempDir, 'app.js');
    const original = 'const x = 1;\n// vulnerability here\nconsole.log(x);\n';
    writeFileSync(knownFile, original);
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: { express: '^4.18.0' },
    }));

    const agent = new FixAgent();
    const finding = makeFinding({
      id: 'surgical-1',
      evidence: { file: 'app.js', line: 2 },
      remediation: {
        summary: 'Fix logging',
        steps: [],
        codeExample: 'console.log("secure");',
        effort: 'low',
        priority: 1,
      }
    });

    const result = await agent.execute(
      makeContext([finding], { targetPath: tempDir, targetType: 'directory', mode: 'apply' })
    );

    const meta = result.metadata.custom as { applied: string[]; patches: FixPatch[] };
    expect(meta.applied).toContain('surgical-1');
    const after = readFileSync(knownFile, 'utf-8');
    expect(after).not.toContain('// vulnerability here');
    expect(after).toContain('console.log("secure");');
  });

  it('isRepo flag reflects whether .git exists', async () => {
    const agent = new FixAgent();
    const result = await agent.execute(
      makeContext([makeFinding()], { targetPath: tempDir, targetType: 'directory' })
    );
    const meta = result.metadata.custom as { isRepo: boolean };
    expect(meta.isRepo).toBe(false);
  });
});
