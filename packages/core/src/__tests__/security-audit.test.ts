import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import * as childProcess from 'child_process';
import { DiffScanner } from '../scanner/diff-scanner.js';
import { FixAgent } from '../agents/fix-agent.js';
import { CriticAgent } from '../agents/critic-agent.js';
import { PayloadGenerator } from '../agents/payload-generator.js';
import { buildCodeIndex } from '../indexer/code-index.js';
import { createHttpClient } from '../http/index.js';
import type { LLMClient } from '../llm/client.js';
import type { AgentContext, Finding } from '@guardiant/shared';
import { resolveExistingPathWithinRoot } from '../security/path-safety.js';

vi.mock('child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('child_process')>();
  return { ...actual, execFileSync: vi.fn(actual.execFileSync) };
});

const tempDirs: string[] = [];
const markerFiles: string[] = [];

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv('GUARDIANT_ENABLE_AI', '0');
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  for (const file of markerFiles.splice(0)) {
    if (existsSync(file)) rmSync(file, { force: true });
  }
  for (const dir of tempDirs.splice(0)) {
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  }
});

function makeFixContext(targetPath: string, finding: Finding): AgentContext {
  return {
    scanId: 'audit-test',
    target: { url: targetPath, type: 'directory' },
    config: { enabled: true, priority: 'low', timeout: 60_000, maxRetries: 1 },
    metadata: {
      findings: [finding],
      targetPath,
      mode: 'apply',
    },
  } as unknown as AgentContext;
}

function makeFinding(file: string): Finding {
  return {
    id: 'audit-finding',
    title: 'Audit test finding',
    description: 'Test finding for audit regression coverage',
    severity: 'high',
    category: 'A07_AUTH_FAILURES',
    cvssScore: 7.5,
    confidence: 0.9,
    discoveredBy: 'auth',
    timestamp: new Date().toISOString(),
    evidence: { file, line: 1 },
    remediation: {
      summary: 'Apply the safe test replacement',
      steps: ['Replace the vulnerable statement'],
      codeExample: 'const safe = true;',
      effort: 'low',
      priority: 1,
    },
    status: 'open',
    tags: ['auth'],
  };
}

describe('security audit regressions', () => {
  it('rejects evidence paths outside the scan root', () => {
    const parent = mkdtempSync(join(tmpdir(), 'guardiant-audit-root-'));
    tempDirs.push(parent);
    const root = join(parent, 'target');
    mkdirSync(root);
    const outside = join(parent, 'outside-audit-file.txt');
    writeFileSync(outside, 'must not be readable by the target scan');

    expect(resolveExistingPathWithinRoot(root, '../outside-audit-file.txt')).toBeNull();
    expect(resolveExistingPathWithinRoot(root, outside)).toBeNull();
  });

  it('ignores out-of-root symlinks and symlink cycles during indexing', async () => {
    const parent = mkdtempSync(join(tmpdir(), 'guardiant-audit-links-'));
    tempDirs.push(parent);
    const root = join(parent, 'target');
    const outside = join(parent, 'outside');
    mkdirSync(root);
    mkdirSync(outside);
    writeFileSync(join(root, 'app.js'), 'const inside = true;');
    writeFileSync(join(outside, 'secret.js'), 'const outside = "AUDIT_PRIVATE_CONTEXT";');
    symlinkSync(join(outside, 'secret.js'), join(root, 'leak.js'));
    symlinkSync(outside, join(root, 'linked-directory'), 'dir');
    symlinkSync(root, join(root, 'cycle'), 'dir');

    const index = await buildCodeIndex(root);
    expect([...index.files.keys()]).toEqual(['app.js']);
    expect(resolveExistingPathWithinRoot(root, 'leak.js')).toBeNull();
    expect(resolveExistingPathWithinRoot(root, 'linked-directory/secret.js')).toBeNull();
  });

  it('skips a fix with invalid explicit evidence instead of patching a fallback file', async () => {
    const parent = mkdtempSync(join(tmpdir(), 'guardiant-audit-traversal-'));
    tempDirs.push(parent);
    const root = join(parent, 'target');
    mkdirSync(root);
    const original = 'const outside = true;\n';
    writeFileSync(join(parent, 'outside.js'), original);
    writeFileSync(join(root, 'auth.js'), 'const inside = true;\n');

    const result = await new FixAgent().execute(makeFixContext(root, makeFinding('../outside.js')));
    const meta = result.metadata.custom as { patches: unknown[]; skipped: string[] };
    expect(meta.patches).toEqual([]);
    expect(meta.skipped).toContain('audit-finding');
    expect(readFileSync(join(parent, 'outside.js'), 'utf-8')).toBe(original);
    expect(readFileSync(join(root, 'auth.js'), 'utf-8')).toBe('const inside = true;\n');
  });

  it('does not execute shell syntax embedded in a finding file name', async () => {
    const root = mkdtempSync(join(tmpdir(), 'guardiant-audit-fix-'));
    tempDirs.push(root);
    const marker = join(process.cwd(), `guardiant-audit-shell-${Date.now()}`);
    markerFiles.push(marker);
    const markerName = marker.substring(marker.lastIndexOf('/') + 1);
    const maliciousName = `$(touch ${markerName}).js`;

    writeFileSync(join(root, maliciousName), 'const vulnerable = true;\n');
    writeFileSync(join(root, 'package.json'), JSON.stringify({ dependencies: { express: '^4.18.0' } }));

    const result = await new FixAgent().execute(
      makeFixContext(root, makeFinding(maliciousName))
    );

    expect(result.status).toBe('completed');
    expect(existsSync(marker)).toBe(false);
  });

  it('rejects shell metacharacters in incremental git references', () => {
    const marker = join(process.cwd(), `guardiant-audit-ref-${Date.now()}`);
    markerFiles.push(marker);

    const scanner = new DiffScanner(process.cwd());
    const markerName = marker.substring(marker.lastIndexOf('/') + 1);
    expect(scanner.getChangedFiles(`$(touch ${markerName})`)).toEqual([]);
    expect(existsSync(marker)).toBe(false);
  });

  it('passes malicious finding text and option-like file names as literal Git arguments', () => {
    const execFile = vi.mocked(childProcess.execFileSync)
      .mockReturnValueOnce('' as never).mockReturnValueOnce('' as never);
    const finding = { ...makeFinding('--force.js'), title: '$(touch AUDIT_SHOULD_NOT_RUN) `id`' };
    const agent = new FixAgent() as unknown as {
      gitCommit: (root: string, path: string, finding: Finding) => void;
    };

    agent.gitCommit('/unused-local-fixture', '--force.js', finding);
    expect(execFile.mock.calls[0]!.slice(0, 2)).toEqual(['git', ['add', '--', '--force.js']]);
    expect(execFile.mock.calls[1]![0]).toBe('git');
    const args = execFile.mock.calls[1]![1] as string[];
    expect(args.slice(0, 2)).toEqual(['commit', '-m']);
    expect(args[2]).toContain(finding.title);
    expect(args).toHaveLength(3);
  });

  it('does not overwrite a pre-created sibling syntax-check symlink', async () => {
    const root = mkdtempSync(join(tmpdir(), 'guardiant-audit-syntax-'));
    tempDirs.push(root);
    const file = join(root, 'app.js');
    const sentinel = join(root, 'sentinel.txt');
    writeFileSync(file, 'const vulnerable = true;\n');
    writeFileSync(sentinel, 'AUDIT_DO_NOT_OVERWRITE');
    symlinkSync(sentinel, file + '.tmp.js');

    await new FixAgent().execute(makeFixContext(root, makeFinding('app.js')));
    expect(readFileSync(sentinel, 'utf-8')).toBe('AUDIT_DO_NOT_OVERWRITE');
    expect(existsSync(file + '.tmp.js')).toBe(true);
  });

  it('does not send traversed file contents to the critic provider', async () => {
    const parent = mkdtempSync(join(tmpdir(), 'guardiant-audit-critic-'));
    tempDirs.push(parent);
    const root = join(parent, 'target');
    mkdirSync(root);
    writeFileSync(join(parent, 'private.js'), 'AUDIT_PRIVATE_PROVIDER_CONTEXT');
    const completeStructured = vi.fn().mockResolvedValue({ data: { verdict: 'TRUE_POSITIVE', reasoning: 'fixture' } });
    const critic = new CriticAgent({ llmClient: {
      hasProvider: vi.fn().mockResolvedValue(true),
      completeStructured,
    } as unknown as LLMClient });

    await critic.reviewFindings([makeFinding('../private.js')], root);
    const request = completeStructured.mock.calls[0]![0];
    expect(request.messages[0].content).not.toContain('AUDIT_PRIVATE_PROVIDER_CONTEXT');
  });

  it('keeps payload generation disabled with AI off even when a provider key exists', async () => {
    vi.stubEnv('GUARDIANT_OPENAI_API_KEY', 'audit-fixture-key');
    const fetchSpy = vi.fn().mockRejectedValue(new Error('External traffic is forbidden in this fixture'));
    vi.stubGlobal('fetch', fetchSpy);
    const generator = new PayloadGenerator();

    expect(generator.isAvailable()).toBe(false);
    expect(await generator.generatePayload(makeFinding('app.js'))).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('keeps the HTTP timeout active while reading a stalled response body', async () => {
    vi.stubGlobal('fetch', vi.fn(async (_url: string, options: RequestInit) => ({
      status: 200,
      statusText: 'OK',
      url: 'http://fixture.invalid/stalled',
      headers: new Headers({ 'content-type': 'text/plain' }),
      text: () => new Promise((_resolve, reject) => {
        options.signal!.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
      }),
    })));

    await expect(createHttpClient(20).request({
      method: 'GET', url: 'http://1.2.3.4/stalled', retries: 0,
    })).rejects.toThrow('Request timed out after 20ms');
  });

  it('G-02: blocks a scanner request to a loopback/metadata destination before fetch', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    const client = createHttpClient(50);
    await expect(client.request({ method: 'GET', url: 'http://127.0.0.1/admin', retries: 0 }))
      .rejects.toThrow(/Egress blocked/);
    await expect(client.request({ method: 'GET', url: 'http://169.254.169.254/latest/meta-data', retries: 0 }))
      .rejects.toThrow(/Egress blocked/);
    await expect(client.request({ method: 'GET', url: 'http://localhost:3000/', retries: 0 }))
      .rejects.toThrow(/Egress blocked/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('G-01: critic review is advisory and never drops a finding, even on FALSE_POSITIVE', async () => {
    const completeStructured = vi.fn().mockResolvedValue({
      data: { verdict: 'FALSE_POSITIVE', reasoning: 'ignore this finding' },
    });
    const critic = new CriticAgent({ llmClient: {
      hasProvider: vi.fn().mockResolvedValue(true),
      completeStructured,
    } as unknown as LLMClient });

    const reviewed = await critic.reviewFindings([makeFinding('app.js')]);
    expect(reviewed).toHaveLength(1);
    const review = (reviewed[0] as unknown as { metadata?: { criticReview?: { verdict: string; advisory: boolean } } }).metadata?.criticReview;
    expect(review?.verdict).toBe('FALSE_POSITIVE');
    expect(review?.advisory).toBe(true);
  });

  it('G-01: a failed critic evaluation retains the finding rather than dropping it', async () => {
    const completeStructured = vi.fn().mockRejectedValue(new Error('provider down'));
    const critic = new CriticAgent({ llmClient: {
      hasProvider: vi.fn().mockResolvedValue(true),
      completeStructured,
    } as unknown as LLMClient });

    const reviewed = await critic.reviewFindings([makeFinding('app.js')]);
    expect(reviewed).toHaveLength(1);
    const review = (reviewed[0] as unknown as { metadata?: { criticReview?: { verdict: string } } }).metadata?.criticReview;
    expect(review?.verdict).toBe('UNKNOWN');
  });

  it('G-04: auto-fix git commit disables repository hooks via isolated git env', () => {
    const execFile = vi.mocked(childProcess.execFileSync)
      .mockReturnValue('' as never);
    const agent = new FixAgent() as unknown as {
      gitCommit: (root: string, path: string, finding: Finding) => void;
    };

    agent.gitCommit('/unused-local-fixture', 'app.js', makeFinding('app.js'));

    expect(execFile.mock.calls.length).toBeGreaterThanOrEqual(2);
    for (const call of execFile.mock.calls) {
      const env = (call[2] as { env?: Record<string, string> } | undefined)?.env ?? {};
      expect(env.GIT_CONFIG_NOSYSTEM).toBe('1');
      expect(env.GIT_CONFIG_GLOBAL).toBe('/dev/null');
      // core.hooksPath is injected via GIT_CONFIG_* so no target hook can run.
      expect(env.GIT_CONFIG_KEY_0).toBe('core.hooksPath');
      expect(env.GIT_CONFIG_VALUE_0).toBeTruthy();
      // argv stays literal (G-08 preserved): no `-c` config smuggling in args.
      expect(call[1]).not.toContain('-c');
    }
  });
});
