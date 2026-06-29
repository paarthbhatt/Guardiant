import { describe, it, expect, vi } from 'vitest';
import { buildCodeIndex } from '../indexer/code-index.js';
import { EvidenceVerifier } from '../evidence/evidence-verifier.js';
import { IDORDetector } from '../detectors/idor-detector.js';
import { SessionStorageDetector } from '../detectors/session-storage-detector.js';
import { ScopingGapDetector } from '../detectors/scoping-gap-detector.js';
import { SUPPRESSION_RULES } from '../validators/suppression-rules.js';

// Mock fs module
vi.mock('fs', () => {
  return {
    readdirSync: vi.fn((dir: string) => {
      const norm = dir.replace(/\\/g, '/');
      if (norm === 'root') return ['app.js', 'vercel.json', 'routes', 'controllers'];
      if (norm === 'root/routes') return ['shares.js', 'inventory.js'];
      if (norm === 'root/controllers') return ['sharesController.js', 'inventoryController.js'];
      return [];
    }),
    statSync: vi.fn((filePath: string) => {
      const norm = filePath.replace(/\\/g, '/');
      const isDir = norm === 'root' || norm === 'root/routes' || norm === 'root/controllers';
      return {
        isDirectory: () => isDir,
        isFile: () => !isDir,
      };
    }),
    readFileSync: vi.fn((filePath: string) => {
      const normalizedPath = filePath.replace(/\\/g, '/');
      if (normalizedPath.endsWith('app.js')) {
        return `
          const express = require('express');
          const app = express();

          // Vulnerable IDOR endpoint
          app.delete('/api/tasks/:id', auth, (req, res) => {
            const taskId = req.params.id;
            const task = db.delete(taskId);
            res.json(task);
          });

          // Secure IDOR endpoint
          app.get('/api/users/:id', auth, (req, res) => {
            if (req.params.id !== req.user.id) {
              return res.status(403).send('Forbidden');
            }
            res.json(req.user);
          });

          // Insecure session storage
          localStorage.setItem('access_token', response.data.token);
        `;
      }
      if (normalizedPath.endsWith('vercel.json')) {
        return JSON.stringify({
          headers: [
            {
              source: '/(.*)',
              headers: [
                { key: 'X-Content-Type-Options', value: 'nosniff' },
                { key: 'Strict-Transport-Security', value: 'max-age=63072000' }
              ]
            }
          ]
        });
      }
      if (normalizedPath.endsWith('routes/shares.js')) {
        return `
          const router = require('express').Router();
          const ctrl = require('../controllers/sharesController');
          router.use(auth);
          router.get('/lead/:leadId', ctrl.listByLead);
        `;
      }
      if (normalizedPath.endsWith('controllers/sharesController.js')) {
        return `
          exports.listByLead = async (req, res) => {
            const leadId = req.params.leadId;
            const lead = await db.query('SELECT * FROM leads WHERE id = $1', [leadId]);
            res.json(lead);
          };
        `;
      }
      if (normalizedPath.endsWith('routes/inventory.js')) {
        return `
          const router = require('express').Router();
          const ctrl = require('../controllers/inventoryController');
          router.get('/search', scopeInventoryQuery, ctrl.search);
          router.get('/export', ctrl.exportInventory);
        `;
      }
      if (normalizedPath.endsWith('controllers/inventoryController.js')) {
        return `
          exports.search = (req, res) => res.json([]);
          exports.exportInventory = (req, res) => res.json([]);
        `;
      }
      return '';
    }),
    existsSync: vi.fn(() => true),
  };
});

describe('CodeIndex and Detectors', () => {
  it('should parse express route registrations and build CodeIndex', async () => {
    const codeIndex = await buildCodeIndex('root');

    expect(codeIndex.files.has('app.js')).toBe(true);
    expect(codeIndex.files.has('vercel.json')).toBe(true);
    expect(codeIndex.routeHandlers).toHaveLength(5); // app.delete, app.get, routes/shares.js (resolved), routes/inventory.js (search, export)

    const deleteRoute = codeIndex.routeHandlers.find(r => r.method === 'DELETE');
    expect(deleteRoute).toBeDefined();
    expect(deleteRoute?.path).toBe('/api/tasks/:id');
    expect(deleteRoute?.params).toContain('id');
    expect(deleteRoute?.middleware).toContain('auth');
  });

  it('should verify evidence snippets and detect mismatches', async () => {
    const codeIndex = await buildCodeIndex('root');
    const verifier = new EvidenceVerifier(codeIndex);

    // Matches
    const result1 = verifier.verify({
      file: 'app.js',
      line: 6,
      snippet: 'app.delete(\'/api/tasks/:id\', auth, (req, res) => {',
    });
    expect(result1.verificationStatus).toBe('verified');
    expect(result1.similarity).toBeGreaterThanOrEqual(0.6);

    // Mismatches
    const result2 = verifier.verify({
      file: 'app.js',
      line: 6,
      snippet: 'completely fabricated snippet that does not exist',
    });
    expect(result2.verificationStatus).toBe('mismatch');
  });

  it('should detect IDOR vulnerabilities via AST analysis', async () => {
    const codeIndex = await buildCodeIndex('root');
    const detector = new IDORDetector(codeIndex);

    const deleteRoute = codeIndex.routeHandlers.find(r => r.method === 'DELETE' && r.file === 'app.js');
    expect(deleteRoute).toBeDefined();
    const deleteResult = detector.detect(deleteRoute!);
    expect(deleteResult).not.toBeNull();
    expect(deleteResult?.type).toBe('idor');
    expect(deleteResult?.severity).toBe('high');

    const getRoute = codeIndex.routeHandlers.find(r => r.method === 'GET' && r.file === 'app.js');
    expect(getRoute).toBeDefined();
    const getResult = detector.detect(getRoute!);
    expect(getResult).toBeNull(); // Secure, has ownership check
  });

  it('should resolve controller method route handler and detect IDOR', async () => {
    const codeIndex = await buildCodeIndex('root');
    const detector = new IDORDetector(codeIndex);

    const shareRoute = codeIndex.routeHandlers.find(r => r.path === '/lead/:leadId');
    expect(shareRoute).toBeDefined();
    expect(shareRoute?.file).toBe('controllers/sharesController.js');
    expect(shareRoute?.middleware).toContain('auth'); // router.use(auth) successfully tracked!

    const result = detector.detect(shareRoute!);
    expect(result).not.toBeNull(); // Flagged because no ownership check is inside listByLead!
    expect(result?.type).toBe('idor');
  });

  it('should detect insecure localStorage usage via AST analysis', async () => {
    const codeIndex = await buildCodeIndex('root');
    const detector = new SessionStorageDetector(codeIndex);

    const result = detector.detectInFile('app.js');
    expect(result).not.toBeNull();
    expect(result?.evidence.snippet).toContain('localStorage.setItem');
    expect(result?.evidence.snippet).toContain('access_token');
  });

  it('should verify header presence in vercel.json configuration', async () => {
    const codeIndex = await buildCodeIndex('root');
    const verifier = new EvidenceVerifier(codeIndex);

    // verify that if a finding complains about missing X-Content-Type-Options,
    // and it is present in vercel.json, it reports a mismatch (false positive)
    const result = verifier.verify({
      file: 'vercel.json',
      title: 'Missing Security Headers',
      description: 'vercel.json has no X-Content-Type-Options header',
    });
    expect(result.verificationStatus).toBe('mismatch');
  });

  it('should detect scoping middleware gaps on sensitive sibling routes', async () => {
    const codeIndex = await buildCodeIndex('root');
    const detector = new ScopingGapDetector(codeIndex);

    const gaps = detector.detectGaps();
    expect(gaps).toHaveLength(1);
    expect(gaps[0].evidence.file).toBe('controllers/inventoryController.js');
    expect(gaps[0].evidence.reasoning).toContain('/export');
  });

  it('should suppress secrets findings in test scripts and files', () => {
    const rule = SUPPRESSION_RULES.find(r => r.id === 'test_files_not_secrets');
    expect(rule).toBeDefined();

    const mockFinding = {
      id: 'f-1',
      title: 'Hardcoded Secret',
      description: 'Found password',
      severity: 'high' as const,
      category: 'A02_CRYPTOGRAPHIC_FAILURES',
      confidence: 0.9,
      evidence: {
        file: 'scripts/securityChecks.js',
        line: 31,
        snippet: 'const PASSWORD = "test";'
      },
      discoveredBy: 'secrets',
      tags: [],
    };

    expect(rule?.matches(mockFinding)).toBe(true);

    const srcFinding = {
      ...mockFinding,
      evidence: {
        ...mockFinding.evidence,
        file: 'src/app.js'
      }
    };
    expect(rule?.matches(srcFinding)).toBe(false);
  });
});
