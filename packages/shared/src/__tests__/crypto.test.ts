import { describe, it, expect } from 'vitest';
import {
  generateId,
  generateDeterministicId,
  generateScanId,
  generateFindingId,
  generateReportId,
  hashString,
  hashObject,
  generateSecureToken,
  encrypt,
  decrypt,
  looksLikeSecret,
  redactSecrets,
  hashFile,
} from '../utils/crypto.js';

describe('generateId', () => {
  it('should return a UUID string', () => {
    const id = generateId();
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('should prepend prefix when provided', () => {
    const id = generateId('scan');
    expect(id).toMatch(/^scan_[0-9a-f-]{36}$/);
  });

  it('should generate unique ids', () => {
    const a = generateId();
    const b = generateId();
    expect(a).not.toBe(b);
  });
});

describe('generateDeterministicId', () => {
  it('should return same ID for same input', () => {
    const id1 = generateDeterministicId('test-content');
    const id2 = generateDeterministicId('test-content');
    expect(id1).toBe(id2);
  });

  it('should return different IDs for different inputs', () => {
    const id1 = generateDeterministicId('content-a');
    const id2 = generateDeterministicId('content-b');
    expect(id1).not.toBe(id2);
  });
});

describe('generateScanId', () => {
  it('should start with scan_', () => {
    expect(generateScanId()).toMatch(/^scan_/);
  });

  it('should be unique each call', () => {
    const ids = new Set(Array.from({ length: 10 }, () => generateScanId()));
    expect(ids.size).toBe(10);
  });
});

describe('generateFindingId', () => {
  it('should include agentId and vulnerabilityType', () => {
    const id = generateFindingId('recon', 'sqli');
    expect(id).toContain('recon');
    expect(id).toContain('sqli');
  });
});

describe('generateReportId', () => {
  it('should produce report_<scanId>', () => {
    expect(generateReportId('scan_abc')).toBe('report_scan_abc');
  });
});

describe('hashString', () => {
  it('should return a 64-char hex string', () => {
    expect(hashString('hello')).toMatch(/^[0-9a-f]{64}$/);
  });

  it('should be deterministic', () => {
    expect(hashString('hello')).toBe(hashString('hello'));
  });

  it('should differ for different inputs', () => {
    expect(hashString('hello')).not.toBe(hashString('world'));
  });
});

describe('hashObject', () => {
  it('should hash object to hex string', () => {
    const hash = hashObject({ a: 1, b: 2 });
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('should be deterministic regardless of key order', () => {
    const h1 = hashObject({ a: 1, b: 2 });
    const h2 = hashObject({ b: 2, a: 1 });
    expect(h1).toBe(h2);
  });
});

describe('generateSecureToken', () => {
  it('should default to 32 bytes (64 hex chars)', () => {
    expect(generateSecureToken()).toHaveLength(64);
  });

  it('should respect custom length', () => {
    expect(generateSecureToken(16)).toHaveLength(32);
  });

  it('should be unique', () => {
    expect(generateSecureToken()).not.toBe(generateSecureToken());
  });
});

describe('encrypt / decrypt', () => {
  it('should round-trip encrypt and decrypt data', () => {
    const key = 'super-secret-key-32chars-or-more';
    const data = 'hello, world!';
    const { encrypted, iv, authTag } = encrypt(data, key);
    const decrypted = decrypt(encrypted, key, iv, authTag);
    expect(decrypted).toBe(data);
  });

  it('should produce different ciphertext for same plaintext', () => {
    const key = 'super-secret-key-32chars-or-more';
    const { encrypted: e1 } = encrypt('same', key);
    const { encrypted: e2 } = encrypt('same', key);
    expect(e1).not.toBe(e2);
  });
});

describe('looksLikeSecret', () => {
  it('should detect OpenAI-style keys', () => {
    expect(looksLikeSecret('sk-abcdefghijklmnopqrstu')).toBe(true);
  });

  it('should detect Anthropic keys', () => {
    expect(looksLikeSecret('sk-ant-abcdefghijklmnopqrstu')).toBe(true);
  });

  it('should detect JWTs', () => {
    expect(looksLikeSecret('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')).toBe(true);
  });

  it('should not flag short strings', () => {
    expect(looksLikeSecret('hello')).toBe(false);
  });
});

describe('redactSecrets', () => {
  it('should redact OpenAI API keys', () => {
    const input = 'key=sk-abcdefghijklmnopqrstuvwxyz123456xyz';
    const result = redactSecrets(input);
    expect(result).not.toContain('sk-abcdefghijklmnopqrstuvwxyz123456xyz');
    expect(result).toContain('REDACTED');
  });

  it('should redact passwords', () => {
    const result = redactSecrets('password=supersecret123');
    expect(result).toContain('REDACTED');
  });

  it('should leave unrelated content unchanged', () => {
    const input = 'Hello, world!';
    expect(redactSecrets(input)).toBe(input);
  });
});

describe('hashFile', () => {
  it('should hash a Buffer to hex', async () => {
    const hash = await hashFile(Buffer.from('test content'));
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('should hash a string directly', async () => {
    const hash = await hashFile('test content');
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('should be deterministic', async () => {
    const h1 = await hashFile('same');
    const h2 = await hashFile('same');
    expect(h1).toBe(h2);
  });
});
