import { v4 as uuidv4, v5 as uuidv5 } from 'uuid';
import * as crypto from 'crypto';

/**
 * Generate a unique ID
 */
export function generateId(prefix?: string): string {
  const id = uuidv4();
  return prefix ? `${prefix}_${id}` : id;
}

/**
 * Generate a deterministic ID from content
 */
export function generateDeterministicId(content: string, _namespace: string = 'guardiant'): string {
  const NAMESPACE_UUID = '6ba7b810-9dad-11d1-80b4-00c04fd430c8'; // UUID namespace for DNS
  return uuidv5(content, NAMESPACE_UUID);
}

/**
 * Generate a scan ID
 */
export function generateScanId(): string {
  const timestamp = Date.now().toString(36);
  const random = crypto.randomBytes(4).toString('hex');
  return `scan_${timestamp}_${random}`;
}

/**
 * Generate a finding ID
 */
export function generateFindingId(agentId: string, vulnerabilityType: string): string {
  const timestamp = Date.now().toString(36);
  const random = crypto.randomBytes(3).toString('hex');
  return `finding_${agentId}_${vulnerabilityType}_${timestamp}_${random}`;
}

/**
 * Generate a report ID
 */
export function generateReportId(scanId: string): string {
  return `report_${scanId}`;
}

/**
 * Hash a string using SHA-256
 */
export function hashString(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Hash content for comparison
 */
export function hashObject(obj: unknown): string {
  const content = JSON.stringify(obj, Object.keys(obj as object).sort());
  return hashString(content);
}

/**
 * Generate a secure random token
 */
export function generateSecureToken(length: number = 32): string {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Encrypt data using AES-256-GCM
 */
export function encrypt(data: string, key: string): { encrypted: string; iv: string; authTag: string } {
  const iv = crypto.randomBytes(16);
  const derivedKey = crypto.scryptSync(key, 'salt', 32);
  const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);

  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
  };
}

/**
 * Decrypt data using AES-256-GCM
 */
export function decrypt(encrypted: string, key: string, iv: string, authTag: string): string {
  const derivedKey = crypto.scryptSync(key, 'salt', 32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, Buffer.from(iv, 'hex'));

  decipher.setAuthTag(Buffer.from(authTag, 'hex'));

  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/**
 * Check if a string looks like a secret/API key
 */
export function looksLikeSecret(value: string): boolean {
  // Check for common secret patterns
  const secretPatterns = [
    /^[a-zA-Z0-9_-]{32,}$/, // Generic long alphanumeric
    /^sk-[a-zA-Z0-9]{20,}$/, // OpenAI-style keys
    /^sk-ant-[a-zA-Z0-9-]{20,}$/, // Anthropic keys
    /^AIza[a-zA-Z0-9_-]{35}$/, // Google API keys
    /^AKIA[A-Z0-9]{16}$/, // AWS access keys
    /^ghp_[a-zA-Z0-9]{36}$/, // GitHub PAT
    /^github_pat_[a-zA-Z0-9_]{22,}$/, // GitHub fine-grained PAT
    /^xox[baprs]-[a-zA-Z0-9-]{10,}$/, // Slack tokens
    /^eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*$/, // JWTs
    /^supabase_service_role_key/, // Supabase service key
    /^firebase_admin_key/, // Firebase admin key
  ];

  return secretPatterns.some(pattern => pattern.test(value));
}

/**
 * Redact secrets from string
 */
export function redactSecrets(content: string): string {
  // Patterns for secrets
  const patterns = [
    { pattern: /(sk-[a-zA-Z0-9]{20,})/g, replacement: 'sk-***REDACTED***' },
    { pattern: /(sk-ant-[a-zA-Z0-9-]{20,})/g, replacement: 'sk-ant-***REDACTED***' },
    { pattern: /(AIza[a-zA-Z0-9_-]{35})/g, replacement: 'AIza***REDACTED***' },
    { pattern: /(AKIA[A-Z0-9]{16})/g, replacement: 'AKIA***REDACTED***' },
    { pattern: /(ghp_[a-zA-Z0-9]{36})/g, replacement: 'ghp_***REDACTED***' },
    { pattern: /(github_pat_[a-zA-Z0-9_]{22,})/g, replacement: 'github_pat_***REDACTED***' },
    { pattern: /(xox[baprs]-[a-zA-Z0-9-]{10,})/g, replacement: 'xox***REDACTED***' },
    { pattern: /(eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)/g, replacement: 'eyJ***REDACTED***' },
    { pattern: /(password\s*[=:]\s*['"`]?[^'"`\s,}\]]{8,})/gi, replacement: 'password=***REDACTED***' },
    { pattern: /(secret\s*[=:]\s*['"`]?[^'"`\s,}\]]{8,})/gi, replacement: 'secret=***REDACTED***' },
    { pattern: /(api[_-]?key\s*[=:]\s*['"`]?[^'"`\s,}\]]{8,})/gi, replacement: 'api_key=***REDACTED***' },
    { pattern: /(token\s*[=:]\s*['"`]?[^'"`\s,}\]]{8,})/gi, replacement: 'token=***REDACTED***' },
  ];

  let result = content;
  for (const { pattern, replacement } of patterns) {
    result = result.replace(pattern, replacement);
  }
  return result;
}

/**
 * Create a SHA-256 hash of a file
 */
export async function hashFile(content: Buffer | string): Promise<string> {
  const buffer = typeof content === 'string' ? Buffer.from(content) : content;
  return crypto.createHash('sha256').update(buffer).digest('hex');
}