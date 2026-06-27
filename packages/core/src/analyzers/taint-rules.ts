import type { Source, Sink, Sanitizer } from './taint-tracker.js';

/**
 * Default source/sink/sanitizer configurations.
 * Can be extended by YAML rules in the future.
 */

export const defaultSources: Source[] = [
  // Express / Next.js API
  { name: 'req', property: 'body' },
  { name: 'req', property: 'query' },
  { name: 'req', property: 'params' },
  { name: 'req', property: 'headers' },
  { name: 'request', property: 'body' },
  { name: 'request', property: 'query' },
  { name: 'request', property: 'params' },
  // React / DOM (client-side)
  { name: 'window', property: 'location' },
  { name: 'document', property: 'cookie' },
  { name: 'localStorage', property: 'getItem' },
];

export const defaultSinks: Sink[] = [
  // SQL
  { object: 'db', method: 'query' },
  { object: 'db', method: 'execute' },
  { object: 'client', method: 'query' },
  { object: 'pool', method: 'query' },
  { object: 'sequelize', method: 'query' },
  // Supabase
  { object: 'supabase', method: 'rpc' },
  // NoSQL / ORM
  { method: 'find' },
  { method: 'findOne' },
  { method: 'update' },
  { method: 'delete' },
  // Command Injection
  { method: 'exec' },
  { method: 'execSync' },
  { method: 'spawn' },
  { method: 'spawnSync' },
  // XSS / HTML
  { object: 'res', method: 'send' },
  { object: 'res', method: 'html' },
  { object: 'document', method: 'write' },
  // Path traversal
  { method: 'readFile' },
  { method: 'readFileSync' },
  { method: 'writeFile' },
  { method: 'writeFileSync' }
];

export const defaultSanitizers: Sanitizer[] = [
  { name: 'escape' },
  { name: 'sanitize' },
  { name: 'parseInt' },
  { name: 'Number' },
  { name: 'String' },
  { name: 'encodeURIComponent' },
  { name: 'DOMPurify' }
];
