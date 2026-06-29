import { AbstractAgent } from './base.js';
import { createFinding } from './types.js';
import type { AgentContext, AgentResult, Finding } from '@guardiant/shared';
import { OWASP_CATEGORIES, createLogger } from '@guardiant/shared';
import { createHttpClient } from '../http/index.js';
import { readFileSync, existsSync, statSync, readdirSync } from 'fs';
import { join, relative, extname } from 'path';

/**
 * Secrets Detection Agent
 *
 * Detects exposed API keys, secrets, and sensitive data in:
 * - Client-side code
 * - JavaScript bundles
 * - Source maps
 * - Configuration files
 * - Environment variable leaks
 */
export class SecretsAgent extends AbstractAgent {
  readonly id = 'secrets' as const;
  readonly name = 'Secrets Detection Agent';
  readonly description = 'Detects exposed API keys, secrets, and sensitive data in code and bundles.';
  readonly categories = [
    OWASP_CATEGORIES.A02_CRYPTOGRAPHIC_FAILURES.code,
    OWASP_CATEGORIES.A05_SECURITY_MISCONFIGURATION.code,
  ];
  readonly priority = 'critical' as const;

  private httpClient: ReturnType<typeof createHttpClient>;
  private logger = createLogger({ level: 'info' });

  constructor(config?: { timeout?: number }) {
    super();
    this.httpClient = createHttpClient(config?.timeout ?? 30000);
  }

  // Secret patterns to detect
  private readonly secretPatterns = [
    // API keys
    { pattern: /sk-[a-zA-Z0-9]{20,}/g, name: 'OpenAI API Key', severity: 'critical' as const },
    { pattern: /sk-ant-[a-zA-Z0-9-]{20,}/g, name: 'Anthropic API Key', severity: 'critical' as const },
    { pattern: /AIza[a-zA-Z0-9_-]{35}/g, name: 'Google API Key', severity: 'critical' as const },
    { pattern: /AKIA[A-Z0-9]{16}/g, name: 'AWS Access Key', severity: 'critical' as const },
    { pattern: /ghp_[a-zA-Z0-9]{36}/g, name: 'GitHub PAT', severity: 'critical' as const },
    { pattern: /github_pat_[a-zA-Z0-9_]{22,}/g, name: 'GitHub Fine-grained PAT', severity: 'critical' as const },
    { pattern: /xox[baprs]-[a-zA-Z0-9-]{10,}/g, name: 'Slack Token', severity: 'high' as const },
    { pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g, name: 'JWT Token', severity: 'medium' as const, checkPlaceholder: true },

    // Generic secrets — checkPlaceholder prevents false positives on test values
    { pattern: /(?:password|passwd|pwd)\s*[=:]\s*['"`]([^'"`]{8,})['"`]/gi, name: 'Hardcoded Password', severity: 'critical' as const, checkPlaceholder: true },
    { pattern: /(?:secret|api[_-]?key|token)\s*[=:]\s*['"`]([^'"`]{16,})['"`]/gi, name: 'Hardcoded Secret', severity: 'critical' as const, checkPlaceholder: true },
    { pattern: /(?:private[_-]?key|secret[_-]?key)\s*[=:]\s*['"`]([^'"`]+)['"`]/gi, name: 'Private Key', severity: 'critical' as const },

    // Database URLs
    { pattern: /(?:postgres|mysql|mongodb|redis):\/\/[^@]+@[^\s]+/gi, name: 'Database URL', severity: 'critical' as const },

    // Supabase specific
    { pattern: /supabase_service_role_key\s*[=:]\s*['"`]([^'"`]+)['"`]/gi, name: 'Supabase Service Key', severity: 'critical' as const },
    { pattern: /SUPABASE_SERVICE_KEY\s*[=:]\s*['"`]([^'"`]+)['"`]/gi, name: 'Supabase Service Key', severity: 'critical' as const },

    // Firebase specific
    { pattern: /firebase_admin_key/gi, name: 'Firebase Admin Key Reference', severity: 'high' as const },
    { pattern: /private_key\s*=\s*['"`]-----BEGIN PRIVATE KEY-----/gi, name: 'Firebase Private Key', severity: 'critical' as const },

    // Environment variable references — NOT secrets themselves, just references to env vars
    { pattern: /process\.env\.(?!NEXT_PUBLIC_|REACT_APP_|VITE_|EXPO_PUBLIC_)(?:API_KEY|SECRET|PASSWORD|TOKEN|PRIVATE)/gi, name: 'Environment Variable Reference (Not a Secret)', severity: 'info' as const },

    // OAuth secrets
    { pattern: /(?:client[_-]?secret|oauth[_-]?secret)\s*[=:]\s*['"`]([^'"`]+)['"`]/gi, name: 'OAuth Client Secret', severity: 'critical' as const },
  ];

  async execute(context: AgentContext): Promise<AgentResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];

    try {
      await this.setup?.(context);

      if (context.target.type === 'directory') {
        // Scan local files for secrets
        const fileFindings = await this.scanLocalDirectory(context);
        findings.push(...fileFindings);
      } else {
        // Phase 1: Scan JavaScript bundles
        const bundleFindings = await this.scanJavaScriptBundles(context);
        findings.push(...bundleFindings);

        // Phase 2: Check for exposed .env files
        const envFindings = await this.checkExposedEnvFiles(context);
        findings.push(...envFindings);

        // Phase 3: Check source maps for secrets
        const sourceMapFindings = await this.checkSourceMaps(context);
        findings.push(...sourceMapFindings);

        // Phase 4: Check for exposed config files
        const configFindings = await this.checkConfigFiles(context);
        findings.push(...configFindings);

        // Phase 5: Check HTML for inline secrets
        const htmlFindings = await this.scanHTML(context);
        findings.push(...htmlFindings);
      }

      await this.teardown?.(context);

      return this.createSuccessResult(findings, {
        filesAnalyzed: findings.length > 0 ? findings.length : 0,
        custom: {
          secretsFound: findings.length,
        },
      }, this.getDuration(startTime));
    } catch (error) {
      return this.createErrorResult(
        error instanceof Error ? error : new Error('Unknown error'),
        this.getDuration(startTime)
      );
    }
  }

  /**
   * Scan a local directory for secrets in files
   */
  private async scanLocalDirectory(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const rootPath = context.target.url;
    const foundSecrets = new Set<string>();

    if (!existsSync(rootPath)) return findings;

    const sensitiveExtensions = new Set([
      '.env', '.env.local', '.env.production', '.env.development',
      '.key', '.pem', '.p12', '.pfx', '.cert',
      '.npmrc', '.dockercfg', '.netrc',
    ]);

    const textExtensions = new Set([
      '.js', '.jsx', '.ts', '.tsx', '.py', '.rb', '.php', '.java',
      '.go', '.rs', '.sh', '.bash', '.zsh', '.yaml', '.yml',
      '.json', '.toml', '.ini', '.cfg', '.conf', '.config',
      '.xml', '.html', '.htm', '.vue', '.svelte', '.ejs', '.hbs',
      '.md', '.txt', '.sql', '.gradle', '.properties',
    ]);

    const excludeDirs = new Set([
      'node_modules', '.git', '.next', 'dist', 'build',
      '.cache', 'coverage', '.nyc_output', 'target',
      '__pycache__', '.venv', 'venv', '.tox',
    ]);

    const walkDir = (dir: string): void => {
      let entries: string[];
      try {
        entries = readdirSync(dir);
      } catch {
        return;
      }

      for (const entry of entries) {
        if (entry.toLowerCase().includes('guardiant-report') || entry.endsWith('.md')) continue;
        const fullPath = join(dir, entry);
        try {
          const stats = statSync(fullPath);
          if (stats.isDirectory()) {
            if (!excludeDirs.has(entry)) {
              walkDir(fullPath);
            }
          } else if (stats.isFile()) {
            const ext = extname(fullPath).toLowerCase();
            const baseName = entry.toLowerCase();

            if (sensitiveExtensions.has(ext) || sensitiveExtensions.has(baseName) || textExtensions.has(ext)) {
              try {
                const content = readFileSync(fullPath, 'utf-8');
                const relPath = relative(rootPath, fullPath);

                for (const { pattern, name, severity } of this.secretPatterns) {
                  const matches = content.matchAll(pattern);
                  for (const match of matches) {
                    const secretKey = `${name}:${match[0].substring(0, 20)}`;
                    if (!foundSecrets.has(secretKey)) {
                      foundSecrets.add(secretKey);
                      const finding = this.createSecretFinding(name, match[0], severity, relPath);
                      if (finding) findings.push(finding);
                    }
                  }
                }
              } catch {
                // Binary or unreadable file, skip
              }
            }
          }
        } catch {
          // Permission denied, skip
        }
      }
    };

    walkDir(rootPath);
    return findings;
  }

  getSystemPrompt(): string {
    return `You are a security expert specializing in secret detection.

Your job is to identify exposed credentials, API keys, and secrets in web applications:

1. API keys (OpenAI, AWS, Google, GitHub, etc.)
2. Database credentials
3. OAuth secrets
4. Private keys
5. Passwords in code
6. Environment variable leaks

For each secret found, provide:
- The type of secret
- Where it was found
- Potential impact
- Remediation steps

Be thorough but avoid false positives.`;
  }

  buildUserPrompt(context: AgentContext): string {
    return `Scan the following target for exposed secrets and credentials:

Target: ${context.target.url}

Check for:
1. Exposed API keys in JavaScript bundles
2. Environment variable leaks
3. Hardcoded credentials
4. Database connection strings
5. OAuth secrets
6. Private keys`;
  }

  async parseResponse(_response: string, _context: AgentContext): Promise<Finding[]> {
    return [];
  }

  /**
   * Scan JavaScript bundles for secrets
   */
  private async scanJavaScriptBundles(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const baseUrl = context.target.url;

    try {
      // Fetch main page
      const mainPage = await this.httpClient.get(baseUrl);
      const htmlContent = mainPage.body;

      // Extract JavaScript bundle URLs
      const jsUrls = this.extractJavaScriptUrls(htmlContent, baseUrl);
      const foundSecrets = new Set<string>(); // Avoid duplicates

      // Scan main HTML for secrets
      for (const { pattern, name, severity } of this.secretPatterns) {
        const matches = htmlContent.matchAll(pattern);
        for (const match of matches) {
          const secretKey = `${name}:${match[0].substring(0, 20)}`;
          if (!foundSecrets.has(secretKey)) {
            foundSecrets.add(secretKey);
            const finding = this.createSecretFinding(name, match[0], severity, 'HTML page');
            if (finding) findings.push(finding);
          }
        }
      }

      // Fetch and scan JavaScript bundles
      for (const jsUrl of jsUrls.slice(0, 10)) { // Limit to 10 bundles
        try {
          const jsResponse = await this.httpClient.get(jsUrl);
          if (!jsResponse.body) continue;

          const content = jsResponse.body;

          for (const { pattern, name, severity } of this.secretPatterns) {
            const matches = content.matchAll(pattern);
            for (const match of matches) {
              const secretKey = `${name}:${match[0].substring(0, 20)}`;
              if (!foundSecrets.has(secretKey)) {
                foundSecrets.add(secretKey);
                const finding = this.createSecretFinding(name, match[0], severity, jsUrl);
                if (finding) findings.push(finding);
              }
            }
          }
        } catch {
          // Continue on error
        }
      }
    } catch (error) {
      this.logger.warn('Error scanning JavaScript bundles:', error);
    }

    return findings;
  }

  /**
   * Create a secret finding
   */
  /**
   * Check if a matched value is a known placeholder/test value.
   * Returns true if the value should be suppressed.
   */
  private isPlaceholderValue(match: string): boolean {
    const lower = match.toLowerCase();
    const placeholders = [
      'example', 'placeholder', 'your-', 'xxx', 'test', 'dummy',
      'fake', 'sample', 'replace_me', 'changeme', 'insert_',
      '<your', 'todo', 'fixme', 'abc123', 'password123',
      'secret123', 'my-secret', 'my-password', 'my-api-key',
      'supersecret', '12345678', 'abcdefgh',
    ];
    return placeholders.some(p => lower.includes(p));
  }

  /**
   * Create a secret finding, or null if the match is a placeholder/test value.
   */
  private createSecretFinding(name: string, match: string, severity: 'critical' | 'high' | 'medium' | 'info', location: string): Finding | null {
    // Suppress placeholder/test values
    if (this.isPlaceholderValue(match)) {
      return null;
    }

    const redactedSecret = match.length > 30 ? match.substring(0, 15) + '...' + match.substring(match.length - 5) : match.substring(0, Math.floor(match.length / 2)) + '...';

    return createFinding(this.id)
      .title(`Exposed ${name}`)
      .description(
        `A ${name} was found exposed in client-side code (${location}). ` +
        `This allows attackers to access your services, potentially read sensitive data, ` +
        `and perform actions on your behalf. Exposed secrets are a critical security vulnerability ` +
        `that can lead to data breaches, financial loss, and service abuse.`
      )
      .severity(severity)
      .cvssScore(severity === 'critical' ? 9.1 : severity === 'high' ? 7.5 : severity === 'medium' ? 5.3 : 0)
      .category('A05_SECURITY_MISCONFIGURATION')
      .confidence(0.85)
      .evidence({
        file: location,
        snippet: redactedSecret,
        context: { keyType: name },
      })
      .remediation({
        summary: `Remove the ${name} from client-side code and rotate it immediately.`,
        steps: [
          `Immediately rotate/regenerate the exposed ${name}`,
          'Remove all secrets from client-side code',
          'Use environment variables on the server side only',
          'Audit all usage of this secret for unauthorized access',
          'Implement secret scanning in CI/CD pipeline',
          'Add pre-commit hooks to prevent future commits with secrets',
        ],
        codeExample: `// ❌ Never do this in client code
const API_KEY = 'sk-your-api-key-here';

// ✅ Use environment variables on server
const API_KEY = process.env.API_KEY;

// ✅ For frontend, use proxy or backend
// frontend/src/api.ts
const response = await fetch('/api/data'); // Proxy to backend
// backend/index.ts - use API_KEY from environment`,
        effort: 'low',
        priority: 1,
      })
      .tags(['secrets', 'exposed', name.toLowerCase().replace(/\s+/g, '-')])
      .build();
  }

  /**
   * Extract JavaScript URLs from HTML
   */
  private extractJavaScriptUrls(html: string, baseUrl: string): string[] {
    const urls: string[] = [];
    const scriptRegex = /<script[^>]+src=["']([^"']+\.js[^"']*)["']/gi;
    let match;

    while ((match = scriptRegex.exec(html)) !== null) {
      const src = match[1];
      if (!src) continue;
      try {
        const url = src.startsWith('http') ? src : new URL(src, baseUrl).toString();
        urls.push(url);
      } catch {
        // Invalid URL
      }
    }

    // Check for Next.js chunks
    const nextRegex = /["'](_next\/static\/chunks\/[^"']+\.js)["']/gi;
    while ((match = nextRegex.exec(html)) !== null) {
      const src = match[1];
      if (!src) continue;
      try {
        const url = new URL(src, baseUrl).toString();
        urls.push(url);
      } catch {
        // Invalid URL
      }
    }

    return [...new Set(urls)];
  }

  /**
   * Check for exposed .env files
   */
  private async checkExposedEnvFiles(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const baseUrl = context.target.url;

    const envPaths = [
      '/.env',
      '/.env.local',
      '/.env.development',
      '/.env.production',
      '/.env.staging',
      '/.env.example',
      '/.env.local.example',
    ];

    for (const envPath of envPaths) {
      try {
        const testUrl = new URL(envPath, baseUrl).toString();
        const response = await this.httpClient.get(testUrl);

        if (response.status === 200 && response.body) {
          // Check if it looks like an env file
          const content = response.body;
          if (content.includes('=') && (content.includes('KEY') || content.includes('SECRET') || content.includes('PASSWORD') || content.includes('TOKEN'))) {
            findings.push(
              createFinding(this.id)
                .title(`Exposed Environment File: ${envPath}`)
                .description(
                  `An environment file (${envPath}) is publicly accessible. ` +
                  `This file typically contains sensitive configuration, API keys, database credentials, ` +
                  `and other secrets that should never be exposed to the public.`
                )
                .severity('critical')
                .cvssScore(10.0)
                .category('A05_SECURITY_MISCONFIGURATION')
                .confidence(0.95)
                .evidence({
                  file: envPath,
                  context: { accessible: true },
                })
                .remediation({
                  summary: `Block access to ${envPath} and rotate all secrets in the file.`,
                  steps: [
                    'Immediately block access to .env files via web server configuration',
                    'Rotate ALL secrets, API keys, and passwords in the file',
                    'Add .env files to .gitignore',
                    'Configure web server to deny access to dotfiles',
                    'Use environment variables injected at build/deploy time',
                  ],
                  codeExample: `# Nginx
location ~ /\\.env {
  deny all;
  return 404;
}

# Apache (.htaccess)
<FilesMatch "^\\.env">
  Order allow,deny
  Deny from all
</FilesMatch>

# Vercel/Netlify
# Use their environment variable UI instead of .env files`,
                  effort: 'low',
                  priority: 1,
                })
                .tags(['secrets', 'env-file', 'exposed'])
                .build()
            );
          }
        }
      } catch {
        // File not accessible, good
      }
    }

    return findings;
  }

  /**
   * Check source maps for secrets
   */
  private async checkSourceMaps(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const baseUrl = context.target.url;

    try {
      const mainPage = await this.httpClient.get(baseUrl);
      const jsUrls = this.extractJavaScriptUrls(mainPage.body, baseUrl);
      const foundSecrets = new Set<string>();

      for (const jsUrl of jsUrls.slice(0, 5)) {
        try {
          // Check if source map exists
          const mapUrl = jsUrl + '.map';
          const mapResponse = await this.httpClient.get(mapUrl);

          if (mapResponse.status === 200 && mapResponse.body) {
            // Source map is accessible - check for secrets in it
            const content = mapResponse.body;

            for (const { pattern, name, severity } of this.secretPatterns) {
              const matches = content.matchAll(pattern);
              for (const match of matches) {
                const secretKey = `${name}:${match[0].substring(0, 20)}`;
                if (!foundSecrets.has(secretKey)) {
                  foundSecrets.add(secretKey);
                  findings.push(
                    createFinding(this.id)
                      .title(`Exposed ${name} in Source Map`)
                      .description(
                        `A ${name} was found in an accessible source map file. ` +
                        `Source maps contain the original source code with comments and variable names, ` +
                        `which may include secrets that were stripped from the production bundle.`
                      )
                      .severity(severity)
                      .cvssScore(severity === 'critical' ? 9.1 : severity === 'high' ? 7.5 : 5.3)
                      .category('A05_SECURITY_MISCONFIGURATION')
                      .confidence(0.8)
                      .evidence({
                        file: mapUrl,
                        context: { keyType: name, sourceMap: true },
                      })
                      .remediation({
                        summary: 'Disable source maps in production and rotate the exposed secret.',
                        steps: [
                          'Set GENERATE_SOURCEMAP=false in production',
                          'Remove .map files from production builds',
                          'Rotate any secrets found in source maps',
                          'Use different build configurations for dev/production',
                        ],
                        effort: 'low',
                        priority: 1,
                      })
                      .tags(['secrets', 'source-map', 'exposed'])
                      .build()
                  );
                }
              }
            }
          }
        } catch {
          // No source map or error
        }
      }
    } catch {
      // Continue on error
    }

    return findings;
  }

  /**
   * Check configuration files
   */
  private async checkConfigFiles(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const baseUrl = context.target.url;

    const configPaths = [
      { path: '/config.json', sensitive: false },
      { path: '/package.json', sensitive: false },
      { path: '/settings.json', sensitive: true },
      { path: '/firebase.json', sensitive: true },
      { path: '/.firebaserc', sensitive: false },
      { path: '/supabase/config.toml', sensitive: true },
      { path: '/.npmrc', sensitive: true },
      { path: '/.dockercfg', sensitive: true },
      { path: '/docker-compose.yml', sensitive: false },
      { path: '/.git/config', sensitive: true },
    ];

    for (const config of configPaths) {
      try {
        const testUrl = new URL(config.path, baseUrl).toString();
        const response = await this.httpClient.get(testUrl);

        if (response.status === 200 && response.body) {
          // For sensitive configs, always report
          if (config.sensitive) {
            findings.push(
              createFinding(this.id)
                .title(`Exposed Configuration File: ${config.path}`)
                .description(
                  `A sensitive configuration file (${config.path}) is publicly accessible. ` +
                  `This file may contain credentials, connection strings, or other sensitive information.`
                )
                .severity('high')
                .cvssScore(7.5)
                .category('A05_SECURITY_MISCONFIGURATION')
                .confidence(0.9)
                .evidence({
                  file: config.path,
                  context: { accessible: true, sensitive: true },
                })
                .remediation({
                  summary: `Block access to ${config.path} and review its contents.`,
                  steps: [
                    'Configure web server to deny access to this file',
                    'Move sensitive data to environment variables',
                    'Review file contents for exposed credentials',
                  ],
                  effort: 'low',
                  priority: 2,
                })
                .tags(['config', 'exposed', 'sensitive'])
                .build()
            );
          } else {
            // Check if non-sensitive config contains secrets
            const content = response.body;
            for (const { pattern, name, severity } of this.secretPatterns) {
              if (pattern.test(content)) {
                findings.push(
                  createFinding(this.id)
                    .title(`Potential ${name} in ${config.path}`)
                    .description(
                      `A pattern matching ${name} was found in ${config.path}. ` +
                      `Configuration files should not contain sensitive secrets.`
                    )
                    .severity(severity)
                    .cvssScore(severity === 'critical' ? 9.1 : severity === 'high' ? 7.5 : 5.3)
                    .category('A05_SECURITY_MISCONFIGURATION')
                    .confidence(0.7)
                    .evidence({
                      file: config.path,
                      context: { keyType: name },
                    })
                    .remediation({
                      summary: 'Remove secrets from configuration files.',
                      steps: [
                        'Move secrets to environment variables',
                        'Use secret management tools',
                        'Update configuration to reference env vars',
                      ],
                      effort: 'low',
                      priority: 2,
                    })
                    .tags(['secrets', 'config', 'exposed'])
                    .build()
                );
              }
            }
          }
        }
      } catch {
        // File not accessible, good
      }
    }

    return findings;
  }

  /**
   * Scan HTML for inline secrets
   */
  private async scanHTML(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const baseUrl = context.target.url;

    try {
      const response = await this.httpClient.get(baseUrl);
      const html = response.body;
      const foundSecrets = new Set<string>();

      // Check inline scripts
      const inlineScriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
      let match;
      while ((match = inlineScriptRegex.exec(html)) !== null) {
        const scriptContent = match[1];
        if (!scriptContent) continue;

        for (const { pattern, name, severity } of this.secretPatterns) {
          const secretMatches = scriptContent.matchAll(pattern);
          for (const secretMatch of secretMatches) {
            const secretKey = `${name}:${secretMatch[0].substring(0, 20)}`;
            if (!foundSecrets.has(secretKey)) {
              foundSecrets.add(secretKey);
              const finding = this.createSecretFinding(name, secretMatch[0], severity, 'inline script');
              if (finding) findings.push(finding);
            }
          }
        }
      }

      // Check data attributes
      const dataAttrRegex = /data-[\w-]+\s*=\s*["']([^"']+)["']/gi;
      while ((match = dataAttrRegex.exec(html)) !== null) {
        const value = match[1];
        if (!value) continue;

        for (const { pattern, name, severity } of this.secretPatterns) {
          if (pattern.test(value)) {
            const secretKey = `${name}:${value.substring(0, 20)}`;
            if (!foundSecrets.has(secretKey)) {
              foundSecrets.add(secretKey);
              const finding = this.createSecretFinding(name, value, severity, 'data attribute');
              if (finding) findings.push(finding);
            }
          }
        }
      }

      // Check hidden inputs
      const hiddenInputRegex = /<input[^>]+type=["']hidden["'][^>]+value=["']([^"']+)["']/gi;
      while ((match = hiddenInputRegex.exec(html)) !== null) {
        const value = match[1];
        if (!value) continue;

        for (const { pattern, name, severity } of this.secretPatterns) {
          if (pattern.test(value)) {
            const secretKey = `${name}:${value.substring(0, 20)}`;
            if (!foundSecrets.has(secretKey)) {
              foundSecrets.add(secretKey);
              const finding = this.createSecretFinding(name, value, severity, 'hidden input');
              if (finding) findings.push(finding);
            }
          }
        }
      }

    } catch {
      // Continue on error
    }

    return findings;
  }
}