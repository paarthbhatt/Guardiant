import { AbstractAgent } from './base.js';
import { createFinding } from './types.js';
import type { AgentContext, AgentResult, Finding, ReconData, DiscoveredEndpoint, TechStackInfo } from '@guardiant/shared';
import { OWASP_CATEGORIES } from '@guardiant/shared';
import type { LLMClient } from '../llm/index.js';
import { createHttpClient, type HttpResponse } from '../http/index.js';

/**
 * Reconnaissance Agent
 *
 * Discovers API endpoints, tech stack, authentication mechanisms,
 * and VCVF patterns. This agent MUST run first as other agents
 * depend on its data.
 */
export class ReconAgent extends AbstractAgent {
  readonly id = 'recon' as const;
  readonly name = 'Reconnaissance Agent';
  readonly description = 'Discovers API endpoints, tech stack, authentication mechanisms, and VCVF patterns.';
  readonly categories = [
    OWASP_CATEGORIES.A05_SECURITY_MISCONFIGURATION.code,
  ];
  readonly priority = 'critical' as const;

  private httpClient: ReturnType<typeof createHttpClient>;

  constructor(_config?: { llmClient?: LLMClient }) {
    super();
    this.httpClient = createHttpClient(30000);
  }

  async execute(context: AgentContext): Promise<AgentResult> {
    const startTime = Date.now();

    try {
      await this.setup?.(context);

      const baseUrl = context.target.url;

      // Phase 1: Fetch the main page
      const mainPageResult = await this.fetchPage(baseUrl);

      if (!mainPageResult.response) {
        return this.createErrorResult(
          new Error(`Failed to fetch target: ${mainPageResult.error}`),
          this.getDuration(startTime)
        );
      }

      const mainPageHtml = mainPageResult.response.body;

      // Phase 2: Discover endpoints
      const endpoints = await this.discoverEndpoints(baseUrl, mainPageHtml);

      // Phase 3: Extract and analyze JavaScript bundles
      const jsBundles = this.extractJavaScriptUrls(mainPageHtml, baseUrl);
      const jsContent = await this.fetchJavaScriptBundles(jsBundles);

      // Phase 4: Analyze tech stack
      const techStack = await this.analyzeTechStack(baseUrl, mainPageResult.response, jsContent);

      // Phase 5: Detect authentication mechanisms
      const authMechanisms = await this.detectAuthMechanisms(mainPageHtml, jsContent);

      // Phase 6: Check for source maps
      const sourceMapsAvailable = await this.checkSourceMaps(jsBundles);

      // Phase 7: Find configuration files
      const configFiles = await this.findConfigFiles(baseUrl);

      // Phase 8: Detect VCVF patterns
      const vcvfPatterns = this.detectVCVFPatterns(mainPageHtml, jsContent, techStack);

      // Phase 9: Analyze data flows
      const dataFlows = this.analyzeDataFlows(endpoints, jsContent);

      // Phase 10: Find external services
      const externalServices = this.detectExternalServices(mainPageHtml, jsContent);

      // Build recon data
      const reconData: ReconData = {
        endpoints,
        techStack,
        authMechanisms,
        sourceMapsAvailable,
        configFiles,
        vcvfPatterns,
        dataFlows,
        externalServices,
      };

      // Create findings for security issues found during recon
      const findings: Finding[] = [];

      // Source map exposure finding
      if (sourceMapsAvailable) {
        findings.push(
          createFinding(this.id)
            .title('Source Maps Exposed in Production')
            .description(
              'Source maps are publicly accessible, exposing original source code, ' +
              'variable names, and potentially sensitive logic. This aids attackers in ' +
              'understanding application internals and finding vulnerabilities.'
            )
            .severity('medium')
            .cvssScore(5.3)
            .category('A05_SECURITY_MISCONFIGURATION')
            .confidence(0.9)
            .evidence({
              file: jsBundles.map(b => b.url).join(', '),
              context: { sourceMapsAvailable: true },
            })
            .remediation({
              summary: 'Disable source maps in production builds.',
              steps: [
                'Set GENERATE_SOURCEMAP=false in production environment',
                'Remove .map files from production builds',
                'Configure bundler to not generate source maps for production',
                'Use server configuration to block .map file access',
              ],
              codeExample: `// next.config.js
module.exports = {
  productionBrowserSourceMaps: false,
}

// webpack.config.js
module.exports = {
  devtool: process.env.NODE_ENV === 'production' ? false : 'source-map',
}`,
              effort: 'low',
              priority: 7,
            })
            .addTag('recon')
            .addTag('source-maps')
            .build()
        );
      }

      // Check for exposed config files
      for (const configFile of configFiles) {
        if (configFile.accessible && configFile.sensitive) {
          findings.push(
            createFinding(this.id)
              .title(`Exposed Configuration File: ${configFile.path}`)
              .description(
                `A sensitive configuration file (${configFile.path}) is publicly accessible. ` +
                `This may contain credentials, API keys, or other sensitive information.`
              )
              .severity('high')
              .cvssScore(7.5)
              .category('A05_SECURITY_MISCONFIGURATION')
              .confidence(0.85)
              .evidence({
                file: configFile.path,
                context: { accessible: true },
              })
              .remediation({
                summary: `Remove or restrict access to ${configFile.path}.`,
                steps: [
                  'Add the file to .gitignore',
                  'Configure web server to deny access to sensitive files',
                  'Move secrets to environment variables',
                  'Remove any committed sensitive files from git history',
                ],
                effort: 'low',
                priority: 2,
              })
              .addTag('recon')
              .addTag('config-exposure')
              .build()
          );
        }
      }

      await this.teardown?.(context);

      return this.createSuccessResult(findings, {
        filesAnalyzed: jsBundles.length + configFiles.length,
        endpointsTested: endpoints.length,
        custom: {
          reconData,
        },
      }, this.getDuration(startTime));
    } catch (error) {
      return this.createErrorResult(
        error instanceof Error ? error : new Error('Unknown error'),
        this.getDuration(startTime)
      );
    }
  }

  getSystemPrompt(): string {
    return `You are a security reconnaissance expert. Your job is to analyze web applications and discover:
1. All API endpoints and their parameters
2. Technology stack (frameworks, languages, databases)
3. Authentication mechanisms
4. External service integrations
5. Security misconfigurations

Focus on identifying potential attack surfaces and security-relevant information.

Output your findings in a structured JSON format.`;
  }

  buildUserPrompt(context: AgentContext): string {
    return `Analyze the following target for security reconnaissance:

Target: ${context.target.url}
Type: ${context.target.type}

${context.target.baasProvider ? `BaaS Provider: ${context.target.baasProvider}` : 'BaaS Provider: Unknown'}
${context.target.framework ? `Framework: ${context.target.framework}` : 'Framework: Unknown'}

Provide a detailed reconnaissance report including:
1. All discovered API endpoints
2. Technology stack information
3. Authentication mechanisms detected
4. External services and integrations
5. Potential security concerns`;
  }

  async parseResponse(_response: string, _context: AgentContext): Promise<Finding[]> {
    return [];
  }

  /**
   * Fetch a page with error handling
   */
  private async fetchPage(url: string): Promise<{ response?: HttpResponse; error?: string }> {
    try {
      const response = await this.httpClient.get(url);
      return { response };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';

      // Provide actionable error messages for common failure modes
      if (message.includes('ECONNREFUSED')) {
        return {
          error: `Connection refused at ${url}. The target server may not be running. ` +
            `If using a local server, ensure it is started and accessible.`,
        };
      }
      if (message.includes('ECONNRESET')) {
        return {
          error: `Connection reset by ${url}. The target server closed the connection unexpectedly.`,
        };
      }
      if (message.includes('timed out')) {
        return {
          error: `Request to ${url} timed out. The target may be slow or unreachable.`,
        };
      }
      if (message.includes('ENOTFOUND')) {
        return {
          error: `DNS resolution failed for ${url}. The hostname could not be resolved.`,
        };
      }

      return { error: `Failed to fetch target: ${message}` };
    }
  }

  /**
   * Discover API endpoints from HTML and JavaScript
   */
  private async discoverEndpoints(baseUrl: string, html: string): Promise<DiscoveredEndpoint[]> {
    const endpoints: DiscoveredEndpoint[] = [];
    const seen = new Set<string>();

    // Common API paths to probe
    const commonPaths = [
      '/api', '/api/v1', '/api/v2', '/graphql',
      '/health', '/metrics', '/status',
      '/swagger', '/swagger.json', '/api-docs', '/openapi.json',
      '/.well-known/openapi', '/docs', '/redoc',
    ];

    // Extract links from HTML
    const linkRegex = /(?:href|src|action)=["']([^"']+)["']/gi;
    let match;
    while ((match = linkRegex.exec(html)) !== null) {
      const href = match[1];
      if (href && (href.startsWith('/') || href.startsWith(baseUrl))) {
        const path = href.startsWith('/') ? href.split('?')[0] : (href ? new URL(href).pathname : '/');
        const key = `GET:${path}`;
        if (!seen.has(key) && path) {
          seen.add(key);
          endpoints.push({
            path,
            method: 'GET',
            authentication: false,
          });
        }
      }
    }

    // Extract forms
    const formRegex = /<form[^>]+action=["']([^"']*)["'][^>]*method=["']([^"']+)["'][^>]*>/gi;
    while ((match = formRegex.exec(html)) !== null) {
      const action = match[1] || '/';
      const method = match[2]?.toUpperCase() || 'GET';
      const path = action.startsWith('/') ? action : new URL(action, baseUrl).pathname;

      // Extract form inputs
      const formStart = match.index;
      const formEnd = html.indexOf('</form>', formStart);
      const formContent = html.substring(formStart, formEnd > 0 ? formEnd : formStart + 5000);

      const params: DiscoveredEndpoint['parameters'] = [];
      const inputRegex = /<input[^>]+name=["']([^"']+)["']/gi;
      let inputMatch;
      while ((inputMatch = inputRegex.exec(formContent)) !== null) {
        if (inputMatch[1]) {
          params.push({
            name: inputMatch[1],
            location: 'body',
            type: 'string',
          });
        }
      }

      const key = `${method}:${path}`;
      if (!seen.has(key)) {
        seen.add(key);
        endpoints.push({
          path,
          method: method as DiscoveredEndpoint['method'],
          parameters: params.length > 0 ? params : undefined,
          authentication: action.toLowerCase().includes('login') || action.toLowerCase().includes('auth'),
        });
      }
    }

    // Extract API routes from inline scripts and data attributes
    const apiRegex = /["']\/api\/([a-zA-Z0-9/_-]+)["']/gi;
    while ((match = apiRegex.exec(html)) !== null) {
      const path = `/api/${match[1]}`;
      const key = `GET:${path}`;
      if (!seen.has(key)) {
        seen.add(key);
        endpoints.push({
          path,
          method: 'GET',
          authentication: true,
        });
      }
    }

    // Check common paths
    for (const commonPath of commonPaths) {
      try {
        const testUrl = new URL(commonPath, baseUrl).toString();
        const response = await this.httpClient.get(testUrl);
        if (response.status < 400 || response.status === 401 || response.status === 403) {
          const key = `GET:${commonPath}`;
          if (!seen.has(key)) {
            seen.add(key);
            endpoints.push({
              path: commonPath,
              method: 'GET',
              authentication: response.status === 401 || response.status === 403,
            });
          }
        }
      } catch {
        // Path doesn't exist, continue
      }
    }

    return endpoints;
  }

  /**
   * Extract JavaScript bundle URLs from HTML
   */
  private extractJavaScriptUrls(html: string, baseUrl: string): Array<{ url: string; path: string }> {
    const scripts: Array<{ url: string; path: string }> = [];

    // Script src attributes
    const scriptRegex = /<script[^>]+src=["']([^"']+\.js[^"']*)["']/gi;
    let match;
    while ((match = scriptRegex.exec(html)) !== null) {
      const src = match[1];
      if (!src) continue;
      try {
        const url = src.startsWith('http') ? src : new URL(src, baseUrl).toString();
        const path = src.startsWith('/') ? src : new URL(src).pathname;
        scripts.push({ url, path });
      } catch {
        // Invalid URL
      }
    }

    // Module scripts
    const moduleRegex = /<script[^>]+type=["']module["'][^>]+src=["']([^"']+)["']/gi;
    while ((match = moduleRegex.exec(html)) !== null) {
      const src = match[1];
      if (!src) continue;
      try {
        const url = src.startsWith('http') ? src : new URL(src, baseUrl).toString();
        const path = src.startsWith('/') ? src : new URL(src).pathname;
        scripts.push({ url, path });
      } catch {
        // Invalid URL
      }
    }

    // Next.js specific: _next/static/chunks
    const nextRegex = /["'](_next\/static\/chunks\/[^"']+\.js)["']/gi;
    while ((match = nextRegex.exec(html)) !== null) {
      const src = match[1];
      if (!src) continue;
      try {
        const url = new URL(src, baseUrl).toString();
        scripts.push({ url, path: `/${src}` });
      } catch {
        // Invalid URL
      }
    }

    // Deduplicate
    const seen = new Set<string>();
    return scripts.filter(s => {
      if (seen.has(s.url)) return false;
      seen.add(s.url);
      return true;
    });
  }

  /**
   * Fetch JavaScript bundles and return combined content
   */
  private async fetchJavaScriptBundles(
    bundles: Array<{ url: string; path: string }>
  ): Promise<string> {
    const contents: string[] = [];

    // Fetch bundles in parallel (limit to 5)
    const limitedBundles = bundles.slice(0, 10);
    const results = await Promise.allSettled(
      limitedBundles.map(b => this.httpClient.get(b.url))
    );

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value.body) {
        contents.push(result.value.body);
      }
    }

    return contents.join('\n\n');
  }

  /**
   * Analyze technology stack
   */
  private async analyzeTechStack(
    _baseUrl: string,
    _response: HttpResponse,
    jsContent: string
  ): Promise<TechStackInfo> {
    const techStack: TechStackInfo = {};

    // Check response headers
    const server = _response.headers['server'];
    if (server) {
      techStack.server = server;
    }

    const poweredBy = _response.headers['x-powered-by'];
    if (poweredBy) {
      techStack.poweredBy = poweredBy;
    }

    // Check for frameworks in JS content
    const frameworkPatterns: Array<{ name: string; pattern: RegExp }> = [
      { name: 'react', pattern: /React\.createElement|react\.[\w.]+production/i },
      { name: 'vue', pattern: /Vue\.\d|createApp\(|__vue__/i },
      { name: 'angular', pattern: /angular|ng-version|ng-[\w-]+/i },
      { name: 'nextjs', pattern: /__NEXT_DATA__|_next\/static|next\/router/i },
      { name: 'nuxt', pattern: /__NUXT__|_nuxt\/|nuxt/i },
      { name: 'svelte', pattern: /__svelte_component|svelte/i },
      { name: 'sveltekit', pattern: /__sveltkit|svelte-kit/i },
      { name: 'remix', pattern: /__remixContext|remix/i },
      { name: 'astro', pattern: /__astro|astro/i },
    ];

    const detectedFrameworks: string[] = [];
    for (const { name, pattern } of frameworkPatterns) {
      if (pattern.test(jsContent)) {
        detectedFrameworks.push(name);
      }
    }
    if (detectedFrameworks.length > 0) {
      techStack.frameworks = detectedFrameworks;
    }

    // Check for BaaS providers
    const baasPatterns: Array<{ provider: string; pattern: RegExp }> = [
      { provider: 'supabase', pattern: /supabase|createClient.*supabase|supabaseUrl/i },
      { provider: 'firebase', pattern: /firebase|firebaseApp|initializeApp.*firebase/i },
      { provider: 'appwrite', pattern: /appwrite|Client\(\).*setEndpoint/i },
      { provider: 'amplify', pattern: /amplify|aws-amplify/i },
    ];

    for (const { provider, pattern } of baasPatterns) {
      if (pattern.test(jsContent)) {
        techStack.baas = {
          provider: provider as 'supabase' | 'firebase' | 'other',
          features: this.detectBaaSFeatures(jsContent, provider),
        };
        break;
      }
    }

    // Check for authentication providers
    const authPatterns: Array<{ provider: string; pattern: RegExp }> = [
      { provider: 'auth0', pattern: /auth0|auth0Client/i },
      { provider: 'clerk', pattern: /clerk|clerk-js/i },
      { provider: 'nextauth', pattern: /next-auth|nextauth|NextAuth/i },
      { provider: 'lucia', pattern: /lucia/i },
      { provider: 'better-auth', pattern: /better-auth|betterAuth/i },
    ];

    const authProviders: string[] = [];
    for (const { provider, pattern } of authPatterns) {
      if (pattern.test(jsContent)) {
        authProviders.push(provider);
      }
    }
    if (authProviders.length > 0) {
      techStack.authProviders = authProviders;
    }

    return techStack;
  }

  /**
   * Detect BaaS features
   */
  private detectBaaSFeatures(jsContent: string, provider: string): string[] {
    const features: string[] = [];

    if (provider === 'supabase') {
      if (/from\([^)]+\)/i.test(jsContent)) features.push('database');
      if (/auth\.(signIn|signUp)/i.test(jsContent)) features.push('auth');
      if (/storage\.(from|upload)/i.test(jsContent)) features.push('storage');
      if (/\.rpc\(/i.test(jsContent)) features.push('functions');
    } else if (provider === 'firebase') {
      if (/firestore/i.test(jsContent)) features.push('firestore');
      if (/auth\.(signIn|signUp)/i.test(jsContent)) features.push('auth');
      if (/storage/i.test(jsContent)) features.push('storage');
      if (/functions/i.test(jsContent)) features.push('functions');
    }

    return features;
  }

  /**
   * Detect authentication mechanisms
   */
  private async detectAuthMechanisms(html: string, jsContent: string): Promise<ReconData['authMechanisms']> {
    const mechanisms: ReconData['authMechanisms'] = [];

    // Check for JWT
    if (/jwt|bearer/i.test(jsContent) || /localStorage\.(setItem|getItem).*token/i.test(jsContent)) {
      mechanisms.push({
        type: 'jwt',
        location: 'header',
        flows: [],
      });
    }

    // Check for session cookies
    if (/session|connect\.sid|PHPSESSID/i.test(jsContent)) {
      mechanisms.push({
        type: 'session',
        location: 'cookie',
        flows: [],
      });
    }

    // Check for OAuth
    if (/oauth|signin.*google|signin.*github|signin.*facebook/i.test(html)) {
      mechanisms.push({
        type: 'oauth',
        location: 'query',
        flows: ['redirect'],
      });
    }

    // Check for BaaS auth
    if (/supabase.*auth|firebase.*auth/i.test(jsContent)) {
      mechanisms.push({
        type: 'custom', // changed from 'baas' to match allowed union
        // baas provider needs to go into custom metadata or be dropped if type doesn't support it.
        location: 'header',
        flows: ['email-password', 'oauth'],
      } as any);
    }

    return mechanisms;
  }

  /**
   * Check for source maps
   */
  private async checkSourceMaps(
    bundles: Array<{ url: string; path: string }>
  ): Promise<boolean> {
    for (const bundle of bundles.slice(0, 3)) {
      try {
        // Check if sourceMappingURL exists in the bundle
        const mapUrl = bundle.url + '.map';
        const response = await this.httpClient.get(mapUrl);
        if (response.status === 200) {
          return true;
        }
      } catch {
        // No source map for this bundle
      }
    }
    return false;
  }

  /**
   * Find configuration files
   */
  private async findConfigFiles(baseUrl: string): Promise<ReconData['configFiles']> {
    const configFiles: ReconData['configFiles'] = [];

    const sensitiveFiles = [
      { path: '/.env', sensitive: true },
      { path: '/.env.local', sensitive: true },
      { path: '/.env.production', sensitive: true },
      { path: '/.env.development', sensitive: true },
      { path: '/config.json', sensitive: false },
      { path: '/package.json', sensitive: false },
      { path: '/firebase.json', sensitive: true },
      { path: '/.firebaserc', sensitive: false },
    ];

    for (const file of sensitiveFiles) {
      try {
        const url = new URL(file.path, baseUrl).toString();
        const response = await this.httpClient.get(url);
        if (response.status === 200) {
          configFiles.push({
            path: file.path,
            accessible: true,
            sensitive: file.sensitive,
          });
        }
      } catch {
        // File not accessible
      }
    }

    return configFiles;
  }

  /**
   * Detect VCVF patterns
   */
  private detectVCVFPatterns(
    _html: string,
    jsContent: string,
    techStack: TechStackInfo
  ): Array<{ type: string; locations: Array<{ file: string }>; confidence: number }> {
    const patterns: Array<{ type: any; locations: Array<{ file: string }>; confidence: number }> = [];

    // Check for auth-authz conflation
    if (techStack.baas) {
      // BaaS apps often have auth but missing authz
      const hasClientAuthCheck = /role\s*===?\s*["']admin["']|isAdmin\(|checkRole\(/i.test(jsContent);
      const hasServerAuthzCheck = false; // Can't really detect from client-side

      if (hasClientAuthCheck && !hasServerAuthzCheck) {
        patterns.push({
          type: 'auth_authz_conflation',
          locations: [{ file: 'app.js' }],
          confidence: 0.85,
        });
      }
    }

    // Check for BaaS bypass architecture
    if (techStack.baas) {
      const hasDirectBaaSCalls = /\.from\([^)]+\)\.(select|insert|update|delete)/i.test(jsContent);
      const hasServiceKey = /service_role|supabase_service_role_key/i.test(jsContent);

      if (hasDirectBaaSCalls || hasServiceKey) {
        patterns.push({
          type: 'baas_bypass_architecture',
          locations: [{ file: 'app.js' }],
          confidence: hasServiceKey ? 0.95 : 0.7,
        });
      }
    }

    // Check for optimistic trust patterns
    const hasClientValidation = /required|validate|check.*input/i.test(jsContent);
    const hasServerValidation = false; // Can't detect from client
    if (hasClientValidation && !hasServerValidation) {
      patterns.push({
        type: 'optimistic_trust_patterns',
        locations: [{ file: 'app.js' }],
        confidence: 0.6,
      });
    }

    // Check for missing negative cases (incomplete error handling)
    const hasCatchWithoutHandle = /\.catch\s*\(\s*\(\s*\)\s*=>\s*\{\s*\}|\.catch\s*\(\s*\(\s*\)\s*=>/i.test(jsContent);
    if (hasCatchWithoutHandle) {
      patterns.push({
        type: 'missing_negative_cases',
        locations: [{ file: 'app.js' }],
        confidence: 0.5,
      });
    }

    // Check for over-permissive defaults
    const hasCORSWildcard = /cors.*\*|access-control-allow-origin.*\*/i.test(jsContent);
    if (hasCORSWildcard) {
      patterns.push({
        type: 'over_permissive_defaults',
        locations: [{ file: 'app.js' }],
        confidence: 0.7,
      });
    }

    return patterns;
  }

  /**
   * Analyze data flows
   */
  private analyzeDataFlows(
    _endpoints: DiscoveredEndpoint[],
    jsContent: string
  ): ReconData['dataFlows'] {
    const dataFlows: ReconData['dataFlows'] = [];

    // Look for data flow patterns in JS
    // User input -> processing -> API call
    const inputPatterns = /onChange|onInput|value=\{|formData/i;
    const apiPatterns = /fetch\(|axios\.|\.from\(|\.post\(/i;

    if (inputPatterns.test(jsContent) && apiPatterns.test(jsContent)) {
      dataFlows.push({
        source: 'user_input',
        sink: 'api',
        transformation: 'unknown',
      });
    }

    return dataFlows;
  }

  /**
   * Detect external services
   */
  private detectExternalServices(html: string, jsContent: string): ReconData['externalServices'] {
    const services: ReconData['externalServices'] = [];

    const servicePatterns: Array<{ name: string; pattern: RegExp; type: string }> = [
      { name: 'Google Analytics', pattern: /google-analytics\.com|gtag\(|ga\(/i, type: 'analytics' },
      { name: 'Stripe', pattern: /stripe\.com|Stripe\(/i, type: 'payment' },
      { name: 'Twilio', pattern: /twilio|twilio\.com/i, type: 'communication' },
      { name: 'SendGrid', pattern: /sendgrid|sendgrid\.com/i, type: 'communication' },
      { name: 'OpenAI', pattern: /openai|api\.openai\.com|sk-/i, type: 'ai' },
      { name: 'Anthropic', pattern: /anthropic|api\.anthropic\.com|sk-ant-/i, type: 'ai' },
      { name: 'AWS', pattern: /amazonaws\.com|aws-sdk/i, type: 'cloud' },
      { name: 'Google Cloud', pattern: /googleapis\.com|gcloud/i, type: 'cloud' },
      { name: 'Sentry', pattern: /sentry\.io|Sentry\.init/i, type: 'monitoring' },
      { name: 'LogRocket', pattern: /logrocket|LogRocket\.init/i, type: 'monitoring' },
    ];

    for (const { name, pattern, type } of servicePatterns) {
      if (pattern.test(html) || pattern.test(jsContent)) {
        services.push({ name, type });
      }
    }

    return services;
  }
}