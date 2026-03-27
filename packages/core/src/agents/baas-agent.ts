import { AbstractAgent } from './base.js';
import { createFinding } from './types.js';
import type { AgentContext, AgentResult, Finding } from '@guardiant/shared';
import { OWASP_CATEGORIES } from '@guardiant/shared';
import { createHttpClient } from '../http/index.js';

/**
 * BaaS Security Agent
 *
 * Tests Backend-as-a-Service specific security issues including:
 * - Supabase RLS (Row Level Security) configuration
 * - Firebase security rules
 * - Service key exposure
 * - Storage bucket permissions
 * - SECURITY DEFINER function analysis
 *
 * This is critical for vibe-coded apps which heavily use BaaS platforms.
 */
export class BaaSsAgent extends AbstractAgent {
  readonly id = 'baas' as const;
  readonly name = 'BaaS Security Agent';
  readonly description = 'Tests BaaS-specific security (Supabase RLS, Firebase rules, service key exposure).';
  readonly categories = [
    OWASP_CATEGORIES.A01_BROKEN_ACCESS_CONTROL.code,
    OWASP_CATEGORIES.A05_SECURITY_MISCONFIGURATION.code,
  ];
  readonly priority = 'critical' as const;

  private httpClient: ReturnType<typeof createHttpClient>;

  constructor(config?: { timeout?: number }) {
    super();
    this.httpClient = createHttpClient(config?.timeout ?? 30000);
  }

  async execute(context: AgentContext): Promise<AgentResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];

    try {
      await this.setup?.(context);

      // Determine BaaS provider from recon data
      const baasProvider = this.detectBaaSProvider(context);

      if (baasProvider === 'none' || baasProvider === 'unknown') {
        // No BaaS detected, skip with info
        return this.createSuccessResult([], {
          endpointsTested: 0,
          custom: { reason: 'No BaaS provider detected' },
        }, this.getDuration(startTime));
      }

      // Run provider-specific tests
      if (baasProvider === 'supabase') {
        findings.push(...await this.testSupabaseSecurity(context));
      } else if (baasProvider === 'firebase') {
        findings.push(...await this.testFirebaseSecurity(context));
      }

      await this.teardown?.(context);

      return this.createSuccessResult(findings, {
        endpointsTested: findings.length,
        custom: { baasProvider },
      }, this.getDuration(startTime));
    } catch (error) {
      return this.createErrorResult(
        error instanceof Error ? error : new Error('Unknown error'),
        this.getDuration(startTime)
      );
    }
  }

  getSystemPrompt(): string {
    return `You are a BaaS security expert specializing in Supabase and Firebase security.

Your job is to identify security misconfigurations in Backend-as-a-Service platforms:

For Supabase:
1. Check if RLS (Row Level Security) is enabled on all tables
2. Analyze RLS policies for overly broad permissions
3. Look for exposed service role keys in client code
4. Check for SECURITY DEFINER functions that bypass RLS
5. Test storage bucket permissions
6. Verify JWT validation

For Firebase:
1. Analyze Firestore security rules
2. Detect test mode configurations
3. Check for public read/write rules
4. Verify storage security rules
5. Look for missing authentication checks

Common vulnerabilities to check:
- Client-side security rules (easily bypassed)
- Service key exposure
- Overly permissive RLS policies
- Missing authentication requirements
- Public storage buckets

Provide detailed findings with remediation steps.`;
  }

  buildUserPrompt(context: AgentContext): string {
    return `Analyze the following BaaS configuration for security issues:

Target: ${context.target.url}
BaaS Provider: ${context.target.baasProvider || 'Unknown'}

${context.reconData ? `Tech Stack: ${JSON.stringify(context.reconData.techStack, null, 2)}` : ''}

Check for:
1. RLS/Security rules enabled
2. Overly permissive policies
3. Exposed service keys
4. Public storage access
5. Missing authentication checks`;
  }

  async parseResponse(_response: string, _context: AgentContext): Promise<Finding[]> {
    // Findings are generated directly by test methods
    return [];
  }

  /**
   * Detect BaaS provider from context
   */
  private detectBaaSProvider(context: AgentContext): 'supabase' | 'firebase' | 'none' | 'unknown' {
    if (context.target.baasProvider) {
      return context.target.baasProvider;
    }

    // Check recon data for BaaS indicators
    if (context.reconData?.techStack?.baas?.provider) {
      return context.reconData.techStack.baas.provider as 'supabase' | 'firebase';
    }

    // Check for BaaS patterns in discovered endpoints
    if (context.reconData?.externalServices) {
      for (const service of context.reconData.externalServices) {
        if (service.name?.toLowerCase().includes('supabase')) return 'supabase';
        if (service.name?.toLowerCase().includes('firebase')) return 'firebase';
      }
    }

    return 'unknown';
  }

  /**
   * Test Supabase-specific security
   */
  private async testSupabaseSecurity(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Test 1: Check for service key exposure
    const serviceKeyFindings = await this.checkServiceKeyExposure(context);
    findings.push(...serviceKeyFindings);

    // Test 2: Check RLS enabled on tables
    const rlsFindings = await this.checkRLSConfiguration(context);
    findings.push(...rlsFindings);

    // Test 3: Check RLS policy analysis
    const policyFindings = await this.analyzeRLSPolicies(context);
    findings.push(...policyFindings);

    // Test 4: Check storage bucket permissions
    const storageFindings = await this.checkStorageBuckets(context);
    findings.push(...storageFindings);

    // Test 5: Check for SECURITY DEFINER functions
    const functionFindings = await this.checkSecurityDefinerFunctions(context);
    findings.push(...functionFindings);

    return findings;
  }

  /**
   * Test Firebase-specific security
   */
  private async testFirebaseSecurity(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Test 1: Check for test mode rules
    const testModeFindings = await this.checkTestModeRules(context);
    findings.push(...testModeFindings);

    // Test 2: Check for public read/write
    const publicAccessFindings = await this.checkPublicAccess(context);
    findings.push(...publicAccessFindings);

    // Test 3: Check storage rules
    const storageFindings = await this.checkFirebaseStorageRules(context);
    findings.push(...storageFindings);

    // Test 4: Check for missing authentication
    const authFindings = await this.checkFirebaseAuthRequirements(context);
    findings.push(...authFindings);

    return findings;
  }

  /**
   * Check for exposed Supabase service role key
   */
  private async checkServiceKeyExposure(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const baseUrl = context.target.url;

    // Patterns that indicate service key exposure
    const criticalPatterns = [
      { pattern: /supabase_service_role_key\s*[=:]\s*['"`]([^'"`]{20,})['"`]/i, name: 'Service Role Key', severity: 'critical' as const },
      { pattern: /SUPABASE_SERVICE_ROLE_KEY\s*[=:]\s*['"`]([^'"`]{20,})['"`]/i, name: 'Service Role Key (env)', severity: 'critical' as const },
      { pattern: /service_role['"`]\s*[,:]?\s*['"`]eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/i, name: 'Service Role JWT', severity: 'critical' as const },
      { pattern: /supabase_service_key\s*[=:]\s*['"`]([^'"`]{20,})['"`]/i, name: 'Service Key', severity: 'critical' as const },
    ];

    // Anon-key patterns (informational only, not flagged as critical)
    // const _anonPatterns = [...]

    // Firebase patterns
    const firebasePatterns = [
      { pattern: /firebase_admin_key/i, name: 'Firebase Admin Key Reference', severity: 'critical' as const },
      { pattern: /private_key\s*=\s*['"`]-----BEGIN PRIVATE KEY-----/i, name: 'Firebase Private Key', severity: 'critical' as const },
      { pattern: /serviceAccount\s*[=:]/i, name: 'Firebase Service Account', severity: 'high' as const },
    ];

    try {
      // Fetch the main page
      const response = await this.httpClient.get(baseUrl);
      const htmlContent = response.body;

      // Extract and check JavaScript bundles
      const jsUrls = this.extractJavaScriptUrls(htmlContent, baseUrl);

      // Fetch up to 5 JS bundles
      const jsContents: string[] = [htmlContent];
      for (const jsUrl of jsUrls.slice(0, 5)) {
        try {
          const jsResponse = await this.httpClient.get(jsUrl);
          if (jsResponse.status === 200 && jsResponse.body) {
            jsContents.push(jsResponse.body);
          }
        } catch {
          // Continue on error
        }
      }

      const combinedContent = jsContents.join('\n');

      // Check for critical patterns
      for (const { pattern, name } of criticalPatterns) {
        const match = combinedContent.match(pattern);
        if (match) {
          findings.push(
            createFinding(this.id)
              .title(`Exposed Supabase ${name}`)
              .description(
                `A Supabase ${name} was found exposed in client-side code. ` +
                `This key bypasses all Row Level Security policies and provides full administrative access ` +
                `to your database. Attackers can extract this key and perform any database operation, ` +
                `including reading all data, modifying records, and deleting tables.`
              )
              .severity('critical')
              .cvssScore(10.0)
              .category('A05_SECURITY_MISCONFIGURATION')
              .confidence(0.95)
              .evidence({
                snippet: match[0].substring(0, 50) + '...',
                pattern: name,
                context: { keyType: 'service_role' },
              })
              .remediation({
                summary: `Remove the ${name} from client-side code immediately.`,
                steps: [
                  'Remove all instances of the service role key from your codebase',
                  'Use environment variables on the server side only',
                  'Never expose service role keys in client-side code',
                  'Consider using Supabase Edge Functions for operations requiring elevated privileges',
                  'Regenerate the service role key in the Supabase dashboard immediately',
                  'Audit your database for any unauthorized access',
                ],
                codeExample: `// ❌ Never do this in client code
const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)

// ✅ Use anon key in client code
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY)

// ✅ Use service role only in server-side code
import { createClient } from '@supabase/supabase-js'
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY // Server-side only!
)`,
                effort: 'low',
                priority: 1,
              })
              .tags(['supabase', 'service-key', 'critical', 'baas-bypass'])
              .vcvfPattern('baas_bypass_architecture')
              .build()
          );
          break; // Only report once per pattern type
        }
      }

      // Check for Firebase patterns
      for (const { pattern, name, severity } of firebasePatterns) {
        const match = combinedContent.match(pattern);
        if (match) {
          findings.push(
            createFinding(this.id)
              .title(`Exposed ${name}`)
              .description(
                `A ${name} was found in client-side code. ` +
                `Firebase service account keys provide full administrative access to your Firebase project. ` +
                `This includes database read/write, authentication management, and cloud function deployment.`
              )
              .severity(severity)
              .cvssScore(severity === 'critical' ? 10.0 : 8.5)
              .category('A05_SECURITY_MISCONFIGURATION')
              .confidence(0.9)
              .evidence({
                snippet: match[0].substring(0, 50) + '...',
                pattern: name,
              })
              .remediation({
                summary: 'Remove service account keys from client-side code.',
                steps: [
                  'Remove the service account key from all client-side code',
                  'Use Firebase Admin SDK only in server-side code',
                  'Regenerate the service account key in Firebase Console',
                  'Review Firebase Security Rules for any unauthorized access',
                ],
                effort: 'low',
                priority: 1,
              })
              .tags(['firebase', 'service-account', 'critical'])
              .build()
          );
        }
      }

    } catch (error) {
      // Log error but continue
      console.error('Error checking service key exposure:', error);
    }

    return findings;
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
      try {
        const url = src!.startsWith('http') ? src! : new URL(src!, baseUrl).toString();
        urls.push(url);
      } catch {
        // Invalid URL
      }
    }

    // Also check for Next.js chunks
    const nextRegex = /["'](_next\/static\/chunks\/[^"']+\.js)["']/gi;
    while ((match = nextRegex.exec(html)) !== null) {
      const src = match[1];
      try {
        const url = new URL(src ?? '', baseUrl).toString();
        urls.push(url);
      } catch {
        // Invalid URL
      }
    }

    return [...new Set(urls)];
  }

  /**
   * Check RLS enabled on all tables
   */
  private async checkRLSConfiguration(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Try to detect Supabase project URL
    const supabaseUrl = await this.detectSupabaseUrl(context);
    if (!supabaseUrl) {
      return findings;
    }

    // Common table names to test
    const commonTables = ['users', 'profiles', 'posts', 'comments', 'messages', 'orders', 'products', 'accounts'];
    const tablesWithoutRLS: string[] = [];

    // Test each table by trying to access it with anon key
    for (const table of commonTables) {
      try {
        // Try to access table without auth - if we get data, RLS might be missing
        const testUrl = `${supabaseUrl}/rest/v1/${table}?select=*&limit=1`;
        const response = await this.httpClient.get(testUrl, {
          'apikey': 'anon',  // Use anon key
          'Authorization': 'Bearer anon',
        });

        // If we get 200 with data, table is accessible without RLS
        if (response.status === 200 && response.body && !response.body.includes('error')) {
          // Try to parse to see if it returns actual data
          try {
            const data = JSON.parse(response.body);
            if (Array.isArray(data) && data.length > 0) {
              tablesWithoutRLS.push(table);
            }
          } catch {
            // Not valid JSON, might be RLS protected
          }
        }
      } catch {
        // Table might not exist or RLS is blocking
      }
    }

    if (tablesWithoutRLS.length > 0) {
      findings.push(
        createFinding(this.id)
          .title('Row Level Security (RLS) Not Enabled or Misconfigured')
          .description(
            `The following tables appear to be accessible without authentication: ${tablesWithoutRLS.join(', ')}. ` +
            'Without proper RLS, all data in these tables may be publicly accessible to anyone with the anon key, ' +
            'which is exposed in client-side code. This is a critical security vulnerability common in ' +
            'vibe-coded applications that use Supabase without proper security configuration.'
          )
          .severity('critical')
          .cvssScore(9.8)
          .category('A01_BROKEN_ACCESS_CONTROL')
          .confidence(0.85)
          .evidence({
            context: { tables: tablesWithoutRLS, rlsEnabled: false },
          })
          .remediation({
            summary: 'Enable Row Level Security on all tables immediately.',
            steps: [
              'Run ALTER TABLE table_name ENABLE ROW LEVEL SECURITY for each table',
              'Create appropriate RLS policies for each table',
              'Test policies to ensure they work correctly',
              'Verify that anon key users can only access public data',
              'Use Supabase Dashboard > Authentication > Policies to configure',
            ],
            codeExample: `-- Enable RLS on a table
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Create a policy that allows users to only see their own data
CREATE POLICY "Users can view own profile" ON users
  FOR SELECT USING (auth.uid() = id);

-- Create a policy for authenticated users
CREATE POLICY "Authenticated users can insert" ON posts
  FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Deny all access to anon users
CREATE POLICY "Deny anon access" ON sensitive_table
  FOR ALL USING (auth.role() = 'authenticated');`,
            effort: 'medium',
            priority: 1,
          })
          .tags(['supabase', 'rls', 'critical', 'baas-bypass'])
          .vcvfPattern('baas_bypass_architecture')
          .build()
      );
    }

    return findings;
  }

  /**
   * Detect Supabase URL from context or content
   */
  private async detectSupabaseUrl(context: AgentContext): Promise<string | null> {
    // Check if we have a known BaaS provider
    if (context.target.baasProvider === 'supabase') {
      // Try to extract from recon data
      const techStack = context.reconData?.techStack;
      if (techStack?.baas?.provider === 'supabase') {
        // Try common Supabase URL patterns
        const baseUrl = new URL(context.target.url);
        const possibleUrls = [
          `https://${baseUrl.hostname.replace(/^[^.]+\./, '')}.supabase.co`,
          // Also check if the app is hosted on a Supabase subdomain
        ];

        for (const url of possibleUrls) {
          try {
            const response = await this.httpClient.get(url);
            if (response.status < 500) {
              return url;
            }
          } catch {
            // Continue
          }
        }
      }
    }

    // Try to find Supabase URL in page content
    try {
      const response = await this.httpClient.get(context.target.url);
      const supabaseUrlMatch = response.body.match(/supabaseUrl\s*[=:]\s*['"`]([^'"`]+)['"`]/i);
      if (supabaseUrlMatch) {
        return supabaseUrlMatch[1] ?? null;
      }

      const projectRefMatch = response.body.match(/([a-z]{20})\.supabase\.co/i);
      if (projectRefMatch) {
        return projectRefMatch[0];
      }
    } catch {
      // Ignore
    }

    return null;
  }

  /**
   * Analyze RLS policies for overly broad permissions
   */
  private async analyzeRLSPolicies(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Fetch JS content to check for RLS policy patterns in code
    try {
      const response = await this.httpClient.get(context.target.url);
      const jsUrls = this.extractJavaScriptUrls(response.body, context.target.url);

      const jsContents: string[] = [response.body];
      for (const jsUrl of jsUrls.slice(0, 5)) {
        try {
          const jsResponse = await this.httpClient.get(jsUrl);
          if (jsResponse.body) {
            jsContents.push(jsResponse.body);
          }
        } catch {
          // Continue
        }
      }

      const combinedContent = jsContents.join('\n');

      // Check for dangerous RLS policy patterns in client code
      // These indicate potential client-side policy definitions (anti-pattern)
      const dangerousPolicyPatterns = [
        { pattern: /\.policy\s*\(\s*['"`]enable_all['"`]/i, name: 'Enable all policy' },
        { pattern: /policy\s*:\s*['"`]public['"`]/i, name: 'Public policy' },
        { pattern: /createPolicy\s*\(\s*\{[^}]*allow\s*:\s*true/i, name: 'Allow all policy' },
      ];

      for (const { pattern, name } of dangerousPolicyPatterns) {
        if (pattern.test(combinedContent)) {
          findings.push(
            createFinding(this.id)
              .title(`Potentially Dangerous RLS Policy: ${name}`)
              .description(
                `Found evidence of potentially overly permissive RLS policy pattern (${name}) in client-side code. ` +
                `This suggests that Row Level Security policies may be configured to allow public access, ` +
                `which defeats the purpose of RLS and exposes all data to unauthenticated users.`
              )
              .severity('high')
              .cvssScore(8.5)
              .category('A01_BROKEN_ACCESS_CONTROL')
              .confidence(0.7)
              .evidence({
                pattern: name,
                context: { policyType: 'overly_permissive' },
              })
              .remediation({
                summary: 'Review and restrict RLS policies to only allow necessary access.',
                steps: [
                  'Audit all RLS policies in Supabase Dashboard > Authentication > Policies',
                  'Replace "allow all" policies with specific conditions',
                  'Use auth.uid() to restrict access to user-owned data',
                  'Test policies with different user roles',
                ],
                codeExample: `-- ❌ Overly permissive policy
CREATE POLICY "Enable all" ON users FOR ALL USING (true);

-- ✅ Proper policy
CREATE POLICY "Users can view own data" ON users
  FOR SELECT USING (auth.uid() = id);

-- ✅ Authenticated users only
CREATE POLICY "Authenticated access" ON posts
  FOR ALL USING (auth.role() = 'authenticated');`,
                effort: 'medium',
                priority: 2,
              })
              .tags(['supabase', 'rls', 'policy', 'overly-permissive'])
              .build()
          );
        }
      }
    } catch {
      // Continue on error
    }

    return findings;
  }

  /**
   * Check storage bucket permissions
   */
  private async checkStorageBuckets(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const supabaseUrl = await this.detectSupabaseUrl(context);

    if (!supabaseUrl) {
      return findings;
    }

    // Common storage bucket names
    const commonBuckets = ['public', 'uploads', 'images', 'files', 'documents', 'avatars'];

    for (const bucket of commonBuckets) {
      try {
        // Try to list files in bucket without auth
        const testUrl = `${supabaseUrl}/storage/v1/object/list/${bucket}`;
        const response = await this.httpClient.post(testUrl, { prefix: '', limit: 100 });

        // If we can list files, bucket might be public
        if (response.status === 200) {
          try {
            const data = JSON.parse(response.body);
            if (Array.isArray(data) && data.length > 0) {
              findings.push(
                createFinding(this.id)
                  .title(`Public Storage Bucket: ${bucket}`)
                  .description(
                    `Storage bucket "${bucket}" appears to be publicly accessible. ` +
                    `Unauthenticated users can list and potentially access files in this bucket. ` +
                    `This may expose sensitive user data, documents, or other uploaded content.`
                  )
                  .severity('high')
                  .cvssScore(7.5)
                  .category('A01_BROKEN_ACCESS_CONTROL')
                  .confidence(0.85)
                  .evidence({
                    bucket,
                    context: { public: true, fileCount: data.length },
                  })
                  .remediation({
                    summary: 'Restrict storage bucket access to authenticated users only.',
                    steps: [
                      'Go to Supabase Dashboard > Storage',
                      'Select the bucket and configure access policies',
                      'Remove public access if not required',
                      'Create policies that restrict access based on user identity',
                    ],
                    codeExample: `-- Storage policy example
CREATE POLICY "Authenticated users can upload"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (bucket_id = 'uploads');

CREATE POLICY "Public read avatars"
ON storage.objects FOR SELECT
TO public
USING (bucket_id = 'avatars');`,
                    effort: 'low',
                    priority: 3,
                  })
                  .tags(['supabase', 'storage', 'public-bucket'])
                  .build()
              );
            }
          } catch {
            // Not valid JSON
          }
        }
      } catch {
        // Bucket not accessible, which is good
      }
    }

    return findings;
  }

  /**
   * Check SECURITY DEFINER functions
   */
  private async checkSecurityDefinerFunctions(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for SECURITY DEFINER usage in client code
    // These functions bypass RLS and can be dangerous
    try {
      const response = await this.httpClient.get(context.target.url);
      const jsUrls = this.extractJavaScriptUrls(response.body, context.target.url);

      const jsContents: string[] = [];
      for (const jsUrl of jsUrls.slice(0, 3)) {
        try {
          const jsResponse = await this.httpClient.get(jsUrl);
          if (jsResponse.body) {
            jsContents.push(jsResponse.body);
          }
        } catch {
          // Continue
        }
      }

      const combinedContent = jsContents.join('\n');

      // Check for RPC calls that might be SECURITY DEFINER
      const rpcCallPatterns = [
        /\.rpc\s*\(\s*['"`]([^'"`]+)['"`]/gi,
        /supabase\.rpc\s*\(/gi,
      ];

      for (const pattern of rpcCallPatterns) {
        const matches = combinedContent.match(pattern);
        if (matches && matches.length > 0) {
          // Found RPC calls - potential SECURITY DEFINER usage
          findings.push(
            createFinding(this.id)
              .title('Potential SECURITY DEFINER Function Usage')
              .description(
                `Found ${matches.length} RPC function calls in client-side code. ` +
                `These functions may use SECURITY DEFINER which bypasses Row Level Security. ` +
                `If these functions perform privileged operations, they could expose sensitive data ` +
                `or allow unauthorized modifications.`
              )
              .severity('medium')
              .cvssScore(6.5)
              .category('A01_BROKEN_ACCESS_CONTROL')
              .confidence(0.6)
              .evidence({
                rpcCalls: matches.slice(0, 5),
                context: { functionType: 'rpc' },
              })
              .remediation({
                summary: 'Review all SECURITY DEFINER functions for proper access control.',
                steps: [
                  'Audit all database functions that use SECURITY DEFINER',
                  'Ensure functions validate user permissions before executing',
                  'Avoid using SECURITY DEFINER unless absolutely necessary',
                  'Add explicit permission checks within function bodies',
                ],
                codeExample: `-- ❌ SECURITY DEFINER without checks
CREATE FUNCTION get_all_users() RETURNS SETOF users
LANGUAGE plpgsql SECURITY DEFINER AS $$
  SELECT * FROM users;
$$;

-- ✅ SECURITY DEFINER with proper checks
CREATE FUNCTION get_own_data() RETURNS SETOF data
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  -- Explicitly check auth
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;
  RETURN QUERY SELECT * FROM data WHERE user_id = auth.uid();
END;
$$;`,
                effort: 'medium',
                priority: 4,
              })
              .tags(['supabase', 'security-definer', 'rpc'])
              .build()
          );
          break; // Only report once
        }
      }
    } catch {
      // Continue on error
    }

    return findings;
  }

  /**
   * Check Firebase test mode rules
   */
  private async checkTestModeRules(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for test mode patterns in JS code
    try {
      const response = await this.httpClient.get(context.target.url);
      const jsUrls = this.extractJavaScriptUrls(response.body, context.target.url);

      const jsContents: string[] = [response.body];
      for (const jsUrl of jsUrls.slice(0, 5)) {
        try {
          const jsResponse = await this.httpClient.get(jsUrl);
          if (jsResponse.body) {
            jsContents.push(jsResponse.body);
          }
        } catch {
          // Continue
        }
      }

      const combinedContent = jsContents.join('\n');

      // Firebase test mode patterns
      const testModePatterns = [
        { pattern: /allow\s+read,\s*write\s*:\s*if\s+true\s*;/i, name: 'Allow all (test mode)' },
        { pattern: /allow\s+\w+\s*:\s*if\s+true\s*;/i, name: 'Allow rule with true condition' },
        { pattern: /rules_version\s*=\s*['"`]2['"`][\s\S]*allow\s+read,\s*write/i, name: 'Firestore rules allowing read/write' },
        { pattern: /request\.time\s*<\s*timestamp\.date\s*\(\s*\d{4}/i, name: 'Time-limited test mode' },
      ];

      for (const { pattern, name } of testModePatterns) {
        if (pattern.test(combinedContent)) {
          findings.push(
            createFinding(this.id)
              .title(`Firebase Test Mode Detected: ${name}`)
              .description(
                `Found evidence of Firebase test mode security rules (${name}). ` +
                `Test mode rules allow unrestricted read/write access to your database. ` +
                `This is acceptable for development but must be disabled before production. ` +
                `Continued use in production exposes all user data.`
              )
              .severity('critical')
              .cvssScore(10.0)
              .category('A05_SECURITY_MISCONFIGURATION')
              .confidence(0.8)
              .evidence({
                pattern: name,
                context: { rulesType: 'test_mode' },
              })
              .remediation({
                summary: 'Replace test mode rules with proper security rules immediately.',
                steps: [
                  'Go to Firebase Console > Firestore > Rules',
                  'Replace test mode rules with proper security rules',
                  'Ensure all collections require authentication for write operations',
                  'Test rules with Firebase emulator',
                  'Deploy rules to production',
                ],
                codeExample: `// ❌ Test mode (NEVER use in production)
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}

// ✅ Production-ready rules
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read: if request.auth != null;
      allow write: if request.auth.uid == userId;
    }
    match /posts/{postId} {
      allow read: if true;
      allow write: if request.auth != null;
    }
  }
}`,
                effort: 'low',
                priority: 1,
              })
              .tags(['firebase', 'test-mode', 'critical', 'firestore-rules'])
              .build()
          );
          break; // Only report once
        }
      }
    } catch {
      // Continue on error
    }

    return findings;
  }

  /**
   * Check for public access in Firebase
   */
  private async checkPublicAccess(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for patterns indicating public database access
    try {
      const response = await this.httpClient.get(context.target.url);

      // Look for Firebase initialization with public config
      // Firebase config patterns omitted (informational, not flagged)

      const jsUrls = this.extractJavaScriptUrls(response.body, context.target.url);
      const jsContents: string[] = [response.body];

      for (const jsUrl of jsUrls.slice(0, 3)) {
        try {
          const jsResponse = await this.httpClient.get(jsUrl);
          if (jsResponse.body) {
            jsContents.push(jsResponse.body);
          }
        } catch {
          // Continue
        }
      }

      const combinedContent = jsContents.join('\n');

      // Check if Firebase config is present (expected, but note it)
      if (/firebaseConfig|initializeApp/i.test(combinedContent)) {
        // Firebase config is present - check for security
        if (/allow\s+\w+\s*:\s*if\s+true/i.test(combinedContent)) {
          findings.push(
            createFinding(this.id)
              .title('Firebase Configuration with Potentially Weak Rules')
              .description(
                `Found Firebase configuration in client-side code with patterns suggesting ` +
                `weak or permissive security rules. While the Firebase config itself is public, ` +
                `the security rules should restrict access properly.`
              )
              .severity('medium')
              .cvssScore(6.5)
              .category('A05_SECURITY_MISCONFIGURATION')
              .confidence(0.7)
              .remediation({
                summary: 'Review Firebase security rules to ensure proper access control.',
                steps: [
                  'Review all Firestore/Realtime Database security rules',
                  'Ensure read/write operations require authentication where appropriate',
                  'Use Firebase Console > Database > Rules to configure',
                ],
                effort: 'medium',
                priority: 4,
              })
              .tags(['firebase', 'security-rules'])
              .build()
          );
        }
      }
    } catch {
      // Continue on error
    }

    return findings;
  }

  /**
   * Check Firebase storage rules
   */
  private async checkFirebaseStorageRules(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Similar check for storage rules
    try {
      const response = await this.httpClient.get(context.target.url);
      const jsUrls = this.extractJavaScriptUrls(response.body, context.target.url);

      for (const jsUrl of jsUrls.slice(0, 3)) {
        try {
          const jsResponse = await this.httpClient.get(jsUrl);
          const content = jsResponse.body;

          // Check for storage upload without auth checks
          if (/ref\(.*put\(|uploadBytes|uploadString/i.test(content || '')) {
            if (!/\.currentUser|auth\.|request\.auth/i.test(content || '')) {
              findings.push(
                createFinding(this.id)
                  .title('Potential Unauthenticated Firebase Storage Upload')
                  .description(
                    `Found storage upload operations without apparent authentication checks. ` +
                    `This could allow unauthenticated users to upload files to your storage buckets, ` +
                    `potentially leading to malicious file uploads, resource abuse, or data leakage.`
                  )
                  .severity('high')
                  .cvssScore(7.5)
                  .category('A01_BROKEN_ACCESS_CONTROL')
                  .confidence(0.65)
                  .remediation({
                    summary: 'Ensure storage uploads require authentication.',
                    steps: [
                      'Verify storage rules require authentication for uploads',
                      'Check file types and sizes before upload',
                      'Implement server-side validation',
                    ],
                    effort: 'medium',
                    priority: 3,
                  })
                  .tags(['firebase', 'storage', 'unauthenticated-upload'])
                  .build()
              );
              break;
            }
          }
        } catch {
          // Continue
        }
      }
    } catch {
      // Continue on error
    }

    return findings;
  }

  /**
   * Check Firebase authentication requirements
   */
  private async checkFirebaseAuthRequirements(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for authentication requirements in client code
    try {
      const response = await this.httpClient.get(context.target.url);
      const jsUrls = this.extractJavaScriptUrls(response.body, context.target.url);

      const jsContents: string[] = [response.body];
      for (const jsUrl of jsUrls.slice(0, 5)) {
        try {
          const jsResponse = await this.httpClient.get(jsUrl);
          if (jsResponse.body) {
            jsContents.push(jsResponse.body);
          }
        } catch {
          // Continue
        }
      }

      const combinedContent = jsContents.join('\n');

      // Check for VCVF pattern: auth-authz conflation
      const hasAuthCheck = /auth\.currentUser|signIn|onAuthStateChanged/i.test(combinedContent);
      const hasClientSideRoleCheck = /role\s*===?\s*['"`]admin['"`]|isAdmin|user\.role/i.test(combinedContent);

      if (hasAuthCheck && hasClientSideRoleCheck) {
        findings.push(
          createFinding(this.id)
            .title('Potential Client-Side Authorization Check')
            .description(
              `Found authentication usage combined with client-side role/authorization checks. ` +
              `This is a common issue in Firebase apps where authorization is enforced only on the client, ` +
              `allowing attackers to bypass role restrictions by modifying client code. ` +
              `Firebase security rules should implement server-side authorization.`
            )
            .severity('high')
            .cvssScore(8.1)
            .category('A01_BROKEN_ACCESS_CONTROL')
            .confidence(0.75)
            .vcvfPattern('auth_authz_conflation')
            .remediation({
              summary: 'Implement server-side authorization in Firebase security rules.',
              steps: [
                'Move role checks from client to Firebase security rules',
                'Use custom claims for user roles',
                'Verify roles server-side in Cloud Functions',
                'Never trust client-side role information',
              ],
              codeExample: `// ❌ Client-side only role check
if (user.role === 'admin') {
  // admin action
}

// ✅ Firebase security rule
match /admin/{document} {
  allow read, write: if request.auth.token.admin == true;
}

// ✅ Server-side role check in Cloud Function
exports.adminAction = functions.https.onCall(async (data, context) => {
  if (!context.auth?.token?.admin) {
    throw new functions.https.HttpsError('permission-denied');
  }
  // proceed
});`,
              effort: 'medium',
              priority: 2,
            })
            .tags(['firebase', 'authorization', 'client-side'])
            .build()
        );
      }
    } catch {
      // Continue on error
    }

    return findings;
  }
}