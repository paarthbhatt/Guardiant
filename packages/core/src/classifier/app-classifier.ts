import type { AppContext, AppType, ReconData } from '@guardiant/shared';
import { createLogger } from '@guardiant/shared';
import { readFileSync, existsSync, statSync, readdirSync } from 'fs';
import { join, extname } from 'path';

const logger = createLogger({ level: 'info' });

// Route patterns that indicate specific app types
const APP_TYPE_SIGNALS: Record<AppType, RegExp[]> = {
  ecommerce: [
    /\/(checkout|cart|payment|order|product|catalog|shop|store|inventory|shipping|stripe|pay)\b/i,
  ],
  crm: [
    /\/(crm|lead|leads|contact|contacts|pipeline|deal|deals|prospect|prospects|company|companies|customer|customers)\b/i,
  ],
  saas: [
    /\/(tenant|tenants|workspace|workspaces|team|teams|organization|organizations|subscription|billing|plan|plans|usage|quota)\b/i,
  ],
  blog: [
    /\/(blog|posts|articles|cms|categories|tags|comments|author|authors)\b/i,
  ],
  portfolio: [
    /\/(portfolio|projects|showcase|gallery|resume|cv|about)\b/i,
  ],
  social: [
    /\/(feed|follow|followers|like|likes|share|comment|comments|profile|profiles|message|messages|notification|notifications)\b/i,
  ],
  dashboard: [
    /\/(dashboard|admin|analytics|reports|settings|manage|metrics)\b/i,
  ],
  api: [
    /\/(api\/v\d+|graphql|swagger|openapi|docs\/api)\b/i,
  ],
  unknown: [],
};

// Route patterns that indicate payment flows
const PAYMENT_PATTERNS = [
  /\/(checkout|payment|pay|stripe|billing|subscribe|subscription|invoice|refund|charge)\b/i,
  /\/api\/(orders?|transactions?|payments?)\b/i,
];

// Route patterns that indicate auth endpoints
const AUTH_PATTERNS = [
  /\/(auth|login|logout|signin|signup|register|forgot-password|reset-password|verify|oauth|callback)\b/i,
  /\/api\/(auth|session|token)\b/i,
];

// Route patterns that indicate admin/role-gated endpoints
const ADMIN_PATTERNS = [
  /\/(admin|manage|moderator|staff|superuser|dashboard\/admin)\b/i,
];

// Route patterns that indicate file upload
const UPLOAD_PATTERNS = [
  /\/(upload|files|attachments|media|images|documents|avatar)\b/i,
];

// Models commonly found in specific app types
const MODEL_PATTERNS: Record<string, RegExp[]> = {
  ecommerce: [/\b(product|item|cart|order|payment|invoice|coupon|discount|inventory|variant|category)\b/gi],
  crm: [/\b(lead|contact|deal|pipeline|stage|company|prospect|activity|note|task|follow.?up)\b/gi],
  saas: [/\b(tenant|workspace|team|subscription|plan|billing|usage|quota|feature.?flag)\b/gi],
  blog: [/\b(post|article|category|tag|comment|author|draft|published)\b/gi],
  social: [/\b(user|profile|post|comment|like|follow|share|message|notification)\b/gi],
};

// Code patterns that indicate specific features
const FEATURE_PATTERNS = {
  payments: [
    /stripe|paypal|braintree|square|razorpay|checkout\.com/i,
    /processPayment|createCharge|createSubscription|handleCheckout/i,
    /price|amount|total.*req\.body/i,
  ],
  auth: [
    /passport|jsonwebtoken|jose|nextauth|lucia|better-auth|clerk|auth0|supabase.*auth|firebase.*auth/i,
    /requireAuth|isAuthenticated|withAuth|authenticateToken|verifyToken/i,
    /bcrypt|argon2|scrypt.*hash/i,
  ],
  roles: [
    /requireRole|isAuthorized|checkPermission|hasAccess|hasRole|isAdmin|role.*===/i,
    /RBAC|ACL|permission.*check|access.*control/i,
  ],
  baas: [
    /createClient.*supabase|initializeApp.*firebase|createClient.*appwrite/i,
    /supabase\.from|firebase\.firestore|firebase\.database/i,
  ],
  multiTenancy: [
    /tenant[_-]?id|workspace[_-]?id|organization[_-]?id|org[_-]?id/i,
    /tenant.*middleware|multi.*tenant/i,
  ],
};

/**
 * App Classifier — analyzes recon data and source code to classify
 * the application type and produce an AppContext.
 *
 * This runs between Phase 1 (recon) and Phase 2 (agent swarm) so that
 * agents can make context-aware decisions about which checks to run.
 */
export class AppClassifier {
  /**
   * Classify the application from recon data and optional source directory.
   */
  classify(reconData: ReconData | undefined, targetPath?: string): AppContext {
    const routes = this.extractRoutes(reconData);
    const codeContent = this.loadCodeContent(targetPath, reconData);

    const appType = this.detectAppType(routes, codeContent, targetPath);
    const hasPayments = this.detectPayments(routes, codeContent);
    const hasAuth = this.detectAuth(reconData, codeContent);
    const hasUserRoles = this.detectRoles(codeContent);
    const hasBaaS = this.detectBaaS(reconData, codeContent);
    const hasMultiTenancy = this.detectMultiTenancy(codeContent);
    const hasFileUpload = this.detectFileUpload(routes);
    const techStack = this.extractTechStack(reconData);
    const dataModels = this.extractDataModels(routes, codeContent);
    const sensitiveEndpoints = this.extractSensitiveEndpoints(routes);
    const suppressions = this.calculateSuppressions(appType, {
      hasPayments,
      hasAuth,
      hasBaaS,
      hasUserRoles,
    });

    logger.info(
      `App classified as: ${appType} (payments=${hasPayments}, auth=${hasAuth}, ` +
      `roles=${hasUserRoles}, BaaS=${hasBaaS}, suppressions=${suppressions.length})`
    );

    return {
      appType,
      hasPayments,
      hasAuth,
      hasUserRoles,
      hasBaaS,
      hasMultiTenancy,
      hasFileUpload,
      techStack,
      dataModels,
      sensitiveEndpoints,
      suppressions,
    };
  }

  /**
   * Extract route paths from recon data.
   */
  private extractRoutes(reconData: ReconData | undefined): string[] {
    if (!reconData?.endpoints) return [];
    return reconData.endpoints.map(e => `${e.method} ${e.path}`);
  }

  /**
   * Load source code content for pattern analysis.
   * For directory scans, reads relevant source files.
   * For URL scans, uses reconData patterns.
   */
  private loadCodeContent(targetPath: string | undefined, reconData: ReconData | undefined): string {
    const parts: string[] = [];

    // Collect code patterns from recon VCVF data
    if (reconData?.vcvfPatterns) {
      for (const p of reconData.vcvfPatterns) {
        parts.push(...(p.locations?.map(l => l.snippet ?? '') ?? []));
      }
    }

    // If we have a local directory, scan key files
    if (targetPath && existsSync(targetPath)) {
      try {
        const stat = statSync(targetPath);
        if (stat.isDirectory()) {
          parts.push(...this.readKeyFiles(targetPath));
        }
      } catch {
        // ignore
      }
    }

    return parts.join('\n');
  }

  /**
   * Read key files from a directory for classification.
   * Only reads files likely to contain routing/model info.
   */
  private readKeyFiles(rootPath: string): string[] {
    const contents: string[] = [];
    const targetFiles = new Set([
      'package.json', 'routes.ts', 'routes.js', 'router.ts', 'router.js',
      'app.ts', 'app.js', 'server.ts', 'server.js', 'index.ts', 'index.js',
      'schema.ts', 'schema.js', 'models.ts', 'models.js', 'prisma',
      'role.ts', 'role.js', 'roles.ts', 'roles.js', 'guard.ts', 'guard.js',
      'roleguard.ts', 'roleguard.js', 'role-guard.ts', 'role-guard.js',
    ]);

    const scanDir = (dir: string, depth: number): void => {
      if (depth > 5) return; // Scan up to 5 levels deep
      let entries: string[];
      try {
        entries = readdirSync(dir);
      } catch {
        return;
      }

      for (const entry of entries) {
        if (['node_modules', '.git', 'dist', 'build', '.next', '.cache'].includes(entry)) continue;
        const fullPath = join(dir, entry);
        try {
          const stats = statSync(fullPath);
          if (stats.isDirectory()) {
            scanDir(fullPath, depth + 1);
          } else if (stats.isFile()) {
            const ext = extname(fullPath).toLowerCase();
            const filenameLower = entry.toLowerCase();
            const nameWithoutExt = filenameLower.replace(ext, '');
            if (['.ts', '.js', '.json'].includes(ext) && (targetFiles.has(filenameLower) || targetFiles.has(nameWithoutExt))) {
              try {
                contents.push(readFileSync(fullPath, 'utf-8'));
              } catch {
                // skip unreadable
              }
            }
          }
        } catch {
          // skip
        }
      }
    };

    scanDir(rootPath, 0);
    return contents;
  }

  /**
   * Detect the primary application type.
   */
  private detectAppType(routes: string[], code: string, targetPath?: string): AppType {
    const scores: Record<AppType, number> = {
      ecommerce: 0, crm: 0, saas: 0, blog: 0,
      portfolio: 0, social: 0, dashboard: 0, api: 0, unknown: 0,
    };

    // Boost scores based on project directory name hints
    if (targetPath) {
      const folderName = targetPath.toLowerCase();
      if (folderName.includes('crm')) {
        scores['crm'] += 15;
      }
      if (folderName.includes('shop') || folderName.includes('store') || folderName.includes('cart') || folderName.includes('market') || folderName.includes('checkout')) {
        scores['ecommerce'] += 15;
      }
      if (folderName.includes('blog')) {
        scores['blog'] += 15;
      }
      if (folderName.includes('social') || folderName.includes('feed') || folderName.includes('chat')) {
        scores['social'] += 15;
      }
      if (folderName.includes('saas') || folderName.includes('tenant') || folderName.includes('multi')) {
        scores['saas'] += 15;
      }
    }

    const routeStr = routes.join(' ');

    for (const [appType, patterns] of Object.entries(APP_TYPE_SIGNALS)) {
      for (const pattern of patterns) {
        if (pattern.test(routeStr)) {
          scores[appType as AppType] += 3;
        }
        if (pattern.test(code)) {
          scores[appType as AppType] += 1;
        }
      }
    }

    // Model-based scoring
    for (const [appType, patterns] of Object.entries(MODEL_PATTERNS)) {
      for (const pattern of patterns) {
        const routeMatches = routeStr.match(pattern);
        const codeMatches = code.match(pattern);
        scores[appType as AppType] += (routeMatches?.length ?? 0) * 2;
        scores[appType as AppType] += (codeMatches?.length ?? 0);
      }
    }

    // Find the highest-scoring type
    const sorted = Object.entries(scores)
      .filter(([type]) => type !== 'unknown')
      .sort(([, a], [, b]) => b - a);

    const [topType, topScore] = sorted[0] ?? ['unknown', 0];
    const [, secondScore] = sorted[1] ?? ['unknown', 0];

    // Need at least 3 points to classify, and must beat second place
    if (topScore < 3 || (secondScore > 0 && topScore / secondScore < 1.5)) {
      return 'unknown';
    }

    return topType as AppType;
  }

  /**
   * Detect if the app has payment flows.
   */
  private detectPayments(routes: string[], code: string): boolean {
    const routeStr = routes.join(' ');
    for (const pattern of PAYMENT_PATTERNS) {
      if (pattern.test(routeStr)) return true;
    }
    for (const pattern of FEATURE_PATTERNS.payments) {
      if (pattern.test(code)) return true;
    }
    return false;
  }

  /**
   * Detect if the app has authentication.
   */
  private detectAuth(reconData: ReconData | undefined, code: string): boolean {
    if (reconData?.authMechanisms && reconData.authMechanisms.length > 0) return true;
    if (reconData?.techStack?.authProviders && reconData.techStack.authProviders.length > 0) return true;
    for (const pattern of FEATURE_PATTERNS.auth) {
      if (pattern.test(code)) return true;
    }
    return false;
  }

  /**
   * Detect if the app has user roles/permissions.
   */
  private detectRoles(code: string): boolean {
    for (const pattern of FEATURE_PATTERNS.roles) {
      if (pattern.test(code)) return true;
    }
    return false;
  }

  /**
   * Detect if the app uses BaaS.
   */
  private detectBaaS(reconData: ReconData | undefined, code: string): boolean {
    if (reconData?.techStack?.baas) return true;
    for (const pattern of FEATURE_PATTERNS.baas) {
      if (pattern.test(code)) return true;
    }
    return false;
  }

  /**
   * Detect multi-tenancy patterns.
   */
  private detectMultiTenancy(code: string): boolean {
    for (const pattern of FEATURE_PATTERNS.multiTenancy) {
      if (pattern.test(code)) return true;
    }
    return false;
  }

  /**
   * Detect file upload functionality.
   */
  private detectFileUpload(routes: string[]): boolean {
    const routeStr = routes.join(' ');
    for (const pattern of UPLOAD_PATTERNS) {
      if (pattern.test(routeStr)) return true;
    }
    return false;
  }

  /**
   * Extract tech stack from recon data.
   */
  private extractTechStack(reconData: ReconData | undefined): AppContext['techStack'] {
    const ts = reconData?.techStack;
    return {
      framework: ts?.frameworks?.[0] ?? ts?.backendFramework ?? 'unknown',
      backend: ts?.backendFramework ?? 'unknown',
      database: ts?.databaseType ?? 'unknown',
      baas: ts?.baas?.provider,
      auth: ts?.authProviders?.[0] ?? ts?.authMechanism?.provider,
    };
  }

  /**
   * Extract data model names from routes.
   */
  private extractDataModels(routes: string[], code: string): string[] {
    const models = new Set<string>();
    const combined = routes.join(' ') + ' ' + code;

    // Extract from API routes: /api/users → "users"
    const apiRoutePattern = /\/api\/([a-z][a-z0-9_-]*)/gi;
    let match;
    while ((match = apiRoutePattern.exec(combined)) !== null) {
      if (match[1] && !['v1', 'v2', 'v3', 'auth', 'health', 'status'].includes(match[1].toLowerCase())) {
        models.add(match[1].toLowerCase());
      }
    }

    // Extract from Supabase .from('table') patterns
    const supabaseTablePattern = /\.from\s*\(\s*['"]([\w]+)['"]\s*\)/gi;
    while ((match = supabaseTablePattern.exec(code)) !== null) {
      if (match[1]) models.add(match[1].toLowerCase());
    }

    return [...models];
  }

  /**
   * Extract sensitive endpoints from routes.
   */
  private extractSensitiveEndpoints(routes: string[]): string[] {
    const sensitive: string[] = [];
    const routeStr = routes.join('\n');

    for (const pattern of [...PAYMENT_PATTERNS, ...AUTH_PATTERNS, ...ADMIN_PATTERNS]) {
      const matches = routeStr.match(pattern);
      if (matches) {
        sensitive.push(...matches);
      }
    }

    return [...new Set(sensitive)];
  }

  /**
   * Determine which rule IDs should be suppressed for this app type.
   */
  private calculateSuppressions(
    appType: AppType,
    features: { hasPayments: boolean; hasAuth: boolean; hasBaaS: boolean; hasUserRoles: boolean }
  ): string[] {
    const suppressions: string[] = [];

    // Apps without payments should skip payment-related rules
    if (!features.hasPayments) {
      suppressions.push(
        'business_logic.payment_manipulation',
        'business_logic.quantity_manipulation',
        'business_logic.coupon_abuse',
        'race_condition.double_spend',
        'race_condition.coupon_race',
      );
    }

    // Apps without auth should skip auth-related rules
    if (!features.hasAuth) {
      suppressions.push(
        'auth.idor',
        'auth.privilege_escalation',
        'auth.session_management',
        'auth.oauth_flow',
        'auth.jwt_security',
        'auth.password_reset',
        'race_condition.concurrent_registration',
      );
    }

    // Apps without user roles should skip role-related rules
    if (!features.hasUserRoles) {
      suppressions.push(
        'auth.privilege_escalation',
      );
    }

    // App-type-specific suppressions
    switch (appType) {
      case 'blog':
      case 'portfolio':
        suppressions.push(
          'business_logic.feature_flag_bypass',
          'business_logic.workflow_bypass',
          'race_condition.counter_manipulation',
          'race_condition.toctou',
        );
        break;
      case 'api':
        // APIs should run most checks
        break;
      case 'dashboard':
        suppressions.push(
          'business_logic.payment_manipulation',
          'business_logic.quantity_manipulation',
          'business_logic.coupon_abuse',
          'race_condition.double_spend',
          'race_condition.coupon_race',
        );
        break;
    }

    // If no BaaS, suppress BaaS-specific checks
    if (!features.hasBaaS) {
      suppressions.push('baas.rls_check', 'baas.storage_check', 'baas.security_definer');
    }

    return [...new Set(suppressions)];
  }
}

/**
 * Create an AppClassifier instance.
 */
export function createAppClassifier(): AppClassifier {
  return new AppClassifier();
}
