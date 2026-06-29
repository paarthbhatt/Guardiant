import * as t from '@babel/types';
import traverse from '@babel/traverse';
import type { CodeIndex, RouteHandler } from '../indexer/code-index.js';

export interface DetectionResult {
  type: 'idor' | 'broken_access_control' | 'missing_auth';
  severity: 'critical' | 'high' | 'medium';
  confidence: number;
  evidence: {
    file: string;
    line: number;
    endLine: number;
    snippet: string;
    reasoning: string;
  };
}

export class IDORDetector {
  constructor(_codeIndex: CodeIndex) {}

  // Analyze a route handler for IDOR vulnerability
  public detect(handler: RouteHandler): DetectionResult | null {
    // 1. Check if route has resource ID param (:id, :userId, :leadId, :propertyId, etc.)
    const hasIdParam = handler.params.some(p =>
      /id|user|lead|property|meeting|task|deal|account/i.test(p)
    );
    if (!hasIdParam) return null;

    // 2. Determine if it has auth middleware
    const hasAuth = handler.middleware.some(m => this.isAuthMiddleware(m));
    const hasAdminCheck = handler.middleware.some(m => this.isAdminMiddleware(m));
    const hasOwnershipCheck = handler.middleware.some(m => this.isOwnershipMiddleware(m));

    // 3. Traverse handler AST to find authorization/ownership checks
    const { hasUserCheck, hasOwnershipComparison, hasRLSQuery, hasAdminVerification } = this.analyzeHandlerAST(handler.handlerAst);

    const isSecure = hasOwnershipCheck || hasAdminCheck || hasAdminVerification || (hasAuth && (hasUserCheck || hasOwnershipComparison || hasRLSQuery));

    if (isSecure) {
      return null;
    }

    // Determine vulnerability type
    let type: DetectionResult['type'] = 'idor';
    let severity: DetectionResult['severity'] = 'high';
    let confidence = 0.85;
    let reasoning = '';

    if (!hasAuth) {
      type = 'broken_access_control';
      severity = 'critical';
      confidence = 0.9;
      reasoning = `Endpoint ${handler.method} ${handler.path} has an ID parameter but no authentication middleware, leaving it publicly exposed.`;
    } else {
      type = 'idor';
      severity = 'high';
      // Fix 3: AST-only findings are lower confidence than HTTP-confirmed ones.
      // 0.65 signals the finding warrants review but is not definitively exploitable.
      confidence = 0.65;
      const mwStr = handler.middleware.length ? ` (middleware: [${handler.middleware.join(', ')}])` : '';
      reasoning = `Endpoint ${handler.method} ${handler.path}${mwStr} is authenticated but lacks checks to verify if the requesting user owns or has access to the requested resource ID.`;
    }

    return {
      type,
      severity,
      confidence,
      evidence: {
        file: handler.controllerFile || handler.file,
        line: handler.startLine,
        endLine: handler.endLine,
        snippet: handler.handlerSource.substring(0, 300),
        reasoning,
      },
    };
  }

  private analyzeHandlerAST(fnNode: t.Function): {
    hasUserCheck: boolean;
    hasOwnershipComparison: boolean;
    hasRLSQuery: boolean;
    hasAdminVerification: boolean;
  } {
    let hasUserCheck = false;
    let hasOwnershipComparison = false;
    let hasRLSQuery = false;
    let hasAdminVerification = false;

    const traverseFn = (traverse as any).default || traverse;
    // We wrap fnNode in a file/program to make traverse happy
    const program = t.program([
      (t.isClassMethod(fnNode) ? fnNode : t.expressionStatement(fnNode as t.Expression)) as any
    ]);

    const nodeToString = (node: t.Node): string => {
      if (t.isIdentifier(node)) {
        return node.name;
      }
      if (t.isMemberExpression(node)) {
        const objStr = nodeToString(node.object);
        const propStr = t.isIdentifier(node.property) 
          ? node.property.name 
          : t.isStringLiteral(node.property) 
            ? node.property.value 
            : '';
        return objStr ? `${objStr}.${propStr}` : propStr;
      }
      return '';
    };

    traverseFn(program, {
      noScope: true, // we are analyzing locally
      enter(path: any) {
        const node = path.node;

        // Check for comparisons (e.g. created_by === req.user.id or req.user.id !== item.userId)
        if (t.isBinaryExpression(node) && (node.operator === '===' || node.operator === '==' || node.operator === '!==' || node.operator === '!=')) {
          const leftStr = nodeToString(node.left);
          const rightStr = nodeToString(node.right);

          const hasUserRef = leftStr.startsWith('req.user') || rightStr.startsWith('req.user') ||
                             leftStr.startsWith('req.session') || rightStr.startsWith('req.session') ||
                             leftStr.startsWith('req.auth') || rightStr.startsWith('req.auth');

          const hasIdRef = leftStr.includes('id') || rightStr.includes('id') ||
                           leftStr.includes('created_by') || rightStr.includes('created_by') ||
                           leftStr.includes('owner') || rightStr.includes('owner') ||
                           leftStr.includes('user_id') || rightStr.includes('user_id');

          if (hasUserRef && hasIdRef) {
            hasOwnershipComparison = true;
          }
        }

        // Check for specific function/method calls (e.g., isAdmin, isAdminLevel, checkOwnership)
        if (t.isCallExpression(node)) {
          const callee = node.callee;
          if (t.isIdentifier(callee)) {
            const name = callee.name.toLowerCase();
            if (name.includes('admin') || name.includes('role')) {
              hasAdminVerification = true;
            }
            if (name.includes('owner') || name.includes('access') || name.includes('belong')) {
              hasUserCheck = true;
            }
          } else if (t.isMemberExpression(callee) && t.isIdentifier(callee.property)) {
            const name = callee.property.name.toLowerCase();
            if (name.includes('admin') || name.includes('role')) {
              hasAdminVerification = true;
            }
            if (name.includes('owner') || name.includes('access') || name.includes('belong')) {
              hasUserCheck = true;
            }
          }
        }

        // Check for Supabase select/eq checking ownership (e.g., query.eq('created_by', req.user.id))
        if (t.isCallExpression(node) && t.isMemberExpression(node.callee) && t.isIdentifier(node.callee.property, { name: 'eq' })) {
          const args = node.arguments;
          if (args.length >= 2 && t.isStringLiteral(args[0]) && args[1]) {
            const field = args[0].value;
            if (['created_by', 'user_id', 'owner', 'id', 'uid'].includes(field)) {
              const valStr = nodeToString(args[1] as t.Node);
              if (valStr.startsWith('req.user') || valStr.startsWith('req.auth') || valStr.startsWith('req.session')) {
                hasRLSQuery = true;
              }
            }
          }
        }

        // Check for raw SQL query checking ownership (e.g., WHERE user_id = $2, [req.params.id, req.user.id])
        if (t.isCallExpression(node)) {
          const calleeStr = nodeToString(node.callee);
          if (calleeStr === 'query' || calleeStr.includes('db.query') || calleeStr.includes('pool.query')) {
            const args = node.arguments;
            if (args.length >= 2 && (t.isStringLiteral(args[0]) || t.isTemplateLiteral(args[0]))) {
              const sql = t.isStringLiteral(args[0]) 
                ? args[0].value.toLowerCase() 
                : (args[0] as any).quasis[0]?.value.cooked?.toLowerCase() ?? '';
              
              if (sql.includes('user_id') || sql.includes('owner') || sql.includes('created_by')) {
                if (t.isArrayExpression(args[1])) {
                  for (const elem of args[1].elements) {
                    if (elem) {
                      const valStr = nodeToString(elem as t.Node);
                      if (valStr.startsWith('req.user') || valStr.startsWith('req.auth') || valStr.startsWith('req.session')) {
                        hasRLSQuery = true;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    });

    return {
      hasUserCheck,
      hasOwnershipComparison,
      hasRLSQuery,
      hasAdminVerification,
    };
  }

  private isAuthMiddleware(name: string): boolean {
    const lower = name.toLowerCase();
    return ['auth', 'authenticate', 'requireauth', 'checkauth', 'verified', 'user', 'session'].some(
      keyword => lower.includes(keyword)
    );
  }

  private isAdminMiddleware(name: string): boolean {
    const lower = name.toLowerCase();
    return ['admin', 'isadmin', 'checkadmin', 'requireadmin', 'roleadmin', 'checkpermission'].some(
      keyword => lower.includes(keyword)
    );
  }

  private isOwnershipMiddleware(name: string): boolean {
    const lower = name.toLowerCase();
    // Fix 4a: Keep the known-safe exact list for high-confidence matches.
    const knownOwnershipGuards = [
      'checkleadaccess', 'resolvescope', 'checkpropertyverticalaccess',
      'scopeinventoryquery', 'scopeleadquery', 'scopequery', 'filtervertical',
      'checkverticalaccess', 'requiremydatauser', 'ownnotifications',
    ];
    if (knownOwnershipGuards.some(keyword => lower.includes(keyword))) return true;

    // Fix 4b: Heuristic — any middleware whose name contains a common ownership-
    // guard keyword is treated as a probable ownership check.
    // This prevents false positives for projects that name guards differently
    // (e.g. verifyOwnership, enforceScope, assertAccess, belongsTo, permitUser).
    const ownershipHeuristic = /scope|verify|assert|enforce|own(?:er)?|belong|permit|authoriz/i;
    return ownershipHeuristic.test(name);
  }
}
