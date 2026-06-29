import type { CodeIndex, RouteHandler } from '../indexer/code-index.js';
import type { DetectionResult } from './idor-detector.js';

export class ScopingGapDetector {
  private codeIndex: CodeIndex;

  constructor(codeIndex: CodeIndex) {
    this.codeIndex = codeIndex;
  }

  public detectGaps(): DetectionResult[] {
    const results: DetectionResult[] = [];

    // Group route handlers by file
    const fileRoutes = new Map<string, RouteHandler[]>();
    for (const route of this.codeIndex.routeHandlers) {
      const routes = fileRoutes.get(route.file) ?? [];
      routes.push(route);
      fileRoutes.set(route.file, routes);
    }

    for (const [file, routes] of fileRoutes) {
      // Find routes that have vertical scoping or permission check middleware
      // e.g. scopeInventoryQuery, scopeLeadQuery, scopeQuery, filterVertical, checkVerticalAccess
      const scopingMiddlewareList = ['scopeinventoryquery', 'scopeleadquery', 'scopequery', 'filtervertical', 'checkverticalaccess', 'scopelead', 'checkpropertyverticalaccess'];
      
      const scopingRoutes = routes.filter(r =>
        r.middleware.some(m => scopingMiddlewareList.some(sm => m.toLowerCase().includes(sm)))
      );

      if (scopingRoutes.length === 0) continue;

      // Sibling routes in the same file that do NOT have scoping middleware
      // but have a sensitive endpoint suffix/path like '/export', '/download', '/bulk'
      const adminMiddlewareList = ['admin', 'isadmin', 'requireadmin', 'checkpermission'];

      const unscopedRoutes = routes.filter(r =>
        !r.middleware.some(m => scopingMiddlewareList.some(sm => m.toLowerCase().includes(sm))) &&
        !r.middleware.some(m => adminMiddlewareList.some(am => m.toLowerCase().includes(am)))
      );

      for (const unscoped of unscopedRoutes) {
        const path = unscoped.path.toLowerCase();
        const hasParams = unscoped.params && unscoped.params.length > 0;
        const isSensitiveAction = path.includes('export') || path.includes('download') || path.includes('bulk') || path.includes('delete') || path.includes('update') || hasParams;
        
        if (isSensitiveAction) {
          let reasoning = `Endpoint ${unscoped.method} ${unscoped.path} does not enforce vertical scoping or ownership filtering middleware, while sibling routes in ${file} do. `;
          reasoning += `This allows users to potentially bypass scoping checks and access data across unauthorized verticals/departments.`;

          results.push({
            type: 'broken_access_control',
            severity: 'high',
            confidence: 0.85,
            evidence: {
              file,
              line: unscoped.startLine,
              endLine: unscoped.endLine,
              snippet: unscoped.handlerSource,
              reasoning,
            },
          });
        }
      }
    }

    return results;
  }
}
