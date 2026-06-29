import * as t from '@babel/types';
import traverse from '@babel/traverse';
import type { CodeIndex } from '../indexer/code-index.js';
import type { DetectionResult } from './idor-detector.js';

export class SessionStorageDetector {
  private codeIndex: CodeIndex;

  constructor(codeIndex: CodeIndex) {
    this.codeIndex = codeIndex;
  }

  // Detect if JWT/session tokens are stored in localStorage
  public detectInFile(filePath: string): DetectionResult | null {
    const relPath = filePath.replace(/\\/g, '/');
    const file = this.codeIndex.files.get(relPath);
    if (!file) return null;

    let result: DetectionResult | null = null;
    const lines = file.lines;
    const traverseFn = (traverse as any).default || traverse;

    traverseFn(file.ast, {
      noScope: true,
      CallExpression(path: any) {
        const callee = path.node.callee;

        // Pattern: localStorage.setItem(key, value)
        if (
          t.isMemberExpression(callee) &&
          t.isIdentifier(callee.object, { name: 'localStorage' }) &&
          t.isIdentifier(callee.property, { name: 'setItem' })
        ) {
          const args = path.node.arguments;
          if (args.length >= 2) {
            const keyArg = args[0];
            let keyVal = '';

            if (t.isStringLiteral(keyArg)) {
              keyVal = keyArg.value;
            } else if (t.isTemplateLiteral(keyArg) && keyArg.quasis[0]) {
              keyVal = keyArg.quasis[0].value.cooked ?? '';
            }

            if (keyVal) {
              const lowerKey = keyVal.toLowerCase();
              // Only keys storing actual sensitive tokens/JWTs
              const isAuthKey = ['token', 'jwt', 'access_token', 'id_token', 'refresh_token', 'auth_token', 'bearer']
                .some(k => lowerKey === k || lowerKey.endsWith('_' + k) || lowerKey.endsWith('-' + k));

              if (isAuthKey) {
                const valueArg = args[1];
                // Check if value is a call expression (e.g. response.data.token) or member expression,
                // representing a dynamic token instead of a static boolean/object
                const isDynamicValue = t.isMemberExpression(valueArg) || 
                                     t.isCallExpression(valueArg) ||
                                     t.isIdentifier(valueArg);

                if (isDynamicValue) {
                  const startLine = path.node.loc?.start.line ?? 1;
                  const endLine = path.node.loc?.end.line ?? startLine;
                  const snippet = lines.slice(startLine - 1, endLine).join('\n');

                  result = {
                    type: 'idor', // mapped to categorizable type, or we can use custom
                    severity: 'high',
                    confidence: 0.9,
                    evidence: {
                      file: relPath,
                      line: startLine,
                      endLine,
                      snippet,
                      reasoning: `Sensitive session/JWT token stored in localStorage with key "${keyVal}". LocalStorage is vulnerable to XSS token theft.`,
                    },
                  };
                  path.stop();
                }
              }
            }
          }
        }
      }
    });

    return result;
  }
}
