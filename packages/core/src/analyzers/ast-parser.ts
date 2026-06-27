import { parse } from '@babel/parser';
import traverse from '@babel/traverse';
import type { Node, CallExpression } from '@babel/types';

export interface AstMatch {
  node: Node;
  type: string;
  code: string;
  start: number;
  end: number;
  loc: {
    start: { line: number; column: number };
    end: { line: number; column: number };
  };
}

/**
 * Parses JS/TS code into an AST and allows searching for specific patterns.
 */
export class ASTParser {
  private ast: ReturnType<typeof parse> | null = null;
  private code: string = '';

  constructor(code: string) {
    this.code = code;
    try {
      this.ast = parse(code, {
        sourceType: 'module',
        plugins: ['typescript', 'jsx'],
      });
    } catch (e) {
      // If parsing fails (e.g. syntax error), we just leave ast as null
    }
  }

  public isParsable(): boolean {
    return this.ast !== null;
  }

  /**
   * Finds all nodes of a specific type (e.g. 'CallExpression')
   */
  public findNodesByType(type: string): AstMatch[] {
    if (!this.ast) return [];

    const matches: AstMatch[] = [];
    const code = this.code;

    // We use traverse.default because of how babel/traverse is exported in some ESM environments
    const traverseFn = (traverse as any).default || traverse;

    traverseFn(this.ast, {
      enter(path: any) {
        if (path.node.type === type) {
          matches.push({
            node: path.node,
            type: path.node.type,
            code: code.substring(path.node.start!, path.node.end!),
            start: path.node.start!,
            end: path.node.end!,
            loc: path.node.loc!
          });
        }
      }
    });

    return matches;
  }

  /**
   * Finds method calls on a specific object (e.g. db.posts.insert)
   */
  public findMethodCalls(objectNames: string[], methodNames: string[]): AstMatch[] {
    if (!this.ast) return [];

    const matches: AstMatch[] = [];
    const code = this.code;

    const traverseFn = (traverse as any).default || traverse;

    traverseFn(this.ast, {
      CallExpression(path: { node: CallExpression }) {
        const callee = path.node.callee;
        if (callee.type === 'MemberExpression') {
          const property = callee.property;
          
          let propName = '';
          if (property.type === 'Identifier') {
            propName = property.name;
          }
          
          if (methodNames.includes(propName)) {
            // Found the method, now check if the object matches one of objectNames
            // E.g. db.insert -> object is db
            const obj = callee.object;
            let objName = '';
            
            if (obj.type === 'Identifier') {
              objName = obj.name;
            } else if (obj.type === 'MemberExpression' && obj.property.type === 'Identifier') {
              // E.g. db.users.insert -> we can just check the property name (users) or object name (db)
              objName = obj.property.name;
            }

            if (objectNames.length === 0 || objectNames.includes(objName)) {
              matches.push({
                node: path.node,
                type: 'MethodCall',
                code: code.substring(path.node.start!, path.node.end!),
                start: path.node.start!,
                end: path.node.end!,
                loc: path.node.loc!
              });
            }
          }
        }
      }
    });

    return matches;
  }
}
