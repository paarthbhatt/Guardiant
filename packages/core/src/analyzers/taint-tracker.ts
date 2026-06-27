import { parse } from '@babel/parser';
import traverse, { NodePath } from '@babel/traverse';
import * as t from '@babel/types';

export interface Source {
  name: string;     // e.g. 'req', 'request'
  property: string; // e.g. 'body', 'query', 'params'
}

export interface Sink {
  object?: string;  // e.g. 'db', 'connection'
  method: string;   // e.g. 'query', 'execute', 'send'
}

export interface Sanitizer {
  name: string;     // e.g. 'escape', 'sanitize', 'parseInt'
}

export interface TaintFlow {
  sourceNode: t.Node;
  sinkNode: t.Node;
  sourceCode: string;
  sinkCode: string;
  sourceLoc: t.SourceLocation;
  sinkLoc: t.SourceLocation;
  isSanitized: boolean;
}

/**
 * TaintTracker implements intra-function data flow analysis.
 * It tracks variables that originate from known sources to known sinks.
 */
export class TaintTracker {
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
      // Syntax error handling
    }
  }

  /**
   * Traces data flows from sources to sinks within the AST.
   */
  public analyzeFlows(sources: Source[], sinks: Sink[], sanitizers: Sanitizer[]): TaintFlow[] {
    if (!this.ast) return [];
    
    const flows: TaintFlow[] = [];
    const code = this.code;
    const traverseFn = (traverse as any).default || traverse;

    // Track variable names that are considered "tainted" in the current scope
    // For a fully robust engine we'd need flow-sensitive analysis, 
    // but for intra-function AST, tracking by binding is a good start.
    const taintedVariables = new Set<string>();

    const getBaseSource = (node: t.Node): {name: string, property: string} | null => {
      if (t.isMemberExpression(node)) {
        if (t.isIdentifier(node.object) && t.isIdentifier(node.property)) {
          return { name: node.object.name, property: node.property.name };
        } else if (t.isMemberExpression(node.object)) {
          return getBaseSource(node.object);
        }
      }
      return null;
    };

    // We'll collect all potential source nodes and sink nodes, 
    // then check if there is a path between them, or simply trace assignments.
    traverseFn(this.ast, {
      VariableDeclarator(path: NodePath<t.VariableDeclarator>) {
        // Check if init is a source
        if (path.node.init && t.isMemberExpression(path.node.init)) {
          const base = getBaseSource(path.node.init);
          if (base) {
            const isSource = sources.some(s => s.name === base.name && s.property === base.property);
            if (isSource) {
              if (t.isIdentifier(path.node.id)) {
                taintedVariables.add(path.node.id.name);
              } else if (t.isObjectPattern(path.node.id)) {
                // Handle destructuring: const { id } = req.body
                for (const prop of path.node.id.properties) {
                  if (t.isObjectProperty(prop) && t.isIdentifier(prop.value)) {
                    taintedVariables.add(prop.value.name);
                  }
                }
              }
            }
          }
        }
      },
      AssignmentExpression(path: NodePath<t.AssignmentExpression>) {
        // Track reassignment (var = taintedVar)
        if (t.isIdentifier(path.node.left) && t.isIdentifier(path.node.right)) {
          if (taintedVariables.has(path.node.right.name)) {
            taintedVariables.add(path.node.left.name);
          }
        }
      },
      CallExpression(path: NodePath<t.CallExpression>) {
        const callee = path.node.callee;
        let isSink = false;
        
        // 1. Check if callee is a known sink (method call or function call)
        if (t.isMemberExpression(callee)) {
          if (t.isIdentifier(callee.property)) {
            const propName = callee.property.name;
            let objName = '';
            
            if (t.isIdentifier(callee.object)) {
              objName = callee.object.name;
            } else if (t.isMemberExpression(callee.object) && t.isIdentifier(callee.object.property)) {
              objName = callee.object.property.name;
            }
            
            isSink = sinks.some(s => s.method === propName && (!s.object || s.object === objName));
          }
        } else if (t.isIdentifier(callee)) {
          // Direct function call, e.g., exec(user_input)
          isSink = sinks.some(s => s.method === callee.name && !s.object);
        }

        if (isSink) {
          // 2. Check if any argument is tainted
          for (const arg of path.node.arguments) {
            let isTainted = false;
            let isSanitized = false;
            let sourceNode: t.Node | null = null;
            
            // Direct use of source, e.g. db.query(req.body.id)
            if (t.isMemberExpression(arg)) {
               const base = getBaseSource(arg);
               if (base) {
                 const isSource = sources.some(s => s.name === base.name && s.property === base.property);
                 if (isSource) {
                   isTainted = true;
                   sourceNode = arg;
                 }
               }
            } 
            // Use of tainted variable, e.g. db.query(id)
            else if (t.isIdentifier(arg)) {
              if (taintedVariables.has(arg.name)) {
                isTainted = true;
                sourceNode = arg; // We point to the variable as the source node for now
              }
            }
            // Template literal, e.g. db.query(`SELECT * FROM users WHERE id = ${id}`)
            else if (t.isTemplateLiteral(arg)) {
              for (const expr of arg.expressions) {
                if (t.isIdentifier(expr) && taintedVariables.has(expr.name)) {
                  isTainted = true;
                  sourceNode = expr;
                } else if (t.isMemberExpression(expr)) {
                   const base = getBaseSource(expr);
                   if (base) {
                     const isSource = sources.some(s => s.name === base.name && s.property === base.property);
                     if (isSource) {
                       isTainted = true;
                       sourceNode = expr;
                     }
                   }
                }
              }
            }
            // Sanitizer wrapper, e.g. db.query(escape(id))
            else if (t.isCallExpression(arg) && t.isIdentifier(arg.callee)) {
              if (sanitizers.some(s => s.name === (arg.callee as t.Identifier).name)) {
                isSanitized = true;
                // Still mark as tainted if the inner arg is tainted, but it's sanitized
                if (arg.arguments.length > 0 && t.isIdentifier(arg.arguments[0])) {
                  if (taintedVariables.has(arg.arguments[0].name)) {
                    isTainted = true;
                    sourceNode = arg.arguments[0];
                  }
                }
              }
            }

            if (isTainted && sourceNode) {
              flows.push({
                sourceNode: sourceNode,
                sinkNode: path.node,
                sourceCode: code.substring(sourceNode.start!, sourceNode.end!),
                sinkCode: code.substring(path.node.start!, path.node.end!),
                sourceLoc: sourceNode.loc!,
                sinkLoc: path.node.loc!,
                isSanitized
              });
            }
          }
        }
      }
    });

    return flows;
  }
}
