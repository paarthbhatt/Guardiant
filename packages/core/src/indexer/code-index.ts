import { parse } from '@babel/parser';
import traverse from '@babel/traverse';
import * as t from '@babel/types';
import { readFileSync, statSync, readdirSync } from 'fs';
import { join, relative, extname, dirname, normalize } from 'path';

export interface ParsedFile {
  path: string;
  source: string;
  lines: string[];
  ast: t.File;
  functions: Array<{ name: string; node: t.Function; startLine: number; endLine: number }>;
  imports: Array<{ source: string; specifiers: string[] }>;
}

export interface RouteHandler {
  method: string;       // GET, POST, etc.
  path: string;         // /api/users/:id
  file: string;
  startLine: number;
  endLine: number;
  middleware: string[]; // [auth, isAdmin]
  params: string[];     // [id, userId]
  handlerSource: string; // full handler body source code
  handlerAst: t.Function;
  controllerFile?: string; // resolved controller file path
  routeFile?: string; // route registration file path
}

export interface CodeIndex {
  files: Map<string, ParsedFile>;
  routeHandlers: RouteHandler[];
  middlewareMap: Map<string, string[]>;  // route → middleware chain
}

// Convert an AST node to its string representation (e.g. ctrl.method -> "ctrl.method")
function nodeToString(node: t.Node): string {
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
}

function resolveRelativePath(fromFile: string, relativePath: string): string {
  const fromDir = dirname(fromFile);
  return normalize(join(fromDir, relativePath)).replace(/\\/g, '/');
}

function findFileInIndex(files: Map<string, any>, resolvedPath: string): string | null {
  if (files.has(resolvedPath)) return resolvedPath;
  const extensions = ['.js', '.ts', '.tsx', '.jsx', '/index.js', '/index.ts'];
  for (const ext of extensions) {
    const pathWithExt = resolvedPath + ext;
    if (files.has(pathWithExt)) return pathWithExt;
  }
  return null;
}

export async function buildCodeIndex(rootPath: string): Promise<CodeIndex> {
  const files = new Map<string, ParsedFile>();
  const routeHandlers: RouteHandler[] = [];
  const middlewareMap = new Map<string, string[]>();

  // Map: file_path -> { method_name -> FunctionAST }
  const fileExports = new Map<string, Map<string, t.Function>>();

  // Map: file_path -> { local_variable_name -> resolved_file_path }
  const fileRequires = new Map<string, Map<string, string>>();

  const textExtensions = new Set(['.ts', '.tsx', '.js', '.jsx', '.vue', '.svelte', '.json']);
  const excludeDirs = new Set(['node_modules', '.git', '.next', 'dist', 'build', '.cache', 'coverage']);

  // Pass 1: Parse AST, collect exports & requires, store in files Map
  const walkDir = (dir: string): void => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }

    for (const entry of entries) {
      if (excludeDirs.has(entry) || entry.toLowerCase().includes('guardiant-report') || entry.endsWith('.md')) continue;
      const fullPath = join(dir, entry);
      try {
        const stats = statSync(fullPath);
        if (stats.isDirectory()) {
          walkDir(fullPath);
        } else if (stats.isFile()) {
          const ext = extname(fullPath).toLowerCase();
          if (textExtensions.has(ext)) {
            try {
              const source = readFileSync(fullPath, 'utf-8');
              const relPath = relative(rootPath, fullPath).replace(/\\/g, '/');
              const lines = source.split('\n');

              let ast: t.File;
              if (ext === '.json') {
                ast = t.file(t.program([]));
              } else {
                ast = parse(source, {
                  sourceType: 'module',
                  plugins: ['typescript', 'jsx', 'decorators-legacy'],
                });
              }

              const functions: ParsedFile['functions'] = [];
              const imports: ParsedFile['imports'] = [];
              const exportsMap = new Map<string, t.Function>();
              const requiresMap = new Map<string, string>();

              const traverseFn = (traverse as any).default || traverse;
              traverseFn(ast, {
                Function(path: any) {
                  const node = path.node;
                  let name = 'anonymous';
                  if (t.isFunctionDeclaration(node) && node.id) {
                    name = node.id.name;
                  } else if (t.isVariableDeclarator(path.parent) && t.isIdentifier(path.parent.id)) {
                    name = path.parent.id.name;
                  } else if (t.isObjectProperty(path.parent) && t.isIdentifier(path.parent.key)) {
                    name = path.parent.key.name;
                  } else if (t.isClassMethod(node) && t.isIdentifier(node.key)) {
                    name = node.key.name;
                  }
                  functions.push({
                    name,
                    node,
                    startLine: node.loc?.start.line ?? 0,
                    endLine: node.loc?.end.line ?? 0,
                  });
                },
                ImportDeclaration(path: any) {
                  const node = path.node;
                  const specifiers = node.specifiers.map((s: any) => s.local.name);
                  imports.push({
                    source: node.source.value,
                    specifiers,
                  });

                  // ESM imports mapping
                  const importPath = node.source.value;
                  for (const spec of node.specifiers) {
                    if (t.isImportDefaultSpecifier(spec) || t.isImportNamespaceSpecifier(spec)) {
                      requiresMap.set(spec.local.name, importPath);
                    } else if (t.isImportSpecifier(spec)) {
                      const importedName = t.isIdentifier(spec.imported) ? spec.imported.name : spec.imported.value;
                      requiresMap.set(spec.local.name, `${importPath}:${importedName}`);
                    }
                  }
                },
                // Collect CommonJS exports
                AssignmentExpression(path: any) {
                  const node = path.node;
                  if (t.isMemberExpression(node.left)) {
                    const leftStr = nodeToString(node.left);
                    if (leftStr.startsWith('exports.') || leftStr.startsWith('module.exports.')) {
                      const methodName = leftStr.split('.').pop()!;
                      if (t.isFunction(node.right)) {
                        exportsMap.set(methodName, node.right as t.Function);
                      }
                    }
                  }
                },
                // Collect ESM exports
                ExportNamedDeclaration(path: any) {
                  const node = path.node;
                  const decl = node.declaration;
                  if (decl) {
                    if (t.isFunctionDeclaration(decl) && decl.id) {
                      exportsMap.set(decl.id.name, decl as t.Function);
                    } else if (t.isVariableDeclaration(decl)) {
                      for (const varDecl of decl.declarations) {
                        if (t.isIdentifier(varDecl.id) && varDecl.init && t.isFunction(varDecl.init)) {
                          exportsMap.set(varDecl.id.name, varDecl.init as t.Function);
                        }
                      }
                    }
                  }
                },
                // Collect CommonJS requires
                VariableDeclarator(path: any) {
                  const node = path.node;
                  if (node.init && t.isCallExpression(node.init) && t.isIdentifier(node.init.callee, { name: 'require' })) {
                    const arg = node.init.arguments[0];
                    if (t.isStringLiteral(arg)) {
                      const importPath = arg.value;
                      if (t.isIdentifier(node.id)) {
                        requiresMap.set(node.id.name, importPath);
                      } else if (t.isObjectPattern(node.id)) {
                        for (const prop of node.id.properties) {
                          if (t.isObjectProperty(prop) && t.isIdentifier(prop.key) && t.isIdentifier(prop.value)) {
                            requiresMap.set(prop.value.name, `${importPath}:${prop.key.name}`);
                          }
                        }
                      }
                    }
                  }
                }
              });

              fileExports.set(relPath, exportsMap);
              fileRequires.set(relPath, requiresMap);

              files.set(relPath, {
                path: relPath,
                source,
                lines,
                ast,
                functions,
                imports,
              });
            } catch (e) {
              // AST parsing error
            }
          }
        }
      } catch {
        // Skip inaccessible files
      }
    }
  };

  walkDir(rootPath);

  // Pass 2: Extract route registrations, resolve referenced controller methods, track router.use(...)
  for (const [relPath, parsedFile] of files) {
    // Fix 2: Track middleware per router-object name so that router.use() on one router
    // does not bleed onto an unrelated router defined in the same file.
    // We use a Map from router variable name -> accumulated middleware list.
    // The special key '__global__' is used for app-level middleware.
    const routerMiddlewareByObj = new Map<string, string[]>();
    const getRouterMW = (objName: string): string[] => {
      if (!routerMiddlewareByObj.has(objName)) {
        routerMiddlewareByObj.set(objName, []);
      }
      return routerMiddlewareByObj.get(objName)!;
    };

    const traverseFn = (traverse as any).default || traverse;
    traverseFn(parsedFile.ast, {
      CallExpression(path: any) {
        const node = path.node;
        const callee = node.callee;

        if (
          t.isMemberExpression(callee) &&
          t.isIdentifier(callee.object) &&
          t.isIdentifier(callee.property)
        ) {
          const objName = callee.object.name;
          const propName = callee.property.name;

          // Fix 2: Track router.use(...) middleware scoped to the router variable
          if (
            (objName === 'app' || objName === 'router') &&
            propName === 'use'
          ) {
            const mwList = getRouterMW(objName);
            for (const arg of node.arguments) {
              // Skip string arguments (path prefixes like router.use('/api', subRouter))
              if (t.isStringLiteral(arg)) continue;
              if (t.isIdentifier(arg)) {
                if (!mwList.includes(arg.name)) mwList.push(arg.name);
              } else if (t.isCallExpression(arg) && t.isIdentifier(arg.callee)) {
                const mwName = arg.callee.name;
                if (!mwList.includes(mwName)) mwList.push(mwName);
              }
            }
            return;
          }

          const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch'];
          if (
            (objName === 'app' || objName === 'router' || objName === 'express') &&
            HTTP_METHODS.includes(propName.toLowerCase())
          ) {
            const args = node.arguments;
            if (args.length >= 2 && (t.isStringLiteral(args[0]) || t.isTemplateLiteral(args[0]))) {
              const routePath = t.isStringLiteral(args[0]) 
                ? args[0].value 
                : (args[0].quasis[0]?.value.cooked ?? '');
              const middlewareList: string[] = [...getRouterMW(objName)];
              let handlerNode: t.Function | null = null;
              let handlerSource = '';
              let handlerFile = relPath;
              let controllerFile: string | undefined = undefined;
              let handlerStartLine = node.loc?.start.line ?? 0;
              let handlerEndLine = node.loc?.end.line ?? 0;

              // The last argument is the handler
              const lastArg = args[args.length - 1];

              if (t.isFunction(lastArg)) {
                handlerNode = lastArg as t.Function;
                if (handlerNode.loc) {
                  const start = handlerNode.loc.start.line - 1;
                  const end = handlerNode.loc.end.line;
                  handlerSource = parsedFile.lines.slice(start, end).join('\n');
                }
              } else {
                // Resolve referenced handler (e.g. ctrl.listByLead or listByLead)
                let resolvedTarget: { file: string; method: string } | null = null;

                if (t.isMemberExpression(lastArg) && t.isIdentifier(lastArg.object) && t.isIdentifier(lastArg.property)) {
                  const objLocal = lastArg.object.name;
                  const methodExport = lastArg.property.name;
                  const reqs = fileRequires.get(relPath);
                  const importPath = reqs?.get(objLocal);
                  if (importPath) {
                    const resolvedFile = resolveRelativePath(relPath, importPath);
                    const targetFile = findFileInIndex(files, resolvedFile);
                    if (targetFile) {
                      resolvedTarget = { file: targetFile, method: methodExport };
                    }
                  }
                } else if (t.isIdentifier(lastArg)) {
                  const localName = lastArg.name;
                  const reqs = fileRequires.get(relPath);
                  const importInfo = reqs?.get(localName);
                  if (importInfo) {
                    const parts = importInfo.split(':');
                    const importPath = parts[0]!;
                    const methodName = parts[1] || localName;
                    const resolvedFile = resolveRelativePath(relPath, importPath);
                    const targetFile = findFileInIndex(files, resolvedFile);
                    if (targetFile) {
                      resolvedTarget = { file: targetFile, method: methodName };
                    }
                  }
                }

                // If resolved, retrieve handler AST and source
                if (resolvedTarget) {
                  const exports = fileExports.get(resolvedTarget.file);
                  const fnAst = exports?.get(resolvedTarget.method);
                  if (fnAst) {
                    handlerNode = fnAst;
                    handlerFile = resolvedTarget.file;
                    controllerFile = resolvedTarget.file;
                    handlerStartLine = fnAst.loc?.start.line ?? 0;
                    handlerEndLine = fnAst.loc?.end.line ?? 0;
                    const targetParsed = files.get(resolvedTarget.file);
                    if (targetParsed && fnAst.loc) {
                      handlerSource = targetParsed.lines.slice(fnAst.loc.start.line - 1, fnAst.loc.end.line).join('\n');
                    }
                  }
                }
              }

              // Arguments between route path and handler are middleware
              for (let i = 1; i < args.length - 1; i++) {
                const arg = args[i];
                if (t.isIdentifier(arg)) {
                  middlewareList.push(arg.name);
                } else if (t.isCallExpression(arg) && t.isIdentifier(arg.callee)) {
                  middlewareList.push(arg.callee.name);
                } else if (t.isMemberExpression(arg) && t.isIdentifier(arg.property)) {
                  middlewareList.push(arg.property.name);
                }
              }

              const routeParams: string[] = [];
              const paramMatches = routePath.match(/:([a-zA-Z0-9_]+)/g);
              if (paramMatches) {
                for (const pm of paramMatches) {
                  routeParams.push(pm.slice(1));
                }
              }

              if (handlerNode) {
                routeHandlers.push({
                  method: propName.toUpperCase(),
                  path: routePath,
                  file: handlerFile, // Controller file or route file if inline
                  routeFile: relPath, // Route registration file
                  controllerFile: controllerFile, // Resolved controller file path
                  startLine: handlerStartLine,
                  endLine: handlerEndLine,
                  middleware: middlewareList,
                  params: routeParams,
                  handlerSource,
                  handlerAst: handlerNode,
                });

                middlewareMap.set(`${propName.toUpperCase()}:${routePath}`, middlewareList);
              }
            }
          }
        }
      }
    });
  }

  return {
    files,
    routeHandlers,
    middlewareMap,
  };
}
