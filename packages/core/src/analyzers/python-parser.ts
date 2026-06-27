export interface PythonASTNode {
  type: string;
  text: string;
  startPosition: { row: number; column: number };
  endPosition: { row: number; column: number };
  children: PythonASTNode[];
}

/**
 * A fallback Python parser that uses regex to find basic syntax
 * (since tree-sitter native modules failed to compile)
 */
export class PythonParser {
  /**
   * Parse Python code into a simplified AST structure
   */
  public parse(code: string): PythonASTNode {
    // Dummy root node
    const root: PythonASTNode = {
      type: 'module',
      text: code,
      startPosition: { row: 0, column: 0 },
      endPosition: { row: code.split('\n').length, column: 0 },
      children: [],
    };

    const lines = code.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line) continue;
      
      // Very basic detection of function calls like subprocess.Popen(shell=True)
      if (line.includes('subprocess.Popen') || line.includes('os.system')) {
        root.children.push({
          type: 'call',
          text: line.trim(),
          startPosition: { row: i, column: line.search(/\\S/) },
          endPosition: { row: i, column: line.length },
          children: [
            {
              type: 'identifier',
              text: line.includes('subprocess') ? 'subprocess.Popen' : 'os.system',
              startPosition: { row: i, column: 0 },
              endPosition: { row: i, column: 0 },
              children: []
            }
          ]
        });
      }
      
      // Basic detection of SQL execution
      if (line.includes('.execute(')) {
         root.children.push({
          type: 'call',
          text: line.trim(),
          startPosition: { row: i, column: line.search(/\\S/) },
          endPosition: { row: i, column: line.length },
          children: [
            {
              type: 'identifier',
              text: 'execute',
              startPosition: { row: i, column: 0 },
              endPosition: { row: i, column: 0 },
              children: []
            }
          ]
        });
      }
    }

    return root;
  }

  /**
   * Find nodes of a specific type in the tree
   */
  public findNodes(root: PythonASTNode, type: string): PythonASTNode[] {
    const nodes: PythonASTNode[] = [];
    if (root.type === type) {
      nodes.push(root);
    }
    for (const child of root.children) {
      nodes.push(...this.findNodes(child, type));
    }
    return nodes;
  }
}
