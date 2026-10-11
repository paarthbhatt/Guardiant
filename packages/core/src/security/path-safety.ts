import { existsSync, realpathSync } from 'fs';
import { isAbsolute, relative, resolve, sep } from 'path';

/**
 * Return true when candidate is the root itself or a descendant of root.
 * `relative()` is used instead of a string prefix so /tmp/app2 is not treated
 * as a child of /tmp/app.
 */
export function isPathWithinRoot(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/**
 * Resolve an existing path supplied by scan data without crossing the scan
 * root. Realpath validation also prevents a symlink inside the target from
 * redirecting reads or writes outside the target.
 */
export function resolveExistingPathWithinRoot(rootPath: string, candidatePath: string): string | null {
  if (!existsSync(rootPath)) return null;

  try {
    const root = realpathSync(rootPath);
    const lexical = resolve(root, candidatePath);
    if (!isPathWithinRoot(root, lexical) || !existsSync(lexical)) return null;

    const actual = realpathSync(lexical);
    return isPathWithinRoot(root, actual) ? actual : null;
  } catch {
    return null;
  }
}
