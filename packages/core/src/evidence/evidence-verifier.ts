import type { CodeIndex } from '../indexer/code-index.js';

export interface VerifiedEvidence {
  file: string;
  line: number;
  endLine?: number;
  claimedSnippet: string;
  actualSnippet: string;
  surroundingContext: string;  // 30 lines before/after
  verificationStatus: 'verified' | 'mismatch' | 'unverified';
  similarity: number;  // 0-1, how similar claimed vs actual
}

export class EvidenceVerifier {
  private codeIndex: CodeIndex;

  constructor(codeIndex: CodeIndex) {
    this.codeIndex = codeIndex;
  }

  // Verify a finding's evidence against actual code
  public verify(evidence: { file?: string; line?: number; endLine?: number; snippet?: string }): VerifiedEvidence {
    const defaultResult = (status: 'verified' | 'mismatch' | 'unverified', sim = 0, actual = '', context = ''): VerifiedEvidence => ({
      file: evidence.file ?? '',
      line: evidence.line ?? 0,
      claimedSnippet: evidence.snippet ?? '',
      actualSnippet: actual,
      surroundingContext: context,
      verificationStatus: status,
      similarity: sim,
    });

    if (!evidence.file) {
      return defaultResult('unverified');
    }

    const relPath = evidence.file.replace(/\\/g, '/');
    const parsedFile = this.codeIndex.files.get(relPath);
    if (!parsedFile) {
      // If the file doesn't exist anywhere in the index, it's a mismatch!
      return defaultResult('mismatch');
    }

    // Custom check for configuration file headers/content (handles M1, M7-style findings)
    const fileName = relPath.toLowerCase();
    if (fileName.endsWith('vercel.json') || fileName.endsWith('nginx.conf') || fileName.endsWith('netlify.toml')) {
      const content = parsedFile.source.toLowerCase();
      const desc = (evidence as any).description?.toLowerCase() || '';
      const title = (evidence as any).title?.toLowerCase() || '';

      // Check for common security headers if the finding complains about missing them
      if (desc.includes('header') || title.includes('header') || desc.includes('csp') || title.includes('csp') || desc.includes('options') || title.includes('options')) {
        const headersToCheck = [
          { name: 'x-content-type-options', keywords: ['x-content-type-options', 'nosniff'] },
          { name: 'x-frame-options', keywords: ['x-frame-options', 'deny', 'sameorigin'] },
          { name: 'strict-transport-security', keywords: ['strict-transport-security', 'hsts', 'max-age'] },
          { name: 'referrer-policy', keywords: ['referrer-policy'] },
          { name: 'permissions-policy', keywords: ['permissions-policy'] },
          { name: 'content-security-policy', keywords: ['content-security-policy', 'csp'] },
        ];

        let hasAllAllegedHeaders = true;
        let complainedHeaders = 0;

        for (const h of headersToCheck) {
          const isComplained = desc.includes(h.name) || title.includes(h.name) || 
                             (h.name === 'content-security-policy' && (desc.includes('csp') || title.includes('csp'))) ||
                             (h.name === 'strict-transport-security' && (desc.includes('hsts') || title.includes('hsts')));

          if (isComplained) {
            complainedHeaders++;
            const isPresent = h.keywords.some(k => content.includes(k));
            if (!isPresent) {
              hasAllAllegedHeaders = false;
            }
          }
        }

        // If the finding complains about specific headers, but ALL of those complained headers are present, then it's a mismatch!
        if (complainedHeaders > 0 && hasAllAllegedHeaders) {
          return defaultResult('mismatch', 0, '', 'All complained headers are present in the configuration file.');
        }
      }
    }

    if (typeof evidence.line !== 'number') {
      return defaultResult('unverified');
    }

    const lines = parsedFile.lines;
    const claimedStartLine = evidence.line - 1;
    const claimedEndLine = typeof evidence.endLine === 'number' ? (evidence.endLine - 1) : claimedStartLine;

    if (claimedStartLine < 0 || claimedStartLine >= lines.length) {
      return defaultResult('mismatch');
    }

    // Grab a few lines around the claimed line range to look for the snippet
    const startIdx = Math.max(0, claimedStartLine - 2);
    const endIdx = Math.min(lines.length - 1, claimedEndLine + 2);
    const actualLinesChunk = lines.slice(startIdx, endIdx + 1).join('\n');

    const claimedSnippet = (evidence.snippet ?? '').trim();
    if (!claimedSnippet) {
      return defaultResult('unverified');
    }

    // Calculate similarity
    const similarity = this.computeSimilarity(claimedSnippet, actualLinesChunk);

    // Context: 15 lines before/after (30 lines total)
    const contextStart = Math.max(0, claimedStartLine - 15);
    const contextEnd = Math.min(lines.length - 1, claimedStartLine + 15);
    const contextLines = lines.slice(contextStart, contextEnd + 1);
    const surroundingContext = contextLines
      .map((line, idx) => `${contextStart + idx + 1}: ${line}`)
      .join('\n');

    const status = similarity >= 0.6 ? 'verified' : 'mismatch';
    return defaultResult(status, similarity, lines[claimedStartLine] ?? '', surroundingContext);
  }

  // Simple token-based Jaccard similarity or Levenshtein
  private computeSimilarity(a: string, b: string): number {
    const clean = (str: string) => str.toLowerCase().replace(/[^a-z0-9]/g, ' ').split(/\s+/).filter(Boolean);
    const tokensA = clean(a);
    const tokensB = clean(b);

    if (tokensA.length === 0 || tokensB.length === 0) return 0;

    // Jaccard similarity of words
    const setA = new Set(tokensA);
    const setB = new Set(tokensB);

    let intersection = 0;
    for (const item of setA) {
      if (setB.has(item)) {
        intersection++;
      }
    }

    // Since a snippet might be a subsegment of the chunk, check if a is fully contained in b
    const allContained = tokensA.every(t => tokensB.includes(t));
    if (allContained) {
      return 1.0;
    }

    const union = new Set([...tokensA, ...tokensB]).size;
    return intersection / union;
  }
}
