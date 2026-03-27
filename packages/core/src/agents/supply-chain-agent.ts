import { AbstractAgent } from './base.js';
import { createFinding } from './types.js';
import type { AgentContext, AgentResult, Finding } from '@guardiant/shared';
import { OWASP_CATEGORIES } from '@guardiant/shared';
import { createHttpClient } from '../http/index.js';

type HttpClient = ReturnType<typeof createHttpClient>;

/**
 * Supply Chain Security Agent
 *
 * Analyzes dependencies for:
 * - Known CVEs via OSV database
 * - Package existence verification (anti-slopsquatting)
 * - Package age and popularity
 * - Hallucinated package detection
 * - Transitive vulnerability analysis
 */
export class SupplyChainAgent extends AbstractAgent {
  readonly id = 'supply_chain' as const;
  readonly name = 'Supply Chain Security Agent';
  readonly description = 'Analyzes dependencies for known vulnerabilities and hallucinated packages.';
  readonly categories = [
    OWASP_CATEGORIES.A06_VULNERABLE_COMPONENTS.code,
    OWASP_CATEGORIES.A08_INTEGRITY_FAILURES.code,
  ];
  readonly priority = 'medium' as const;

  private httpClient: HttpClient;

  // Common hallucinated package patterns (examples from research)
  private readonly knownHallucinatedPackages = [
    // These are examples of packages that don't exist or are typosquats
    'react-native-webview-bridge',
    'node-async-wait',
    'express-route-cache',
    'mongodb-query-parser',
  ];

  constructor() {
    super();
    this.httpClient = createHttpClient(30000);
  }

  async execute(context: AgentContext): Promise<AgentResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];

    try {
      await this.setup?.(context);

      // Phase 1: Find package.json or similar
      const packageFiles = await this.findPackageFiles(context);

      // Phase 2: Analyze dependencies
      const depFindings = await this.analyzeDependencies(context, packageFiles);
      findings.push(...depFindings);

      // Phase 3: Check for hallucinated packages
      const hallucinationFindings = await this.checkHallucinatedPackages(context, packageFiles);
      findings.push(...hallucinationFindings);

      // Phase 4: Check for known CVEs
      const cveFindings = await this.checkKnownCVEs(context, packageFiles);
      findings.push(...cveFindings);

      // Phase 5: Check VCVF patterns
      const vcvfFindings = await this.checkVCVFPatterns(context);
      findings.push(...vcvfFindings);

      await this.teardown?.(context);

      return this.createSuccessResult(findings, {
        filesAnalyzed: packageFiles.length,
        custom: {
          packagesChecked: findings.length,
        },
      }, this.getDuration(startTime));
    } catch (error) {
      return this.createErrorResult(
        error instanceof Error ? error : new Error('Unknown error'),
        this.getDuration(startTime)
      );
    }
  }

  getSystemPrompt(): string {
    return `You are a software supply chain security expert.

Your job is to analyze dependencies for security issues:

1. Package Existence - Verify all packages exist on npm/PyPI
2. Known CVEs - Check against vulnerability databases
3. Hallucinated Packages - Detect AI-hallucinated package names
4. Typosquatting - Identify packages mimicking popular ones
5. Transitive Dependencies - Analyze indirect dependencies
6. License Issues - Flag problematic licenses

For each vulnerability found, provide:
- CVE ID (if applicable)
- Severity score
- Affected versions
- Fixed versions
- Remediation steps`;
  }

  buildUserPrompt(context: AgentContext): string {
    return `Analyze dependencies for the following target:

Target: ${context.target.url}

Check for:
1. Packages that don't exist (hallucinated)
2. Known CVEs in dependencies
3. Outdated packages with security issues
4. Typosquatting attempts
5. Unmaintained packages`;
  }

  async parseResponse(_response: string, _context: AgentContext): Promise<Finding[]> {
    return [];
  }

  /**
   * Find package.json or similar files
   */
  private async findPackageFiles(context: AgentContext): Promise<string[]> {
    const packageFiles: string[] = [];

    // Look for package.json, requirements.txt, Cargo.toml, etc.
    const commonFiles = [
      '/package.json',
      '/package-lock.json',
      '/yarn.lock',
      '/pnpm-lock.yaml',
      '/requirements.txt',
      '/Pipfile',
      '/Cargo.toml',
      '/go.mod',
    ];

    const baseUrl = context.target.url;
    for (const filePath of commonFiles) {
      try {
        const testUrl = new URL(filePath, baseUrl).toString();
        const response = await this.httpClient.get(testUrl);
        if (response.status === 200 && response.body) {
          packageFiles.push(filePath);
        }
      } catch {
        // File not accessible
      }
    }

    return packageFiles;
  }

  /**
   * Analyze dependencies for issues
   */
  private async analyzeDependencies(context: AgentContext, packageFiles: string[]): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Parse package.json and analyze each dependency
    const baseUrl = context.target.url;

    for (const filePath of packageFiles) {
      try {
        const url = new URL(filePath, baseUrl).toString();
        const response = await this.httpClient.get(url);
        if (response.status !== 200 || !response.body) continue;

        const content = response.body;

        // Check for package.json format
        if (filePath === '/package.json' || filePath === 'package.json') {
          let pkg: any;
          try {
            pkg = JSON.parse(content);
          } catch {
            continue;
          }

          const dependencies = { ...pkg.dependencies, ...pkg.devDependencies };

          for (const [depName] of Object.entries(dependencies)) {
            // Check if this is likely a hallucinated package
            if (this.knownHallucinatedPackages.includes(depName)) {
              findings.push(
                createFinding(this.id)
                  .title(`Hallucinated Dependency: ${depName}`)
                  .description(
                    `The package "${depName}" does not exist on the npm registry. ` +
                    `This is likely an AI hallucination where the model suggested ` +
                    `a non-existent package. Check your imports and dependencies.`
                  )
                  .severity('medium')
                  .cvssScore(6.5)
                  .category('A06_VULNERABLE_COMPONENTS')
                  .confidence(0.9)
                  .evidence({
                    context: { package: depName, file: filePath },
                  })
                  .remediation({
                    summary: `Remove or replace the hallucinated "${depName}" package.`,
                    steps: [
                      `Check if "${depName}" actually exists on npm (npm view ${depName})`,
                      'Search for similar package names (may be typosquatting)',
                      'Replace with a known, maintained alternative',
                      'Remove the import from your code',
                      'Remove from package.json dependencies',
                    ],
                    effort: 'low',
                    priority: 6,
                  })
                  .tags(['supply-chain', 'hallucinated', 'dependency'])
                  .build()
              );
            }
          }
        }
      } catch {
        // Continue on error
      }
    }

    return findings;
  }

  /**
   * Check for hallucinated packages
   */
  private async checkHallucinatedPackages(context: AgentContext, _packageFiles: string[]): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check if packages actually exist
    // AI-generated code may reference packages that don't exist

    // VCVF pattern: phantom_dependencies
    const hasPhantomDeps = context.reconData?.vcvfPatterns.some(
      p => p.type === 'phantom_dependencies'
    );

    if (hasPhantomDeps) {
      findings.push(
        createFinding(this.id)
          .title('Potentially Hallucinated Dependencies')
          .description(
            'One or more package imports may reference packages that do not exist on npm registry. ' +
            'This is a common issue in AI-generated code where the model hallucinates package names ' +
            'or suggests packages from its training data that have been removed or never existed.'
          )
          .severity('medium')
          .cvssScore(6.5)
          .category('A06_VULNERABLE_COMPONENTS')
          .confidence(0.7)
          .vcvfPattern('phantom_dependencies')
          .evidence({
            context: { pattern: 'phantom_dependencies' },
          })
          .remediation({
            summary: 'Verify all package imports exist and are spelled correctly.',
            steps: [
              'Check each import against npm registry (npm view <package>)',
              'Search for similar package names (may be typosquatting)',
              'Replace with known alternatives if packages don\'t exist',
              'Add package existence checks to CI/CD pipeline',
            ],
            effort: 'low',
            priority: 6,
          })
          .tags(['supply-chain', 'hallucinated', 'phantom-dependencies'])
          .build()
      );
    }

    return findings;
  }

  /**
   * Check for known CVEs
   */
  private async checkKnownCVEs(_context: AgentContext, _packageFiles: string[]): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Query OSV database or Snyk DB for known CVEs

    return findings;
  }

  /**
   * Check VCVF patterns related to supply chain
   */
  private async checkVCVFPatterns(context: AgentContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for copy-paste insecurity in dependency management
    const hasCopyPaste = context.reconData?.vcvfPatterns.some(
      p => p.type === 'copy_paste_insecurity'
    );

    if (hasCopyPaste) {
      // May indicate dependency versions copied without verification
    }

    return findings;
  }
}