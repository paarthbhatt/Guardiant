# Contributing to Guardiant

Thank you for your interest in contributing to Guardiant! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Code Style](#code-style)
- [Testing](#testing)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Adding New Security Agents](#adding-new-security-agents)
- [Adding New VCVF Patterns](#adding-new-vcvf-patterns)

## Code of Conduct

Be respectful, inclusive, and constructive. We welcome contributions from everyone.

## Development Setup

### Prerequisites

- Node.js 20+
- pnpm 9+
- SQLite3 (built-in)
- Redis (optional, for production queue)

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/guardiant/guardiant.git
cd guardiant

# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test

# Set up environment variables
cp .env.example .env
# Edit .env with your API keys
```

### Development Commands

```bash
# Build all packages
pnpm build

# Build specific package
pnpm build --filter=@guardiant/core

# Watch mode for development
pnpm dev

# Run all tests
pnpm test

# Run tests for specific package
pnpm test --filter=@guardiant/core

# Run linting
pnpm lint

# Run type checking
pnpm typecheck

# Run CLI locally
pnpm cli scan https://example.com

# Run web dashboard
pnpm web
```

## Project Structure

```
guardiant/
├── apps/
│   ├── cli/              # CLI application (pnpm cli)
│   └── web/              # Web dashboard (pnpm web)
│
├── packages/
│   ├── core/             # Core logic (agents, analyzers, orchestrator)
│   ├── database/         # SQLite schema and operations
│   ├── queue/            # Job queue system
│   └── shared/           # Shared types and utilities
│
├── tools/
│   └── payloads/         # Attack payload libraries
│
├── docs/                 # Documentation
├── config/               # Configuration files
└── .github/              # GitHub Actions workflows
```

## Code Style

### TypeScript Guidelines

1. **Strict Mode**: All packages use TypeScript strict mode
2. **Explicit Types**: Prefer explicit type annotations for function parameters and returns
3. **Avoid `any`**: Use `unknown` when type is truly unknown, then narrow it
4. **Use `const` assertions**: For literal types and readonly arrays

```typescript
// ✅ Good
export function processFinding(finding: Finding): ProcessedFinding {
  return { ...finding, processed: true };
}

// ❌ Avoid
export function processFinding(finding: any) {
  return { ...finding, processed: true };
}
```

### Naming Conventions

- **Files**: `kebab-case.ts` (e.g., `recon-agent.ts`)
- **Classes**: `PascalCase` (e.g., `ReconAgent`)
- **Interfaces**: `PascalCase` with `I` prefix for interfaces (e.g., `IAgentConfig`)
- **Functions**: `camelCase` (e.g., `processScan`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `MAX_RETRIES`)
- **Types**: `PascalCase` (e.g., `AgentResult`)

### Imports Organization

```typescript
// 1. External packages (alphabetical)
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { z } from 'zod';

// 2. Internal packages (alphabetical)
import { Finding, Severity } from '@guardiant/shared';
import { createFinding } from '@guardiant/core';

// 3. Relative imports (alphabetical)
import { processScan } from './orchestrator.js';
import type { AgentContext } from './types.js';
```

### Error Handling

```typescript
// ✅ Good: Specific error handling with context
try {
  await agent.execute(context);
} catch (error) {
  const message = error instanceof Error ? error.message : 'Unknown error';
  throw new Error(`Agent ${agent.id} failed: ${message}`);
}

// ❌ Avoid: Silent failures
try {
  await agent.execute(context);
} catch {
  // Silently ignored
}
```

## Testing

### Running Tests

```bash
# All tests
pnpm test

# Specific package
pnpm test --filter=@guardiant/core

# Watch mode
pnpm test --watch

# Coverage
pnpm test --coverage
```

### Test Structure

Tests are located in `__tests__` directories adjacent to source files:

```
packages/core/src/
├── agents/
│   ├── recon-agent.ts
│   └── __tests__/
│       └── recon-agent.test.ts
├── analyzers/
│   └── __tests__/
│       ├── cvc-analyzer.test.ts
│       ├── vcvf-matcher.test.ts
│       └── tief-detector.test.ts
└── __tests__/
    └── integration/
        └── pipeline.test.ts
```

### Writing Tests

```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { ReconAgent } from '../recon-agent.js';

describe('ReconAgent', () => {
  let agent: ReconAgent;

  beforeEach(() => {
    agent = new ReconAgent();
  });

  it('should discover endpoints from HTML', async () => {
    const result = await agent.execute(mockContext);
    expect(result.findings).toBeDefined();
    expect(result.metadata.endpointsFound).toBeGreaterThan(0);
  });

  it('should detect Supabase as BaaS provider', async () => {
    // Test implementation
  });
});
```

### Test Coverage Requirements

- **New features**: Minimum 80% coverage
- **Bug fixes**: Must include regression test
- **Core agents**: Minimum 90% coverage
- **Analyzers**: Minimum 85% coverage

## Commit Guidelines

### Commit Message Format

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding/updating tests
- `chore`: Maintenance tasks

### Examples

```
feat(agents): add business logic agent

Add new agent for detecting business logic vulnerabilities including
payment manipulation and rate limiting bypass.

Closes #123
```

```
fix(analyzers): fix CVC chain calculation for compound severity

The compound severity calculation was incorrectly using average instead
of max+contribution formula.

Fixes #456
```

## Pull Request Process

### Before Submitting

1. **Fork and Branch**: Create a feature branch from `main`
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Write Tests**: Ensure all new code has tests

3. **Run Checks**: All checks must pass
   ```bash
   pnpm build
   pnpm test
   pnpm lint
   pnpm typecheck
   ```

4. **Update Documentation**: Update relevant docs

### PR Requirements

- **Title**: Clear, descriptive title following commit format
- **Description**: Explain what and why, not just how
- **Tests**: All tests must pass
- **Coverage**: No coverage decrease
- **Breaking Changes**: Clearly mark any breaking changes

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] All tests pass

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings introduced
```

### Review Process

1. At least one approval required
2. All CI checks must pass
3. No unresolved conversations
4. Squash and merge to `main`

## Adding New Security Agents

### Agent Interface

All agents must extend `AbstractAgent`:

```typescript
// packages/core/src/agents/my-agent.ts
import { AbstractAgent, createFinding } from './base.js';
import type { AgentContext, AgentResult, Finding } from '@guardiant/shared';
import { OWASP_CATEGORIES } from '@guardiant/shared';

export class MyAgent extends AbstractAgent {
  readonly id = 'my_agent' as const;
  readonly name = 'My Security Agent';
  readonly description = 'Description of what this agent detects.';
  readonly categories = [
    OWASP_CATEGORIES.A01_BROKEN_ACCESS_CONTROL.code,
  ];
  readonly priority = 'medium' as const;

  async execute(context: AgentContext): Promise<AgentResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];

    try {
      await this.setup?.(context);

      // Agent logic here
      const results = await this.runTests(context);
      findings.push(...results);

      await this.teardown?.(context);

      return this.createSuccessResult(findings, {
        endpointsTested: context.reconData?.endpoints.length ?? 0,
      }, this.getDuration(startTime));
    } catch (error) {
      return this.createErrorResult(
        error instanceof Error ? error : new Error('Unknown error'),
        this.getDuration(startTime)
      );
    }
  }

  getSystemPrompt(): string {
    return `You are a security testing expert...`;
  }

  buildUserPrompt(context: AgentContext): string {
    return `Test the following target: ${context.target.url}`;
  }

  async parseResponse(response: string, context: AgentContext): Promise<Finding[]> {
    // Parse LLM response into Findings
    return [];
  }

  private async runTests(context: AgentContext): Promise<Finding[]> {
    // Implementation
    return [];
  }
}
```

### Register Agent

```typescript
// packages/core/src/agents/index.ts
export { MyAgent } from './my-agent.js';

// packages/core/src/agents/registry.ts
import { MyAgent } from './my-agent.js';

export const defaultAgents = [
  // ... existing agents
  new MyAgent(),
];
```

### Write Tests

```typescript
// packages/core/src/agents/__tests__/my-agent.test.ts
import { describe, it, expect } from 'vitest';
import { MyAgent } from '../my-agent.js';

describe('MyAgent', () => {
  it('should detect vulnerabilities', async () => {
    // Test implementation
  });
});
```

## Adding New VCVF Patterns

### Pattern Definition

```typescript
// packages/shared/src/constants/vcvf-patterns.ts
export const VCVF_PATTERNS: Record<string, VCVFPattern> = {
  // Existing patterns...

  my_new_pattern: {
    id: 'my_new_pattern',
    name: 'My New Pattern',
    description: 'Description of the pattern',
    severity: 'medium',
    cvssScore: 5.3,
    indicators: [
      /pattern1/,
      /pattern2/,
    ],
    predictedVulnerabilities: [
      'vuln_type_1',
      'vuln_type_2',
    ],
    remediation: {
      summary: 'Fix summary',
      steps: ['Step 1', 'Step 2'],
      effort: 'low',
      priority: 5,
    },
  },
};
```

### Update Matcher

```typescript
// packages/core/src/analyzers/vcvf-matcher.ts
// Add detection logic for the new pattern
```

## Security Considerations

When contributing security-related code:

1. **No Hardcoded Secrets**: Never commit API keys or secrets
2. **Safe Defaults**: Default configurations should be secure
3. **Input Validation**: Always validate external inputs
4. **Error Messages**: Don't leak sensitive information in errors
5. **Payload Safety**: Use safe payload libraries, don't execute malicious code

## Getting Help

- **GitHub Issues**: Report bugs or request features
- **Discussions**: Ask questions or share ideas
- **Documentation**: Check `docs/` directory

## License

By contributing, you agree that your contributions will be licensed under the MIT License.