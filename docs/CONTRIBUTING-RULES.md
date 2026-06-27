# Contributing VCVF Rules

Guardiant uses VCVF (Vibe Code Vulnerability Fingerprint) patterns defined in YAML to detect security issues across different frameworks, languages, and architectures.

This guide explains how to write new rules.

## Rule Format

Rules are stored in `packages/core/rules/vcvf/` as YAML files.

```yaml
name: "Firebase Vulnerability Patterns"
version: "1.0.0"
rules:
  - id: "firebase-insecure-rules"
    name: "Insecure Firebase Realtime DB Rules"
    description: "Detects Firebase rules that allow public read/write access."
    severity: "critical"
    patterns:
      - type: "code"
        language: "json"
        pattern: '".read": "true"'
      - type: "code"
        language: "json"
        pattern: '".write": "true"'
    remediation: "Implement strict authentication checks in Firebase security rules."
```

## Available Pattern Types

1. **Code Pattern (`code`)**: Simple regex/string matching.
2. **AST Pattern (`ast`)**: Node type matching using AST parsing.
3. **BaaS Indicator (`baas`)**: Identifies BaaS architectures (e.g. Supabase, Firebase).
4. **Taint Pattern (`taint`)**: Data flow analysis (sources to sinks).

## Submitting Rules

1. Fork the repository
2. Add your YAML file to `packages/core/rules/vcvf/`
3. Add a test case demonstrating the vulnerability
4. Open a Pull Request
