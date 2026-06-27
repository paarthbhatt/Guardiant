# Guardiant Scan Action

This GitHub Action runs Guardiant on your codebase and automatically uploads the results to GitHub Security tab (Code Scanning) using the SARIF format.

## Usage

```yaml
name: "Security Scan"

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  guardiant:
    name: Run Guardiant
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Guardiant
        uses: paarthbhatt/Guardiant/.github/actions/guardiant-scan@main
        with:
          target: '.'
          format: 'sarif'
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `target` | Path to scan | `.` |
| `format` | Output format (`sarif`, `json`, `html`, `markdown`) | `sarif` |
| `fail-on-severity` | Fail build if findings meet/exceed severity | `high` |
