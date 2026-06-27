# Taste (Continuously Learned by [CommandCode][cmd])

[cmd]: https://commandcode.ai/

# architecture
- Use parallel orchestration with multiple sub-agents to distribute workload efficiently. Confidence: 0.75
- Prioritize token efficiency — avoid unnecessary token consumption in responses. Confidence: 0.75

# configuration
- Use YAML-based rule configuration system (under rules/ directory) instead of hardcoded patterns in code. Confidence: 0.85
- Organize rule YAML files into subdirectories by category: rules/vcvf/ for vulnerability fingerprint rules, rules/secrets/ for secret detection rules. Confidence: 0.85

# scanning
- Require concrete evidence (HTTP test results or code analysis with file/line/snippet) for all findings — pattern matching alone is insufficient. Confidence: 0.85
- Include negative suppressors in rule definitions: patterns that, if found in the same file, should skip the rule match entirely. Confidence: 0.85
- Perform real HTTP concurrency testing using Promise.all bursts (10x parallel requests) to confirm race conditions, not just static code analysis. Confidence: 0.75
- Perform real HTTP auth testing (actual IDOR, privilege escalation, and JWT manipulation requests) to confirm auth vulnerabilities, not just static pattern analysis. Confidence: 0.75
- Include placeholder/test value detection in secrets scanning to suppress false positives on values containing "example", "test", "placeholder", "dummy", etc. Confidence: 0.80
