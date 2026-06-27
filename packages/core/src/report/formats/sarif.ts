import type { Report } from '@guardiant/shared';

/**
 * Format report as SARIF (Static Analysis Results Interchange Format)
 * v2.1.0 JSON format for GitHub Code Scanning compatibility.
 */
export function formatAsSarif(report: Report): string {
  const sarif = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'Guardiant',
            informationUri: 'https://github.com/paarthbhatt/Guardiant',
            version: '0.3.0',
            rules: report.findings.reduce((rules: any[], finding) => {
              const ruleId = `${finding.category}_${finding.title.replace(/\s+/g, '_').toLowerCase()}`;
              if (!rules.find(r => r.id === ruleId)) {
                rules.push({
                  id: ruleId,
                  name: finding.title,
                  shortDescription: { text: finding.title },
                  fullDescription: { text: finding.description },
                  help: { text: finding.remediation?.summary || 'No remediation provided.' },
                  properties: {
                    tags: finding.tags || [],
                    securitySeverity: getSarifSeverity(finding.severity),
                    cvssScore: finding.cvssScore
                  }
                });
              }
              return rules;
            }, [])
          }
        },
        results: report.findings.map(finding => {
          const ruleId = `${finding.category}_${finding.title.replace(/\s+/g, '_').toLowerCase()}`;
          
          return {
            ruleId,
            level: getSarifLevel(finding.severity),
            message: {
              text: finding.description
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: finding.evidence?.file || 'unknown-file'
                  },
                  region: {
                    startLine: finding.evidence?.line || 1,
                    startColumn: finding.evidence?.column || 1,
                    endLine: finding.evidence?.line || 1,
                    endColumn: (finding.evidence?.column || 1) + 1
                  }
                }
              }
            ],
            properties: {
              confidence: finding.confidence,
              vcvfPattern: finding.vcvfPattern,
              tiefIndicator: finding.tiefIndicator
            }
          };
        }),
        properties: {
          scanId: report.scanId,
          target: report.target,
          duration: report.duration,
          timestamp: report.timestamp
        }
      }
    ]
  };

  return JSON.stringify(sarif, null, 2);
}

function getSarifLevel(severity: string): string {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
    default:
      return 'none';
  }
}

function getSarifSeverity(severity: string): string {
  switch (severity) {
    case 'critical': return '9.0';
    case 'high': return '7.0';
    case 'medium': return '4.0';
    case 'low': return '1.0';
    default: return '0.0';
  }
}
