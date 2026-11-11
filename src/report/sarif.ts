import { Finding, ScanResult, Severity } from '../types.js';
import { sanitize } from '../utils/sanitize.js';

export interface SarifOutput {
  $schema: string;
  version: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: Array<{
          id: string;
          name: string;
          shortDescription: { text: string };
          help: { text: string };
          properties?: Record<string, unknown>;
        }>;
      };
    };
    results: Array<{
      ruleId: string;
      level: 'error' | 'warning' | 'note' | 'none';
      message: { text: string };
      locations: Array<{
        physicalLocation: {
          artifactLocation: { uri: string };
          region: { startLine: number };
        };
      }>;
    }>;
  }>;
}

function severityToSarifLevel(sev: Severity): 'error' | 'warning' | 'note' | 'none' {
  switch (sev) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
    case 'info':
      return 'none';
  }
}

export function formatSarifReport(result: ScanResult, version = '0.1.0'): string {
  const rulesMap = new Map<string, { id: string; name: string; description: string; fix: string; cwe?: string }>();

  for (const f of result.findings) {
    if (!rulesMap.has(f.ruleId)) {
      rulesMap.set(f.ruleId, {
        id: f.ruleId,
        name: sanitize(f.title),
        description: sanitize(f.plainExplanation),
        fix: sanitize(f.fix),
        ...(f.cwe ? { cwe: f.cwe } : {}),
      });
    }
  }

  const sarifRules = Array.from(rulesMap.values()).map(r => ({
    id: r.id,
    name: r.name,
    shortDescription: { text: r.name },
    help: { text: `${r.description}\n\nFix: ${r.fix}` },
    properties: {
      tags: ['security', ...(r.cwe ? [r.cwe] : [])],
    },
  }));

  const sarifResults = result.findings.map(f => ({
    ruleId: f.ruleId,
    level: severityToSarifLevel(f.severity),
    message: { text: `${sanitize(f.title)}: ${sanitize(f.plainExplanation)}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file },
          region: { startLine: Math.max(1, f.line) },
        },
      },
    ],
  }));

  const sarif: SarifOutput = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'CodeShield',
            version,
            informationUri: 'https://github.com/nikhiltelkar2005-glitch/codeshield_npm_package',
            rules: sarifRules,
          },
        },
        results: sarifResults,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
