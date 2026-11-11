import { Finding, ScanContext, Scanner, Severity } from '../types.js';
import { maskSecret, sanitize } from '../utils/sanitize.js';

export interface RuleContext {
  file: string;
  content: string;
  lines: string[];
}

export interface Rule {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  remediation: string;
  check: (context: RuleContext) => Finding[];
}

export interface RegexRuleOptions {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  remediation: string;
  regex: RegExp;
  isSecret?: boolean;
  extensions?: string[];
  customMessage?: (match: RegExpExecArray) => string;
}

export function createLineRegexRule(options: RegexRuleOptions): Rule {
  return {
    id: options.id,
    name: options.name,
    severity: options.severity,
    description: options.description,
    remediation: options.remediation,
    check(context: RuleContext): Finding[] {
      if (options.extensions && options.extensions.length > 0) {
        const matchesExt = options.extensions.some(ext =>
          context.file.toLowerCase().endsWith(ext.toLowerCase())
        );
        if (!matchesExt) return [];
      }

      const findings: Finding[] = [];

      for (let lineIdx = 0; lineIdx < context.lines.length; lineIdx++) {
        const line = context.lines[lineIdx] ?? '';
        const re = new RegExp(options.regex.source, options.regex.flags);

        let match: RegExpExecArray | null;
        while ((match = re.exec(line)) !== null) {
          let snippet = sanitize(line.trim());
          if (options.isSecret) {
            const secretValue = match[1] ?? match[0];
            snippet = snippet.replace(secretValue, maskSecret(secretValue));
          }

          const message = options.customMessage
            ? options.customMessage(match)
            : options.description;

          findings.push({
            ruleId: options.id,
            severity: options.severity,
            title: options.name,
            plainExplanation: message,
            file: context.file,
            line: lineIdx + 1,
            fix: options.remediation,
            aiPrompt: `Fix security issue "${options.name}" (${options.id}): ${message}. Remediation: ${options.remediation}. Code: ${snippet}`,
          });

          if (!re.global) break;
          if (match.index === re.lastIndex) {
            re.lastIndex++;
          }
        }
      }

      return findings;
    },
  };
}
