import { Finding, ScanResult, Severity } from '../types.js';
import { SEVERITIES } from '../utils/constants.js';
import { sanitize } from '../utils/sanitize.js';
import { Colorizer, ColorOptions } from './colors.js';
import { ScoreDetails } from './score.js';

export interface TerminalReportOptions extends ColorOptions {
  detailed?: boolean;
  historyText?: string;
}

function formatSummaryLine(
  result: ScanResult,
  scoreDetails: ScoreDetails,
  c: Colorizer,
  options?: TerminalReportOptions,
): string {
  const parts: string[] = [];
  for (const sev of SEVERITIES) {
    const count = scoreDetails.countsBySeverity[sev] ?? 0;
    if (count > 0) {
      parts.push(`${count} ${sev}`);
    }
  }

  const findingsText = parts.length > 0 ? parts.join(', ') : '0 findings';
  const duration = `${result.durationMs}ms`;
  const scanned = `${result.filesScanned} file${result.filesScanned === 1 ? '' : 's'}${result.truncated ? ' (truncated)' : ''}`;

  const lines = [
    `\n${c.dim('────────────────────────────────────────────────────────────')}`,
    `${c.bold('Security Score')} : ${c.scoreBadge(scoreDetails.score, scoreDetails.grade)} (${scoreDetails.gradeLabel})`,
  ];

  if (options?.historyText) {
    lines.push(`${c.bold('Progress      ')} : ${c.cyan(options.historyText)}`);
  }

  lines.push(
    `${c.bold('Files Scanned ')} : ${scanned}`,
    `${c.bold('Findings      ')} : ${scoreDetails.totalFindings} [${findingsText}]`,
    `${c.bold('Duration      ')} : ${duration}`,
    c.dim('────────────────────────────────────────────────────────────'),
  );

  return lines.join('\n');
}

function formatFindingBlock(f: Finding, c: Colorizer, isDetailed = false): string {
  const lines: string[] = [
    `\n${c.severityBadge(f.severity)} [${c.bold(f.ruleId)}] ${c.bold(sanitize(f.title))}`,
    `  ${c.dim('File     ')} : ${c.cyan(sanitize(f.file))}:${c.cyan(String(f.line))}`,
  ];

  if (f.snippet) {
    lines.push(`  ${c.dim('Line     ')} : ${c.dim(sanitize(f.snippet))}`);
  }

  if (isDetailed && f.cwe) {
    lines.push(`  ${c.dim('CWE      ')} : ${sanitize(f.cwe)}`);
  }

  lines.push(`  ${c.dim('Issue    ')} : ${sanitize(f.plainExplanation)}`);
  lines.push(`  ${c.dim('Fix      ')} : ${c.green(sanitize(f.fix))}`);
  lines.push(`  ${c.dim('AI Prompt')} : ${c.bold(sanitize(f.aiPrompt))}`);

  return lines.join('\n');
}

export function formatSimpleReport(
  result: ScanResult,
  scoreDetails: ScoreDetails,
  options?: TerminalReportOptions,
): string {
  const c = new Colorizer(options);
  const out: string[] = [];

  out.push(formatSummaryLine(result, scoreDetails, c, options));

  if (result.findings.length === 0) {
    out.push(`\n${c.bold(c.green('✅ No security issues found. Codebase looks clean!'))}\n`);
    return out.join('\n');
  }

  const topCount = Math.min(5, Math.max(3, Math.min(5, result.findings.length)));
  const topFindings = result.findings.slice(0, topCount);

  out.push(`\n${c.bold('🎯 Fix These First (Top Priorities):')}`);

  for (const f of topFindings) {
    out.push(formatFindingBlock(f, c, false));
  }

  if (result.findings.length > topCount) {
    const remaining = result.findings.length - topCount;
    out.push(
      `\n${c.dim(`... and ${remaining} more finding${remaining === 1 ? '' : 's'}. Run with --detailed to view all findings.`)}`,
    );
  }

  out.push('');
  return out.join('\n');
}

export function formatDetailedReport(
  result: ScanResult,
  scoreDetails: ScoreDetails,
  options?: TerminalReportOptions,
): string {
  const c = new Colorizer(options);
  const out: string[] = [];

  out.push(formatSummaryLine(result, scoreDetails, c, options));

  if (result.findings.length === 0) {
    out.push(`\n${c.bold(c.green('✅ No security issues found. Codebase looks clean!'))}\n`);
    return out.join('\n');
  }

  out.push(`\n${c.bold(`📋 All Findings (${result.findings.length}):`)}`);

  for (const f of result.findings) {
    out.push(formatFindingBlock(f, c, true));
  }

  out.push('');
  return out.join('\n');
}
