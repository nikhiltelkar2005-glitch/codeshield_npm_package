import { ScanResult } from '../types.js';
import { calculateScore, ScoreDetails } from './score.js';
import { formatSimpleReport, formatDetailedReport, TerminalReportOptions } from './terminal.js';
import { formatSarifReport } from './sarif.js';

export * from './score.js';
export * from './colors.js';
export * from './terminal.js';
export * from './sarif.js';

export type ReportMode = 'simple' | 'detailed' | 'json' | 'sarif';

export interface ReportOptions extends TerminalReportOptions {
  mode?: ReportMode;
  version?: string;
}

export function formatJsonReport(result: ScanResult, scoreDetails?: ScoreDetails): string {
  const details = scoreDetails ?? calculateScore(result.findings);
  const payload = {
    score: details.score,
    grade: details.grade,
    gradeLabel: details.gradeLabel,
    projectType: result.projectType,
    filesScanned: result.filesScanned,
    filesSkipped: result.filesSkipped,
    truncated: result.truncated,
    durationMs: result.durationMs,
    summary: details.countsBySeverity,
    findings: result.findings,
  };
  return JSON.stringify(payload, null, 2);
}

export function renderReport(result: ScanResult, options: ReportOptions = {}): string {
  const mode = options.mode ?? 'simple';
  const scoreDetails = calculateScore(result.findings);

  switch (mode) {
    case 'json':
      return formatJsonReport(result, scoreDetails);
    case 'sarif':
      return formatSarifReport(result, options.version ?? '0.1.0');
    case 'detailed':
      return formatDetailedReport(result, scoreDetails, options);
    case 'simple':
    default:
      return formatSimpleReport(result, scoreDetails, options);
  }
}
