import { Finding, RunnerOptions, ScanContext, ScanResult, Severity } from '../types.js';
import { SEVERITY_RANK } from '../utils/constants.js';
import { walkFiles } from './fileWalker.js';
import { detectProjectType } from './projectDetector.js';
import { scanDependencies, type DepScanOptions } from '../scanners/dependencies.js';

export interface AsyncRunnerOptions extends RunnerOptions {
  depOptions?: DepScanOptions;
}

function finalizeFindings(findings: Finding[], minRank: number): Finding[] {
  const filtered = findings.filter(
    (f) => (SEVERITY_RANK[f.severity] ?? 0) >= minRank,
  );

  filtered.sort((a, b) => {
    const rankDiff = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
    if (rankDiff !== 0) return rankDiff;
    const fileDiff = a.file.localeCompare(b.file);
    if (fileDiff !== 0) return fileDiff;
    return a.line - b.line;
  });

  return filtered;
}

function buildContext(options: RunnerOptions): {
  context: ScanContext;
  walkResult: ReturnType<typeof walkFiles>;
} {
  const projectType = detectProjectType(options.root);
  const walkResult = walkFiles(options.root);
  const context: ScanContext = {
    root: options.root,
    projectType,
    files: walkResult.files,
  };
  return { context, walkResult };
}

export function runScan(options: RunnerOptions): ScanResult {
  const startTime = Date.now();
  const minSeverity: Severity = options.minSeverity ?? 'info';
  const minRank = SEVERITY_RANK[minSeverity] ?? 0;

  const { context, walkResult } = buildContext(options);

  const findings: Finding[] = [];
  for (const scanner of options.scanners ?? []) {
    try {
      const scannerFindings = scanner.scan(context);
      if (Array.isArray(scannerFindings)) {
        findings.push(...scannerFindings);
      }
    } catch {
      // scanner error handled gracefully
    }
  }

  return {
    projectType: context.projectType,
    findings: finalizeFindings(findings, minRank),
    filesScanned: walkResult.filesVisited,
    filesSkipped: walkResult.filesSkipped,
    truncated: walkResult.truncated,
    durationMs: Date.now() - startTime,
  };
}

export async function runScanAsync(options: AsyncRunnerOptions): Promise<ScanResult> {
  const startTime = Date.now();
  const minSeverity: Severity = options.minSeverity ?? 'info';
  const minRank = SEVERITY_RANK[minSeverity] ?? 0;

  const { context, walkResult } = buildContext(options);

  const findings: Finding[] = [];

  for (const scanner of options.scanners ?? []) {
    try {
      const scannerFindings = scanner.scan(context);
      if (Array.isArray(scannerFindings)) {
        findings.push(...scannerFindings);
      }
    } catch {
      // scanner error handled gracefully
    }
  }

  try {
    const depFindings = await scanDependencies(context, options.depOptions ?? {});
    findings.push(...depFindings);
  } catch {
    // dependency scanner failure must never crash the tool
  }

  return {
    projectType: context.projectType,
    findings: finalizeFindings(findings, minRank),
    filesScanned: walkResult.filesVisited,
    filesSkipped: walkResult.filesSkipped,
    truncated: walkResult.truncated,
    durationMs: Date.now() - startTime,
  };
}
