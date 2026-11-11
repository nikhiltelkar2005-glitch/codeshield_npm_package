#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { secretsScanner } from './scanners/secrets.js';
import { envScanner } from './scanners/env.js';
import { codeScanner } from './scanners/code.js';
import { fetchRegistry } from './utils/registry.js';
import { isValidNpmName } from './scanners/dependencies.js';
import { runScanAsync } from './engine/runner.js';
import type { Severity } from './types.js';
import { SEVERITY_RANK, SEVERITIES } from './utils/constants.js';
import { sanitize } from './utils/sanitize.js';
import { renderReport, ReportMode, calculateScore } from './report/index.js';
import { runFix } from './fix/fixer.js';
import { readLastScan, saveLastScan, compareWithLastScan } from './fix/history.js';

function getVersion(): string {
  try {
    const currentDir = dirname(fileURLToPath(import.meta.url));
    const pkgPath = resolve(currentDir, '..', 'package.json');
    const content = readFileSync(pkgPath, 'utf8');
    const parsed = JSON.parse(content) as { version?: string };
    return parsed.version ?? '0.1.0';
  } catch {
    return '0.1.0';
  }
}

function isValidSeverity(s: string): s is Severity {
  return (SEVERITIES as readonly string[]).includes(s);
}

const HELP_TEXT = `
CodeShield — Security scanner for AI-generated codebases

Usage:
  codeshield scan [path] [options]    Scan directory (default: current dir)
  codeshield fix [path] [--yes]       Apply safe, reversible fixes automatically
  codeshield verify <package>         Check a single npm package
  codeshield --help                   Show this help
  codeshield --version                Show version

Scan options:
  --detailed                          Show all findings with full metadata
  --json                              Output results as JSON (for CI)
  --sarif                             Output results as SARIF v2.1.0
  --fail-on <severity>                Exit code 1 if findings >= severity
                                      (critical|high|medium|low|info, default: info)
  --severity <severity>               Minimum severity to include in report
                                      (critical|high|medium|low|info, default: info)
  --offline                           Skip npm registry network checks

Fix options:
  -y, --yes                           Skip confirmation prompt and apply fixes

Examples:
  codeshield scan .
  codeshield scan ./my-project --detailed
  codeshield scan . --fail-on high
  codeshield scan . --json
  codeshield scan . --sarif > results.sarif
  codeshield fix .
  codeshield fix ./my-project --yes
  codeshield verify express

Exit codes:
  0   Passed (no findings at or above fail-on threshold)
  1   Findings detected at or above fail-on threshold
  2   Tool error
`.trim();

async function runVerify(pkgName: string): Promise<number> {
  const safeName = sanitize(pkgName);

  if (!isValidNpmName(pkgName)) {
    console.error(`Error: "${safeName}" is not a valid npm package name.`);
    return 2;
  }

  console.log(`Checking "${safeName}" on npm registry…`);

  const result = await fetchRegistry(pkgName, 5_000);

  if (result.status === 'not-found') {
    console.log(`\n🔴 CRITICAL [DEP-001] Package does not exist on npm.`);
    console.log(`  "${safeName}" was not found in the npm registry.`);
    console.log(`  This may be a hallucinated package name from an AI tool.`);
    console.log(`  Verify at https://www.npmjs.com/package/${safeName}`);
    return 1;
  }

  if (result.status === 'error') {
    console.error(`\n⚠️  Could not check "${safeName}": ${sanitize(result.reason)}`);
    console.error(`  The package has NOT been verified as safe.`);
    return 2;
  }

  const { data } = result;
  const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
  let hasFindings = false;

  console.log(`\n✅ Package "${safeName}" exists on npm.`);
  if (data.created) {
    console.log(`  First published : ${data.created}`);
    if (Date.now() - Date.parse(data.created) < thirtyDaysMs) {
      console.log(`  🟠 HIGH [DEP-002] Published less than 30 days ago — verify this is intentional.`);
      hasFindings = true;
    }
  }

  const dangerScripts = (['install', 'postinstall', 'preinstall'] as const).filter(
    (s) => s in data.latestScripts,
  );
  if (dangerScripts.length > 0) {
    console.log(`  🟠 HIGH [DEP-003] Has install script(s): ${dangerScripts.join(', ')}`);
    console.log(`  Audit the script source before installing.`);
    hasFindings = true;
  }

  if (!hasFindings) {
    console.log(`  No issues found. Always review packages before use.`);
  }

  return hasFindings ? 1 : 0;
}

interface ScanCommandOptions {
  targetPath: string;
  offline: boolean;
  minSeverity: Severity;
  failOn: Severity;
  mode: ReportMode;
}

async function runScan(opts: ScanCommandOptions): Promise<number> {
  const root = resolve(opts.targetPath);
  const isStructuredOutput = opts.mode === 'json' || opts.mode === 'sarif';

  if (!isStructuredOutput) {
    console.log(`CodeShield — scanning ${root}`);
    if (opts.offline) console.log('(offline mode: npm registry checks skipped)');
  }

  let result;
  try {
    result = await runScanAsync({
      root,
      minSeverity: opts.minSeverity,
      scanners: [secretsScanner, envScanner, codeScanner],
      depOptions: { offline: opts.offline },
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Error during scan: ${sanitize(msg)}`);
    return 2;
  }

  const scoreDetails = calculateScore(result.findings);
  const previousScan = readLastScan(root);
  let historyText: string | undefined;

  if (previousScan) {
    const comparison = compareWithLastScan(previousScan, scoreDetails.score, result.findings);
    historyText = comparison.summaryText;
  }

  saveLastScan(root, scoreDetails.score, scoreDetails.grade, result.findings);

  const output = renderReport(result, {
    mode: opts.mode,
    version: getVersion(),
    ...(historyText ? { historyText } : {}),
  });

  console.log(output);

  const failOnRank = SEVERITY_RANK[opts.failOn] ?? 0;
  const hasFailingFindings = result.findings.some(
    (f) => (SEVERITY_RANK[f.severity] ?? 0) >= failOnRank,
  );

  return hasFailingFindings ? 1 : 0;
}

export async function runCli(argv: string[] = process.argv.slice(2)): Promise<number> {
  try {
    const { values, positionals } = parseArgs({
      args: argv,
      options: {
        help:       { type: 'boolean', short: 'h', default: false },
        version:    { type: 'boolean', short: 'v', default: false },
        offline:    { type: 'boolean', default: false },
        detailed:   { type: 'boolean', default: false },
        json:       { type: 'boolean', default: false },
        sarif:      { type: 'boolean', default: false },
        yes:        { type: 'boolean', short: 'y', default: false },
        severity:   { type: 'string',  default: 'info' },
        'fail-on':  { type: 'string' },
      },
      allowPositionals: true,
      strict: true,
    });

    if (values.version) {
      console.log(`codeshield v${getVersion()}`);
      return 0;
    }

    if (values.help || positionals.length === 0) {
      console.log(HELP_TEXT);
      return 0;
    }

    const severityArg = values.severity ?? 'info';
    if (!isValidSeverity(severityArg)) {
      console.error(
        `Error: Invalid severity "${sanitize(severityArg)}". ` +
        `Valid values: ${SEVERITIES.join(', ')}`,
      );
      return 2;
    }

    const failOnArg = values['fail-on'] ?? severityArg;
    if (!isValidSeverity(failOnArg)) {
      console.error(
        `Error: Invalid fail-on severity "${sanitize(failOnArg)}". ` +
        `Valid values: ${SEVERITIES.join(', ')}`,
      );
      return 2;
    }

    let mode: ReportMode = 'simple';
    if (values.json) mode = 'json';
    else if (values.sarif) mode = 'sarif';
    else if (values.detailed) mode = 'detailed';

    const command = positionals[0]!;

    if (command === 'scan') {
      const targetPath = positionals[1] ?? '.';
      return await runScan({
        targetPath,
        offline: values.offline ?? false,
        minSeverity: severityArg,
        failOn: failOnArg,
        mode,
      });
    }

    if (command === 'fix') {
      const targetPath = positionals[1] ?? '.';
      return await runFix(targetPath, values.yes ?? false);
    }

    if (command === 'verify') {
      const pkgName = positionals[1];
      if (!pkgName) {
        console.error('Error: "verify" requires a package name. Example: codeshield verify express');
        return 2;
      }
      return await runVerify(pkgName);
    }

    console.error(
      `Error: Unknown command "${sanitize(command)}". Run "codeshield --help" for available commands.`,
    );
    return 2;

  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`Error: ${sanitize(message)}`);
    return 2;
  }
}

const isDirectlyExecuted =
  process.argv[1] !== undefined &&
  (process.argv[1] === fileURLToPath(import.meta.url) ||
    process.argv[1].endsWith('/codeshield') ||
    process.argv[1].endsWith('\\codeshield'));

if (isDirectlyExecuted) {
  const exitCode = await runCli();
  process.exit(exitCode);
}
