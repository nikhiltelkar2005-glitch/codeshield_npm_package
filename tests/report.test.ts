/**
 * tests/report.test.ts
 * Tests for score calculation, color handling, terminal formatters,
 * JSON, and SARIF export in src/report/.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';

import {
  calculateScore,
  Colorizer,
  formatJsonReport,
  formatSarifReport,
  formatSimpleReport,
  formatDetailedReport,
  renderReport,
} from '../src/report/index.js';
import type { Finding, ScanResult } from '../src/types.js';

function makeFinding(opts: {
  ruleId: string;
  severity: Finding['severity'];
  title?: string;
  file?: string;
  line?: number;
  cwe?: string;
}): Finding {
  return {
    ruleId: opts.ruleId,
    severity: opts.severity,
    title: opts.title ?? `Finding for ${opts.ruleId}`,
    plainExplanation: 'Sample explanation for testing.',
    file: opts.file ?? 'src/index.ts',
    line: opts.line ?? 10,
    fix: 'Apply sample fix.',
    aiPrompt: 'Fix this issue.',
    ...(opts.cwe ? { cwe: opts.cwe } : {}),
  };
}

function makeScanResult(findings: Finding[]): ScanResult {
  return {
    projectType: 'express',
    findings,
    filesScanned: 5,
    filesSkipped: 1,
    truncated: false,
    durationMs: 42,
  };
}

// ---------------------------------------------------------------------------
// Score Calculation (0-100) & Cap Formula
// ---------------------------------------------------------------------------
describe('Report - Score Calculation', () => {
  it('gives 100 points and Grade A when there are no findings', () => {
    const details = calculateScore([]);
    assert.equal(details.score, 100);
    assert.equal(details.grade, 'A');
    assert.equal(details.gradeLabel, 'Excellent');
    assert.equal(details.totalFindings, 0);
  });

  it('deducts 25 points for a single critical finding', () => {
    const details = calculateScore([makeFinding({ ruleId: 'SEC-001', severity: 'critical' })]);
    assert.equal(details.score, 75);
    assert.equal(details.grade, 'B');
  });

  it('deducts 15 points for a high finding', () => {
    const details = calculateScore([makeFinding({ ruleId: 'COD-005', severity: 'high' })]);
    assert.equal(details.score, 85);
    assert.equal(details.grade, 'B');
  });

  it('deducts 8 points for a medium finding', () => {
    const details = calculateScore([makeFinding({ ruleId: 'COD-008', severity: 'medium' })]);
    assert.equal(details.score, 92);
    assert.equal(details.grade, 'A');
  });

  it('deducts 3 points for a low finding', () => {
    const details = calculateScore([makeFinding({ ruleId: 'ENV-003', severity: 'low' })]);
    assert.equal(details.score, 97);
    assert.equal(details.grade, 'A');
  });

  it('does not deduct points for info findings', () => {
    const details = calculateScore([makeFinding({ ruleId: 'DEP-005', severity: 'info' })]);
    assert.equal(details.score, 100);
    assert.equal(details.grade, 'A');
  });

  it('caps deductions per rule at 35 points (anti-noise guard)', () => {
    // 5 critical findings of the EXACT same rule (5 * 25 = 125 raw penalty)
    const findings = Array.from({ length: 5 }, () =>
      makeFinding({ ruleId: 'SEC-001', severity: 'critical' }),
    );
    const details = calculateScore(findings);

    // Capped at 35 points max deduction for SEC-001
    assert.equal(details.deductionsByRule['SEC-001'], 35);
    assert.equal(details.score, 65); // 100 - 35 = 65 (Grade C)
    assert.equal(details.grade, 'C');
  });

  it('accumulates deductions across different rules and clamps to 0', () => {
    const findings = [
      makeFinding({ ruleId: 'SEC-001', severity: 'critical' }), // 25
      makeFinding({ ruleId: 'SEC-002', severity: 'critical' }), // 25
      makeFinding({ ruleId: 'COD-001', severity: 'critical' }), // 25
      makeFinding({ ruleId: 'COD-002', severity: 'critical' }), // 25
      makeFinding({ ruleId: 'COD-003', severity: 'high' }),     // 15
    ];
    const details = calculateScore(findings);
    // 25 * 4 + 15 = 115 penalty -> clamped to 0
    assert.equal(details.score, 0);
    assert.equal(details.grade, 'F');
  });
});

// ---------------------------------------------------------------------------
// Colors and NO_COLOR Handling
// ---------------------------------------------------------------------------
describe('Report - Colors', () => {
  it('strips formatting when enabled is false', () => {
    const c = new Colorizer({ enabled: false });
    const text = 'critical finding';
    assert.equal(c.red(text), text);
    assert.equal(c.bold(text), text);
    assert.equal(c.dim(text), text);
  });

  it('includes ANSI escape codes when enabled is true', () => {
    const c = new Colorizer({ enabled: true });
    const formatted = c.red('test');
    assert.ok(formatted.includes('\x1b['), 'Expected ANSI sequence');
  });
});

// ---------------------------------------------------------------------------
// Terminal Formatter: Simple Mode (Top 3-5, Fix These First)
// ---------------------------------------------------------------------------
describe('Report - Simple Terminal Mode', () => {
  it('displays clean message when there are no findings', () => {
    const result = makeScanResult([]);
    const score = calculateScore([]);
    const output = formatSimpleReport(result, score, { enabled: false });

    assert.ok(output.includes('100/100'));
    assert.ok(output.includes('No security issues found'));
  });

  it('displays "Fix These First" with top findings and copy-paste prompt', () => {
    const findings = [
      makeFinding({ ruleId: 'SEC-001', severity: 'critical', title: 'AWS Key Leaked' }),
      makeFinding({ ruleId: 'COD-002', severity: 'critical', title: 'SQL Injection' }),
      makeFinding({ ruleId: 'COD-003', severity: 'high', title: 'NoSQL Injection' }),
      makeFinding({ ruleId: 'COD-008', severity: 'medium', title: 'Permissive CORS' }),
      makeFinding({ ruleId: 'ENV-003', severity: 'low', title: 'Missing .env.example' }),
      makeFinding({ ruleId: 'DEP-005', severity: 'info', title: 'Registry Unchecked' }),
    ];
    const result = makeScanResult(findings);
    const score = calculateScore(findings);
    const output = formatSimpleReport(result, score, { enabled: false });

    assert.ok(output.includes('Fix These First'));
    assert.ok(output.includes('AWS Key Leaked'));
    assert.ok(output.includes('SQL Injection'));
    assert.ok(output.includes('Prompt'));
    assert.ok(output.includes('Run with --detailed to view all findings'));
  });
});

// ---------------------------------------------------------------------------
// Terminal Formatter: Detailed Mode
// ---------------------------------------------------------------------------
describe('Report - Detailed Terminal Mode', () => {
  it('lists all findings with full metadata', () => {
    const findings = [
      makeFinding({ ruleId: 'SEC-001', severity: 'critical', cwe: 'CWE-798' }),
      makeFinding({ ruleId: 'COD-001', severity: 'critical', cwe: 'CWE-95' }),
    ];
    const result = makeScanResult(findings);
    const score = calculateScore(findings);
    const output = formatDetailedReport(result, score, { enabled: false });

    assert.ok(output.includes('All Findings (2)'));
    assert.ok(output.includes('SEC-001'));
    assert.ok(output.includes('COD-001'));
    assert.ok(output.includes('CWE-798'));
    assert.ok(output.includes('CWE-95'));
  });
});

// ---------------------------------------------------------------------------
// JSON Report Mode
// ---------------------------------------------------------------------------
describe('Report - JSON Mode', () => {
  it('generates valid JSON with score, grade, and summary counts', () => {
    const findings = [makeFinding({ ruleId: 'SEC-001', severity: 'critical' })];
    const result = makeScanResult(findings);
    const jsonStr = formatJsonReport(result);
    const parsed = JSON.parse(jsonStr) as Record<string, unknown>;

    assert.equal(parsed['score'], 75);
    assert.equal(parsed['grade'], 'B');
    assert.equal(parsed['projectType'], 'express');
    assert.equal(Array.isArray(parsed['findings']), true);
  });
});

// ---------------------------------------------------------------------------
// SARIF v2.1.0 Mode
// ---------------------------------------------------------------------------
describe('Report - SARIF Mode', () => {
  it('generates valid SARIF v2.1.0 conforming to schema', () => {
    const findings = [
      makeFinding({ ruleId: 'SEC-001', severity: 'critical', cwe: 'CWE-798' }),
      makeFinding({ ruleId: 'COD-008', severity: 'medium', cwe: 'CWE-942' }),
    ];
    const result = makeScanResult(findings);
    const sarifStr = formatSarifReport(result, '0.1.0');
    const parsed = JSON.parse(sarifStr) as {
      version: string;
      runs: Array<{
        tool: { driver: { name: string; rules: unknown[] } };
        results: Array<{ ruleId: string; level: string }>;
      }>;
    };

    assert.equal(parsed.version, '2.1.0');
    assert.equal(parsed.runs[0]!.tool.driver.name, 'CodeShield');
    assert.equal(parsed.runs[0]!.results.length, 2);

    // Verify level mapping: critical -> error, medium -> warning
    const secRes = parsed.runs[0]!.results.find(r => r.ruleId === 'SEC-001');
    assert.equal(secRes?.level, 'error');

    const codRes = parsed.runs[0]!.results.find(r => r.ruleId === 'COD-008');
    assert.equal(codRes?.level, 'warning');
  });
});

// ---------------------------------------------------------------------------
// High-Level renderReport Dispatcher
// ---------------------------------------------------------------------------
describe('Report - renderReport Dispatcher', () => {
  it('renders JSON when mode is json', () => {
    const result = makeScanResult([]);
    const out = renderReport(result, { mode: 'json' });
    assert.ok(out.startsWith('{'));
    assert.ok(out.includes('"score": 100'));
  });

  it('renders SARIF when mode is sarif', () => {
    const result = makeScanResult([]);
    const out = renderReport(result, { mode: 'sarif' });
    assert.ok(out.includes('"version": "2.1.0"'));
  });

  it('renders detailed text when mode is detailed', () => {
    const result = makeScanResult([]);
    const out = renderReport(result, { mode: 'detailed', enabled: false });
    assert.ok(out.includes('Security Score'));
  });
});

