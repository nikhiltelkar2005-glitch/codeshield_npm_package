import { Finding, Severity } from '../types.js';

export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
};

export const MAX_DEDUCTION_PER_RULE = 35;

export type LetterGrade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface ScoreDetails {
  score: number;
  grade: LetterGrade;
  gradeLabel: string;
  totalFindings: number;
  deductionsByRule: Record<string, number>;
  countsBySeverity: Record<Severity, number>;
}

export function calculateScore(findings: readonly Finding[]): ScoreDetails {
  const deductionsByRule: Record<string, number> = {};
  const countsBySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const f of findings) {
    countsBySeverity[f.severity] = (countsBySeverity[f.severity] ?? 0) + 1;
    const penalty = SEVERITY_WEIGHTS[f.severity] ?? 0;
    deductionsByRule[f.ruleId] = (deductionsByRule[f.ruleId] ?? 0) + penalty;
  }

  let totalDeductions = 0;
  for (const ruleId of Object.keys(deductionsByRule)) {
    const rawPenalty = deductionsByRule[ruleId] ?? 0;
    const cappedPenalty = Math.min(rawPenalty, MAX_DEDUCTION_PER_RULE);
    deductionsByRule[ruleId] = cappedPenalty;
    totalDeductions += cappedPenalty;
  }

  const score = Math.max(0, Math.min(100, Math.round(100 - totalDeductions)));

  let grade: LetterGrade;
  let gradeLabel: string;

  if (score >= 90) {
    grade = 'A';
    gradeLabel = 'Excellent';
  } else if (score >= 75) {
    grade = 'B';
    gradeLabel = 'Good';
  } else if (score >= 60) {
    grade = 'C';
    gradeLabel = 'Needs Improvement';
  } else if (score >= 40) {
    grade = 'D';
    gradeLabel = 'Poor';
  } else {
    grade = 'F';
    gradeLabel = 'Critical Attention Required';
  }

  return {
    score,
    grade,
    gradeLabel,
    totalFindings: findings.length,
    deductionsByRule,
    countsBySeverity,
  };
}
