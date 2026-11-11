import * as fs from 'node:fs';
import * as path from 'node:path';
import { Finding } from '../types.js';

export interface ScanSnapshot {
  timestamp: number;
  score: number;
  grade: string;
  findingsCount: number;
  findingFingerprints: string[];
}

export interface HistoryComparison {
  previousScore: number;
  currentScore: number;
  scoreDiff: number;
  fixedCount: number;
  newCount: number;
  summaryText: string;
}

export function getFindingFingerprint(f: Finding): string {
  return `${f.ruleId}:${f.file}:${f.line}`;
}

const HISTORY_DIR = '.codeshield';
const HISTORY_FILE = 'last-scan.json';

export function getHistoryFilePath(root: string): string {
  return path.join(path.resolve(root), HISTORY_DIR, HISTORY_FILE);
}

export function readLastScan(root: string): ScanSnapshot | null {
  try {
    const filePath = getHistoryFilePath(root);
    if (!fs.existsSync(filePath)) return null;
    const content = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(content) as ScanSnapshot;
    if (typeof parsed.score === 'number' && Array.isArray(parsed.findingFingerprints)) {
      return parsed;
    }
    return null;
  } catch {
    return null;
  }
}

export function saveLastScan(
  root: string,
  score: number,
  grade: string,
  findings: readonly Finding[],
): void {
  try {
    const dirPath = path.join(path.resolve(root), HISTORY_DIR);
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
    }

    const snapshot: ScanSnapshot = {
      timestamp: Date.now(),
      score,
      grade,
      findingsCount: findings.length,
      findingFingerprints: findings.map(getFindingFingerprint),
    };

    const filePath = path.join(dirPath, HISTORY_FILE);
    fs.writeFileSync(filePath, JSON.stringify(snapshot, null, 2), 'utf8');

    ensureCodeshieldInGitignore(root);
  } catch {
    // fail silently — history recording should never crash the scan
  }
}

export function ensureCodeshieldInGitignore(root: string): void {
  try {
    const gitignorePath = path.join(path.resolve(root), '.gitignore');
    if (!fs.existsSync(gitignorePath)) return;

    const content = fs.readFileSync(gitignorePath, 'utf8');
    if (content.includes('.codeshield')) return;

    const addition = content.endsWith('\n') || content.length === 0
      ? '.codeshield/\n'
      : '\n.codeshield/\n';

    fs.appendFileSync(gitignorePath, addition, 'utf8');
  } catch {
    // fail silently
  }
}

export function compareWithLastScan(
  previous: ScanSnapshot,
  currentScore: number,
  currentFindings: readonly Finding[],
): HistoryComparison {
  const currentFingerprints = new Set(currentFindings.map(getFindingFingerprint));
  const previousFingerprints = new Set(previous.findingFingerprints);

  let fixedCount = 0;
  for (const fp of previousFingerprints) {
    if (!currentFingerprints.has(fp)) {
      fixedCount++;
    }
  }

  let newCount = 0;
  for (const fp of currentFingerprints) {
    if (!previousFingerprints.has(fp)) {
      newCount++;
    }
  }

  const scoreDiff = currentScore - previous.score;
  let summaryText = '';

  const fixedLabel = `${fixedCount} issue${fixedCount === 1 ? '' : 's'} fixed`;
  const newLabel = `${newCount} new issue${newCount === 1 ? '' : 's'}`;

  if (scoreDiff > 0) {
    summaryText = `Score improved ${previous.score} -> ${currentScore}, ${fixedLabel}${newCount > 0 ? `, ${newLabel}` : ''}.`;
  } else if (scoreDiff < 0) {
    summaryText = `Score dropped ${previous.score} -> ${currentScore}, ${newLabel}${fixedCount > 0 ? `, ${fixedLabel}` : ''}.`;
  } else {
    if (fixedCount > 0 || newCount > 0) {
      summaryText = `Score unchanged at ${currentScore}, ${fixedLabel}, ${newLabel}.`;
    } else {
      summaryText = `Score unchanged at ${currentScore}.`;
    }
  }

  return {
    previousScore: previous.score,
    currentScore,
    scoreDiff,
    fixedCount,
    newCount,
    summaryText,
  };
}
