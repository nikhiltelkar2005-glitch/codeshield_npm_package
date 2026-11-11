export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ProjectType = 'nextjs' | 'vite-react' | 'express' | 'plain-html' | 'unknown';

export interface Finding {
  ruleId: string;
  severity: Severity;
  title: string;
  plainExplanation: string;
  file: string;
  line: number;
  fix: string;
  aiPrompt: string;
  cwe?: string;
  snippet?: string;
}

export interface ScannedFile {
  path: string;
  relativePath: string;
  content: string;
  lines: string[];
}

export interface ScanContext {
  root: string;
  projectType: ProjectType;
  files: ScannedFile[];
}

export interface Scanner {
  name: string;
  scan: (context: ScanContext) => Finding[];
}

export interface ScanResult {
  projectType: ProjectType;
  findings: Finding[];
  filesScanned: number;
  filesSkipped: number;
  truncated: boolean;
  durationMs: number;
}

export interface RunnerOptions {
  root: string;
  minSeverity?: Severity;
  scanners?: Scanner[];
}
