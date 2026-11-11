import * as fs from 'node:fs';
import * as path from 'node:path';
import { Finding, ScanContext, Scanner } from '../types.js';

export function isRealEnvFile(filePath: string): boolean {
  const base = path.basename(filePath).toLowerCase();
  if (!base.startsWith('.env')) return false;

  if (
    base === '.env.example' ||
    base === '.env.sample' ||
    base === '.env.template' ||
    base === '.env.dist' ||
    base === '.env.defaults' ||
    base.endsWith('.example') ||
    base.endsWith('.sample') ||
    base.endsWith('.template')
  ) {
    return false;
  }

  return true;
}

export function isEnvExampleFile(filePath: string): boolean {
  const base = path.basename(filePath).toLowerCase();
  return (
    base === '.env.example' ||
    base === '.env.sample' ||
    base === '.env.template' ||
    base.endsWith('.example') ||
    base.endsWith('.sample') ||
    base.endsWith('.template')
  );
}

export function isEnvIgnoredByGitignore(
  envRelativePath: string,
  gitignoreContent: string
): boolean {
  const envFileName = path.basename(envRelativePath);
  const normalizedEnvPath = envRelativePath.replace(/\\/g, '/');

  const lines = gitignoreContent.split(/\r?\n/);
  for (const rawLine of lines) {
    let line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    if (line.startsWith('/')) {
      line = line.slice(1);
    }

    if (line === envFileName || line === normalizedEnvPath) return true;

    if (line === '.env' && envFileName === '.env') return true;
    if (line === '.env*' && (envFileName === '.env' || envFileName.startsWith('.env.'))) return true;
    if (line === '*.env' && envFileName.endsWith('.env')) return true;
    if (line === '.env.*' && envFileName.startsWith('.env.')) return true;
    if (line === '**/.env' && envFileName === '.env') return true;
    if (line.endsWith('/.env') && envFileName === '.env') return true;
    if (line.endsWith('/.env*') && (envFileName === '.env' || envFileName.startsWith('.env.'))) return true;

    if (line.includes('*')) {
      const escaped = line.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
      try {
        const re = new RegExp(`^${escaped}$`);
        if (re.test(envFileName) || re.test(normalizedEnvPath)) return true;
      } catch {
        // ignore invalid regex
      }
    }
  }

  return false;
}

const BUILD_CONFIG_FILES = new Set([
  'next.config.js',
  'next.config.mjs',
  'next.config.ts',
  'next.config.cjs',
  'vite.config.js',
  'vite.config.ts',
  'vite.config.mjs',
  'vite.config.cjs',
  'webpack.config.js',
  'webpack.config.ts',
  'webpack.config.mjs',
  'webpack.config.cjs',
]);

interface SourceMapPattern {
  name: string;
  regex: RegExp;
}

const SOURCE_MAP_PATTERNS: SourceMapPattern[] = [
  {
    name: 'Next.js productionBrowserSourceMaps',
    regex: /\bproductionBrowserSourceMaps\s*:\s*true\b/,
  },
  {
    name: 'Vite build sourcemap',
    regex: /\bsourcemap\s*:\s*(?:true|['"]inline['"]|['"]hidden['"])\b/,
  },
  {
    name: 'Webpack production devtool sourcemap',
    regex: /\bdevtool\s*:\s*['"](?:source-map|inline-source-map|eval-source-map|cheap-module-source-map)['"]/,
  },
];

export function scanEnv(context: ScanContext): Finding[] {
  const findings: Finding[] = [];

  let gitignoreContent: string | null = null;
  const gitignoreFile = context.files.find(
    f => path.basename(f.relativePath).toLowerCase() === '.gitignore'
  );

  if (gitignoreFile) {
    gitignoreContent = gitignoreFile.content;
  } else {
    try {
      const diskPath = path.join(context.root, '.gitignore');
      if (fs.existsSync(diskPath)) {
        gitignoreContent = fs.readFileSync(diskPath, 'utf8');
      }
    } catch {
      gitignoreContent = null;
    }
  }

  const realEnvFiles = context.files.filter(f => isRealEnvFile(f.relativePath));
  const hasExampleFile =
    context.files.some(f => isEnvExampleFile(f.relativePath)) ||
    fs.existsSync(path.join(context.root, '.env.example')) ||
    fs.existsSync(path.join(context.root, '.env.sample')) ||
    fs.existsSync(path.join(context.root, '.env.template'));

  for (const envFile of realEnvFiles) {
    const baseName = path.basename(envFile.relativePath);
    const isIgnored = gitignoreContent !== null && isEnvIgnoredByGitignore(envFile.relativePath, gitignoreContent);

    if (!isIgnored) {
      findings.push({
        ruleId: 'ENV-001',
        severity: 'critical',
        title: `Unignored ${baseName} File Not Covered by .gitignore`,
        cwe: 'CWE-798',
        plainExplanation: `The environment file "${envFile.relativePath}" was found, but it is not ignored in .gitignore. Any API keys, database credentials, or auth secrets inside this file are at risk of being committed to Git and leaked publicly.`,
        file: envFile.relativePath,
        line: 1,
        fix: `Add "${baseName}" or ".env*" to your .gitignore file immediately.`,
        aiPrompt: `Add the following lines to .gitignore to ensure environment files are never committed:\n.env\n.env.*\n!.env.example\n!.env.sample`,
      });

      findings.push({
        ruleId: 'ENV-002',
        severity: 'high',
        title: `Risk of Committed Secrets in ${baseName}`,
        cwe: 'CWE-312',
        plainExplanation: `The file "${envFile.relativePath}" exists in the repository without .gitignore protection. If this repository is shared or pushed to GitHub/GitLab, the secrets in this file may be permanently exposed in commit history.`,
        file: envFile.relativePath,
        line: 1,
        fix: `Stop tracking the file with "git rm --cached ${envFile.relativePath}" and ensure it is listed in .gitignore.`,
        aiPrompt: `Provide the git commands to untrack "${envFile.relativePath}" without deleting the local file:\ngit rm --cached ${envFile.relativePath}\ngit commit -m "Untrack ${baseName}"`,
      });
    }
  }

  if (realEnvFiles.length > 0 && !hasExampleFile) {
    const primaryEnv = realEnvFiles[0]!;
    findings.push({
      ruleId: 'ENV-003',
      severity: 'low',
      title: 'Missing .env.example Template File',
      cwe: 'CWE-1059',
      plainExplanation: `A .env file was found, but no ".env.example" or ".env.sample" template exists. Without an example template, other developers or AI assistants cannot know which environment variables are required to run the project.`,
      file: primaryEnv.relativePath,
      line: 1,
      fix: `Create a .env.example file containing all required variable names with dummy placeholder values (never real secrets).`,
      aiPrompt: `Read ${primaryEnv.relativePath} and generate a safe .env.example file with all keys preserved, but with dummy values (e.g. DATABASE_URL="postgres://user:YOUR_PASSWORD@localhost:5432/mydb").`,
    });
  }

  for (const file of context.files) {
    const baseName = path.basename(file.relativePath).toLowerCase();
    if (!BUILD_CONFIG_FILES.has(baseName)) {
      continue;
    }

    for (let lineIdx = 0; lineIdx < file.lines.length; lineIdx++) {
      const line = file.lines[lineIdx] ?? '';
      if (line.trim().startsWith('//') || line.trim().startsWith('/*') || line.trim().startsWith('*')) {
        continue;
      }

      for (const pattern of SOURCE_MAP_PATTERNS) {
        if (pattern.regex.test(line)) {
          findings.push({
            ruleId: 'ENV-004',
            severity: 'medium',
            title: 'Production Source Maps Enabled in Build Config',
            cwe: 'CWE-540',
            plainExplanation: `Production source maps are enabled (${pattern.name}) on line ${lineIdx + 1} of "${file.relativePath}". When source maps are uploaded to production, anyone can open browser Developer Tools and view your original unminified source code, proprietary algorithms, and internal comments.`,
            file: file.relativePath,
            line: lineIdx + 1,
            fix: `Disable production source maps in "${baseName}" (set productionBrowserSourceMaps: false or sourcemap: false).`,
            aiPrompt: `In "${file.relativePath}", disable production source maps on line ${lineIdx + 1} by setting the option to false.`,
          });
        }
      }
    }
  }

  return findings;
}

export const envScanner: Scanner = {
  name: 'env',
  scan: scanEnv,
};
