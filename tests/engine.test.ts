/**
 * engine.test.ts
 * Tests for fileWalker, projectDetector, and runner using fixtures and symlinks.
 */

import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { walkFiles } from '../src/engine/fileWalker.js';
import { detectProjectType, readPackageJson } from '../src/engine/projectDetector.js';
import { runScan } from '../src/engine/runner.js';
import { Finding, ScanContext, Scanner } from '../src/types.js';

// Robust fixture path resolution from workspace root
const fixturesRoot = path.resolve(process.cwd(), 'fixtures');
const fakeProjectRoot = path.join(fixturesRoot, 'fake-project');

describe('Engine - fileWalker', () => {
  it('safely walks fake-project fixture and reads valid text files', () => {
    const result = walkFiles(fakeProjectRoot);

    assert.ok(result.files.length >= 3);
    const relPaths = result.files.map(f => f.relativePath);

    // Should include regular source and config files
    assert.ok(relPaths.some(p => p.includes('package.json')));
    assert.ok(relPaths.some(p => p.includes('server.ts')));
    assert.ok(relPaths.some(p => p.includes('README.md')));

    // Security Rule 2: Must skip node_modules, .git, and dist
    assert.ok(!relPaths.some(p => p.includes('node_modules')));
    assert.ok(!relPaths.some(p => p.includes('.git')));
    assert.ok(!relPaths.some(p => p.includes('dist')));

    // Security Rule 2: Must skip binary files (.png)
    assert.ok(!relPaths.some(p => p.endsWith('.png')));
  });

  it('never follows symlinks pointing outside the scan root (Security Rule 2)', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cs-symlink-root-'));
    const tempOutside = fs.mkdtempSync(path.join(os.tmpdir(), 'cs-symlink-outside-'));

    try {
      // Create secret file outside root
      const secretFile = path.join(tempOutside, 'secret.env');
      fs.writeFileSync(secretFile, 'SUPER_SECRET_KEY=12345', 'utf8');

      // Create legit file inside root
      const legitFile = path.join(tempRoot, 'legit.ts');
      fs.writeFileSync(legitFile, 'const a = 1;', 'utf8');

      // Create malicious symlink inside root pointing to secret outside root
      const symlinkPath = path.join(tempRoot, 'malicious-link.ts');
      fs.symlinkSync(secretFile, symlinkPath);

      const result = walkFiles(tempRoot);

      // Verify the symlink was skipped and outside file content was NEVER read
      assert.equal(result.files.length, 1);
      assert.equal(result.files[0]?.path, legitFile);
      assert.ok(!result.files.some(f => f.content.includes('SUPER_SECRET_KEY')));
      assert.ok(result.filesSkipped >= 1);
    } finally {
      fs.rmSync(tempRoot, { recursive: true, force: true });
      fs.rmSync(tempOutside, { recursive: true, force: true });
    }
  });

  it('enforces maximum file size limit', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cs-size-root-'));
    try {
      fs.writeFileSync(path.join(tempRoot, 'small.ts'), 'export const x = 1;', 'utf8');
      fs.writeFileSync(path.join(tempRoot, 'oversized.ts'), 'x'.repeat(1000), 'utf8');

      // Test with maxBytes set to 500
      const result = walkFiles(tempRoot, { maxBytes: 500 });
      assert.equal(result.files.length, 1);
      assert.ok(result.files[0]?.relativePath.includes('small.ts'));
      assert.ok(result.filesSkipped >= 1);
    } finally {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  it('enforces maximum file count limit', () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cs-count-root-'));
    try {
      for (let i = 0; i < 5; i++) {
        fs.writeFileSync(path.join(tempRoot, `file${i}.ts`), `const v${i} = ${i};`, 'utf8');
      }

      const result = walkFiles(tempRoot, { maxFiles: 3 });
      assert.equal(result.files.length, 3);
      assert.equal(result.truncated, true);
    } finally {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });
});

describe('Engine - projectDetector', () => {
  it('detects Next.js projects', () => {
    const pType = detectProjectType(path.join(fixturesRoot, 'projects', 'nextjs'));
    assert.equal(pType, 'nextjs');
  });

  it('detects Vite/React projects', () => {
    const pType = detectProjectType(path.join(fixturesRoot, 'projects', 'vite-react'));
    assert.equal(pType, 'vite-react');
  });

  it('detects Express projects', () => {
    const pType = detectProjectType(path.join(fixturesRoot, 'projects', 'express'));
    assert.equal(pType, 'express');
  });

  it('detects Plain HTML projects', () => {
    const pType = detectProjectType(path.join(fixturesRoot, 'projects', 'plain-html'));
    assert.equal(pType, 'plain-html');
  });

  it('identifies unclassified directory as unknown', () => {
    const pType = detectProjectType(path.join(fixturesRoot, 'projects', 'unknown'));
    assert.equal(pType, 'unknown');
  });

  it('handles missing or malformed package.json safely without throwing', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cs-malformed-'));
    try {
      fs.writeFileSync(path.join(tempDir, 'package.json'), 'INVALID JSON{{{', 'utf8');
      assert.equal(readPackageJson(tempDir), null);
      assert.equal(detectProjectType(tempDir), 'unknown');
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});

describe('Engine - runner', () => {
  it('runs scanners across files, filters by severity, and returns ScanResult', () => {
    // Create mock scanner adhering to Scanner interface
    const mockScanner: Scanner = {
      name: 'mock-security-scanner',
      scan(context: ScanContext): Finding[] {
        const findings: Finding[] = [];
        for (const file of context.files) {
          if (file.content.includes('fake-app')) {
            findings.push({
              ruleId: 'SEC001',
              severity: 'critical',
              title: 'Hardcoded App Name',
              plainExplanation: 'Found hardcoded application name string.',
              file: file.relativePath,
              line: 2,
              fix: 'Use environment variables for application configuration.',
              aiPrompt: 'Refactor appName to read from process.env.',
              cwe: 'CWE-798',
            });
          }
          if (file.relativePath.includes('README')) {
            findings.push({
              ruleId: 'INFO001',
              severity: 'info',
              title: 'Readme Detected',
              plainExplanation: 'Project has documentation.',
              file: file.relativePath,
              line: 1,
              fix: 'No fix needed.',
              aiPrompt: '',
            });
          }
        }
        return findings;
      },
    };

    const result = runScan({
      root: fakeProjectRoot,
      scanners: [mockScanner],
      minSeverity: 'info',
    });

    assert.equal(result.projectType, 'express');
    assert.ok(result.filesScanned >= 3);
    assert.equal(result.findings.length, 2);

    // Verify ordering: critical comes first, then info
    assert.equal(result.findings[0]?.severity, 'critical');
    assert.equal(result.findings[1]?.severity, 'info');

    // Test with minSeverity filter = 'high' (should omit 'info')
    const highResult = runScan({
      root: fakeProjectRoot,
      scanners: [mockScanner],
      minSeverity: 'high',
    });
    assert.equal(highResult.findings.length, 1);
    assert.equal(highResult.findings[0]?.severity, 'critical');
  });

  it('handles scanner throwing an exception gracefully without crashing runner', () => {
    const crashingScanner: Scanner = {
      name: 'buggy-scanner',
      scan(): Finding[] {
        throw new Error('Unexpected crash in scanner implementation');
      },
    };

    const result = runScan({
      root: fakeProjectRoot,
      scanners: [crashingScanner],
    });

    assert.equal(result.findings.length, 0);
    assert.ok(result.filesScanned >= 1);
  });
});
