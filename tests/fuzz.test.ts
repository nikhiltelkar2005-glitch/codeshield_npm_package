// codeshield-ignore-file
/**
 * tests/fuzz.test.ts
 * Fuzz tests for CodeShield engine, fileWalker, and scanners.
 *
 * Tests robustness against:
 *   - Huge files exceeding MAX_FILE_BYTES (1 MiB)
 *   - Binary files and files with null bytes
 *   - Corrupt / invalid UTF-8 byte sequences
 *   - Deeply nested directories (30 levels)
 *   - Recursive symlink loops (infinite loop defense)
 *   - External symlinks escaping the scan root
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { walkFiles } from '../src/engine/fileWalker.js';
import { runScan } from '../src/engine/runner.js';
import { secretsScanner } from '../src/scanners/secrets.js';
import { codeScanner } from '../src/scanners/code.js';
import { envScanner } from '../src/scanners/env.js';
import { MAX_FILE_BYTES } from '../src/utils/constants.js';

function createTempDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `codeshield-fuzz-${prefix}-`));
}

describe('Fuzzing & Robustness - File Walker & Scanners', () => {
  it('skips files exceeding MAX_FILE_BYTES (1 MiB) without crashing', () => {
    const tmp = createTempDir('huge');
    try {
      // Create a 2 MiB file (> 1 MiB limit)
      const bigPath = path.join(tmp, 'huge-file.ts');
      const buffer = Buffer.alloc(MAX_FILE_BYTES + 1024, 'a');
      fs.writeFileSync(bigPath, buffer);

      // Create a normal small file
      const smallPath = path.join(tmp, 'small.ts');
      fs.writeFileSync(smallPath, 'export const val = 42;\n');

      const result = walkFiles(tmp);

      // Huge file must be skipped; small file visited
      assert.equal(result.files.length, 1);
      assert.equal(result.files[0]!.relativePath, 'small.ts');
      assert.ok(result.filesSkipped >= 1);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('skips binary files and files with binary extensions', () => {
    const tmp = createTempDir('binary');
    try {
      // Fake binary image
      const imgPath = path.join(tmp, 'logo.png');
      fs.writeFileSync(imgPath, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));

      // Executable binary
      const exePath = path.join(tmp, 'binary.exe');
      fs.writeFileSync(exePath, Buffer.from([0x4d, 0x5a, 0x90, 0x00]));

      // Legitimate source file
      const srcPath = path.join(tmp, 'index.ts');
      fs.writeFileSync(srcPath, 'const name = "test";\n');

      const result = walkFiles(tmp);
      assert.equal(result.files.length, 1);
      assert.equal(result.files[0]!.relativePath, 'index.ts');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('safely handles files with invalid UTF-8 and control bytes', () => {
    const tmp = createTempDir('utf8');
    try {
      // File containing invalid UTF-8 byte sequences and control chars
      const badPath = path.join(tmp, 'corrupt.ts');
      const badBytes = Buffer.from([
        0x63, 0x6f, 0x6e, 0x73, 0x74, 0x20, // 'const '
        0xff, 0xfe, 0x80, 0x81, 0x00, 0x07, // corrupt bytes
        0x3b, 0x0a,                         // ';\n'
      ]);
      fs.writeFileSync(badPath, badBytes);

      const result = runScan({
        root: tmp,
        scanners: [secretsScanner, codeScanner, envScanner],
      });

      // Scanner must complete gracefully with 0 crashes
      assert.ok(result.filesScanned >= 0);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('traverses deeply nested directory hierarchies without stack overflow', () => {
    const tmp = createTempDir('deep');
    try {
      // Create a 25-level deep directory structure
      let current = tmp;
      for (let i = 0; i < 25; i++) {
        current = path.join(current, `level_${i}`);
        fs.mkdirSync(current);
      }

      fs.writeFileSync(path.join(current, 'deep.ts'), 'export const depth = 25;\n');

      const result = walkFiles(tmp);
      assert.equal(result.files.length, 1);
      assert.ok(result.files[0]!.relativePath.includes('deep.ts'));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('prevents infinite recursion on recursive symlink loops', () => {
    const tmp = createTempDir('symlink-loop');
    try {
      const srcDir = path.join(tmp, 'src');
      fs.mkdirSync(srcDir);
      fs.writeFileSync(path.join(srcDir, 'app.ts'), 'const x = 1;\n');

      // Create a symlink pointing to its parent or self (loop)
      try {
        fs.symlinkSync(srcDir, path.join(srcDir, 'loop-to-self'), 'dir');
      } catch {
        // Skip symlink test if OS permissions deny symlink creation
        return;
      }

      const result = walkFiles(tmp);

      // Must complete and find app.ts without infinite loop
      assert.ok(result.files.length >= 1);
      assert.ok(result.files.some(f => f.relativePath.includes('app.ts')));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('does NOT follow symlinks pointing outside the scan root', () => {
    const tmpRoot = createTempDir('symlink-root');
    const outsideDir = createTempDir('symlink-outside');
    try {
      // Create a secret file outside the root
      fs.writeFileSync(path.join(outsideDir, 'secret.ts'), 'const AWS_KEY = "AKIA1111111111111111";\n');

      // Create a symlink inside tmpRoot pointing outside
      try {
        fs.symlinkSync(path.join(outsideDir, 'secret.ts'), path.join(tmpRoot, 'outside-link.ts'), 'file');
      } catch {
        return;
      }

      fs.writeFileSync(path.join(tmpRoot, 'safe.ts'), 'export const safe = true;\n');

      const result = walkFiles(tmpRoot);

      // External file must NOT be visited
      assert.equal(result.files.length, 1);
      assert.equal(result.files[0]!.relativePath, 'safe.ts');
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
      fs.rmSync(outsideDir, { recursive: true, force: true });
    }
  });
});
