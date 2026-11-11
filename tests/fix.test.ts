/**
 * tests/fix.test.ts
 * // codeshield-ignore-file
 * Unit tests for safe automated fixes, path traversal security guard,
 * backup creation, and scan history progression.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  resolveSafePath,
  generateEnvExampleContent,
  planFixes,
  runFix,
} from '../src/fix/fixer.js';
import {
  readLastScan,
  saveLastScan,
  compareWithLastScan,
  ScanSnapshot,
} from '../src/fix/history.js';
import type { Finding } from '../src/types.js';

function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-fix-test-'));
}

// ---------------------------------------------------------------------------
// Path Traversal Security Guard
// ---------------------------------------------------------------------------
describe('Fixer - Path Traversal Security', () => {
  it('allows valid paths within root', () => {
    const root = '/my/project';
    const safe = resolveSafePath(root, 'src/index.ts');
    assert.equal(safe, path.resolve('/my/project/src/index.ts'));
  });

  it('allows root itself', () => {
    const root = '/my/project';
    const safe = resolveSafePath(root, '.');
    assert.equal(safe, path.resolve('/my/project'));
  });

  it('throws on path traversal attempt escaping root via ../', () => {
    const root = '/my/project';
    assert.throws(
      () => resolveSafePath(root, '../../etc/passwd'),
      /Path traversal attempt rejected/,
    );
  });

  it('throws on absolute path pointing outside root', () => {
    const root = '/my/project';
    assert.throws(
      () => resolveSafePath(root, '/var/log/system.log'),
      /Path traversal attempt rejected/,
    );
  });
});

// ---------------------------------------------------------------------------
// .env.example Template Generator
// ---------------------------------------------------------------------------
describe('Fixer - generateEnvExampleContent', () => {
  it('preserves comments and non-sensitive configurations', () => {
    const env = `
# Application Config
PORT=3000
NODE_ENV=production
DEBUG=false
`;
    const example = generateEnvExampleContent(env);
    assert.ok(example.includes('# Application Config'));
    assert.ok(example.includes('PORT=3000'));
    assert.ok(example.includes('NODE_ENV=production'));
  });

  it('replaces credentials and secret keys with placeholders', () => {
    const fakeStripe = 'sk_' + 'live_1234567890abcdef';
    const env = `
DATABASE_URL=postgres://admin:superSecretPassword@localhost:5432/mydb
STRIPE_SECRET_KEY=${fakeStripe}
API_TOKEN=my_super_secret_token_value_xyz
JWT_SECRET=topsecretjwtkey
`;
    const example = generateEnvExampleContent(env);

    // Ensure raw secret values are NEVER present in example
    assert.ok(!example.includes('superSecretPassword'));
    assert.ok(!example.includes(fakeStripe));
    assert.ok(!example.includes('my_super_secret_token_value_xyz'));
    assert.ok(!example.includes('topsecretjwtkey'));

    // Check placeholder formatting
    assert.ok(example.includes('DATABASE_URL=your_database_url_here'));
    assert.ok(example.includes('STRIPE_SECRET_KEY=your_stripe_secret_key_here'));
    assert.ok(example.includes('API_TOKEN=your_api_token_here'));
  });
});

// ---------------------------------------------------------------------------
// Automated Fix Planning and Execution
// ---------------------------------------------------------------------------
describe('Fixer - planFixes & runFix', () => {
  it('plans to create .gitignore and .env.example when missing', () => {
    const tmp = createTempDir();
    try {
      // Create a .env file with secrets
      fs.writeFileSync(path.join(tmp, '.env'), 'API_KEY=secret123\nPORT=8080\n', 'utf8');

      const fixes = planFixes(tmp);
      assert.equal(fixes.length, 2);

      assert.ok(fixes.some(f => f.id === 'FIX-GITIGNORE'));
      assert.ok(fixes.some(f => f.id === 'FIX-ENV-EXAMPLE'));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('creates backups before modifying existing .gitignore', async () => {
    const tmp = createTempDir();
    try {
      const originalGitignore = 'node_modules/\ndist/\n';
      fs.writeFileSync(path.join(tmp, '.gitignore'), originalGitignore, 'utf8');
      fs.writeFileSync(path.join(tmp, '.env'), 'SECRET_KEY=testkey\n', 'utf8');

      const exitCode = await runFix(tmp, true); // autoConfirm = true
      assert.equal(exitCode, 0);

      // Verify .gitignore updated
      const updatedGitignore = fs.readFileSync(path.join(tmp, '.gitignore'), 'utf8');
      assert.ok(updatedGitignore.includes('.env'));
      assert.ok(updatedGitignore.includes('.codeshield/'));

      // Verify backup was created and has original contents
      const backupPath = path.join(tmp, '.gitignore.codeshield.bak');
      assert.ok(fs.existsSync(backupPath), 'Backup file must exist');
      const backupContent = fs.readFileSync(backupPath, 'utf8');
      assert.equal(backupContent, originalGitignore);

      // Verify .env.example created
      const examplePath = path.join(tmp, '.env.example');
      assert.ok(fs.existsSync(examplePath));
      const exampleContent = fs.readFileSync(examplePath, 'utf8');
      assert.ok(exampleContent.includes('SECRET_KEY=your_secret_key_here'));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('reports no fixes needed when project is already compliant', async () => {
    const tmp = createTempDir();
    try {
      // .gitignore already ignores .env and .codeshield
      fs.writeFileSync(path.join(tmp, '.gitignore'), '.env\n.codeshield/\n', 'utf8');
      fs.writeFileSync(path.join(tmp, '.env'), 'PORT=3000\n', 'utf8');
      fs.writeFileSync(path.join(tmp, '.env.example'), 'PORT=3000\n', 'utf8');

      const fixes = planFixes(tmp);
      assert.equal(fixes.length, 0);

      const exitCode = await runFix(tmp, true);
      assert.equal(exitCode, 0);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// Scan History & Score Progression Tracking
// ---------------------------------------------------------------------------
describe('History - .codeshield/last-scan.json Tracking', () => {
  it('returns null when history file does not exist', () => {
    const tmp = createTempDir();
    try {
      assert.equal(readLastScan(tmp), null);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('saves scan snapshot and ensures .codeshield is in .gitignore', () => {
    const tmp = createTempDir();
    try {
      fs.writeFileSync(path.join(tmp, '.gitignore'), 'node_modules/\n', 'utf8');

      const findings: Finding[] = [
        {
          ruleId: 'SEC-001',
          severity: 'critical',
          title: 'AWS Key',
          plainExplanation: 'why',
          file: 'src/app.ts',
          line: 12,
          fix: 'fix',
          aiPrompt: 'prompt',
        },
      ];

      saveLastScan(tmp, 75, 'B', findings);

      const saved = readLastScan(tmp);
      assert.ok(saved);
      assert.equal(saved.score, 75);
      assert.equal(saved.grade, 'B');
      assert.equal(saved.findingsCount, 1);
      assert.deepEqual(saved.findingFingerprints, ['SEC-001:src/app.ts:12']);

      // Check .gitignore was updated
      const gitignore = fs.readFileSync(path.join(tmp, '.gitignore'), 'utf8');
      assert.ok(gitignore.includes('.codeshield/'));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('accurately compares score improvements: 54 -> 91, 4 issues fixed, 1 new issue', () => {
    const previousSnapshot: ScanSnapshot = {
      timestamp: Date.now() - 10000,
      score: 54,
      grade: 'D',
      findingsCount: 5,
      findingFingerprints: [
        'SEC-001:src/app.ts:10',
        'SEC-002:src/app.ts:20',
        'COD-001:src/eval.ts:5',
        'COD-002:src/db.ts:15',
        'COD-003:src/user.ts:30', // remains
      ],
    };

    const currentFindings: Finding[] = [
      {
        ruleId: 'COD-003',
        severity: 'high',
        title: 'NoSQL Injection',
        plainExplanation: 'why',
        file: 'src/user.ts',
        line: 30, // still present
        fix: 'fix',
        aiPrompt: 'prompt',
      },
      {
        ruleId: 'ENV-003',
        severity: 'low',
        title: 'Missing .env.example',
        plainExplanation: 'why',
        file: '.env',
        line: 1, // new finding
        fix: 'fix',
        aiPrompt: 'prompt',
      },
    ];

    const comparison = compareWithLastScan(previousSnapshot, 91, currentFindings);

    assert.equal(comparison.previousScore, 54);
    assert.equal(comparison.currentScore, 91);
    assert.equal(comparison.scoreDiff, 37);
    assert.equal(comparison.fixedCount, 4);
    assert.equal(comparison.newCount, 1);
    assert.equal(
      comparison.summaryText,
      'Score improved 54 -> 91, 4 issues fixed, 1 new issue.',
    );
  });

  it('accurately compares score drops', () => {
    const previousSnapshot: ScanSnapshot = {
      timestamp: Date.now() - 10000,
      score: 90,
      grade: 'A',
      findingsCount: 1,
      findingFingerprints: ['ENV-003:.env:1'],
    };

    const currentFindings: Finding[] = [
      {
        ruleId: 'ENV-003',
        severity: 'low',
        title: 'Missing .env.example',
        plainExplanation: 'why',
        file: '.env',
        line: 1,
        fix: 'fix',
        aiPrompt: 'prompt',
      },
      {
        ruleId: 'SEC-001',
        severity: 'critical',
        title: 'AWS Key',
        plainExplanation: 'why',
        file: 'src/config.ts',
        line: 8,
        fix: 'fix',
        aiPrompt: 'prompt',
      },
    ];

    const comparison = compareWithLastScan(previousSnapshot, 75, currentFindings);
    assert.equal(comparison.summaryText, 'Score dropped 90 -> 75, 1 new issue.');
  });
});

