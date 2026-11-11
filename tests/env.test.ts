/**
 * env.test.ts
 * Tests for the environment scanner (src/scanners/env.ts):
 *   - ENV-001 & ENV-002: Unignored .env files and version control exposure
 *   - ENV-003: Missing .env.example template
 *   - ENV-004: Production source maps enabled in build config
 */

import * as assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { isEnvIgnoredByGitignore, isRealEnvFile, scanEnv } from '../src/scanners/env.js';
import { ScanContext, ScannedFile } from '../src/types.js';

function makeContext(files: { path: string; content: string }[], root = '/fake-project'): ScanContext {
  const scannedFiles: ScannedFile[] = files.map(f => ({
    path: f.path,
    relativePath: f.path.replace(/^\//, ''),
    content: f.content,
    lines: f.content.split(/\r?\n/),
  }));

  return {
    root,
    projectType: 'unknown',
    files: scannedFiles,
  };
}

describe('Environment Scanner — ENV-001 & ENV-002 (.env and .gitignore)', () => {
  it('flags .env when .gitignore is missing', () => {
    const ctx = makeContext([
      { path: '.env', content: 'DATABASE_URL=postgres://user:pass@localhost/db\nAPI_KEY=123' },
    ]);
    const findings = scanEnv(ctx);

    const unignored = findings.find(f => f.ruleId === 'ENV-001');
    const exposure = findings.find(f => f.ruleId === 'ENV-002');

    assert.ok(unignored, 'Should flag ENV-001');
    assert.equal(unignored?.severity, 'critical');
    assert.equal(unignored?.file, '.env');

    assert.ok(exposure, 'Should flag ENV-002');
    assert.equal(exposure?.severity, 'high');
  });

  it('flags .env when .gitignore exists but does not ignore .env', () => {
    const ctx = makeContext([
      { path: '.env', content: 'SECRET=val' },
      { path: '.gitignore', content: 'node_modules/\ndist/\n' },
    ]);
    const findings = scanEnv(ctx);

    assert.ok(findings.some(f => f.ruleId === 'ENV-001'));
    assert.ok(findings.some(f => f.ruleId === 'ENV-002'));
  });

  it('does NOT flag .env when .gitignore includes .env', () => {
    const ctx = makeContext([
      { path: '.env', content: 'SECRET=val' },
      { path: '.env.example', content: 'SECRET=your_secret' },
      { path: '.gitignore', content: 'node_modules/\n.env\n' },
    ]);
    const findings = scanEnv(ctx);

    assert.equal(findings.filter(f => f.ruleId === 'ENV-001').length, 0);
    assert.equal(findings.filter(f => f.ruleId === 'ENV-002').length, 0);
  });

  it('does NOT flag .env or .env.local when .gitignore includes .env*', () => {
    const ctx = makeContext([
      { path: '.env', content: 'A=1' },
      { path: '.env.local', content: 'B=2' },
      { path: '.env.example', content: 'A=placeholder\nB=placeholder' },
      { path: '.gitignore', content: 'node_modules/\n.env*\n!.env.example' },
    ]);
    const findings = scanEnv(ctx);

    assert.equal(findings.filter(f => f.ruleId === 'ENV-001').length, 0);
    assert.equal(findings.filter(f => f.ruleId === 'ENV-002').length, 0);
  });

  it('does not treat .env.example or .env.sample as real secret files', () => {
    const ctx = makeContext([
      { path: '.env.example', content: 'API_KEY=YOUR_KEY' },
      { path: '.env.sample', content: 'DB_URL=sample' },
      { path: '.gitignore', content: 'node_modules/\n' },
    ]);
    const findings = scanEnv(ctx);

    assert.equal(findings.filter(f => f.ruleId === 'ENV-001').length, 0);
    assert.equal(findings.filter(f => f.ruleId === 'ENV-002').length, 0);
  });
});

describe('Environment Scanner — ENV-003 (Missing .env.example)', () => {
  it('flags missing .env.example when .env exists and no template is present', () => {
    const ctx = makeContext([
      { path: '.env', content: 'FOO=bar' },
      { path: '.gitignore', content: '.env\n' },
    ]);
    const findings = scanEnv(ctx);

    const missingExample = findings.find(f => f.ruleId === 'ENV-003');
    assert.ok(missingExample, 'Should flag missing .env.example');
    assert.equal(missingExample?.severity, 'low');
    assert.equal(missingExample?.cwe, 'CWE-1059');
  });

  it('does NOT flag ENV-003 when .env.example is present', () => {
    const ctx = makeContext([
      { path: '.env', content: 'FOO=bar' },
      { path: '.env.example', content: 'FOO=your_foo' },
      { path: '.gitignore', content: '.env\n' },
    ]);
    const findings = scanEnv(ctx);

    assert.equal(findings.filter(f => f.ruleId === 'ENV-003').length, 0);
  });

  it('does NOT flag ENV-003 when .env.sample is present', () => {
    const ctx = makeContext([
      { path: '.env', content: 'FOO=bar' },
      { path: '.env.sample', content: 'FOO=sample_foo' },
      { path: '.gitignore', content: '.env\n' },
    ]);
    const findings = scanEnv(ctx);

    assert.equal(findings.filter(f => f.ruleId === 'ENV-003').length, 0);
  });

  it('does NOT flag ENV-003 when no .env files exist', () => {
    const ctx = makeContext([
      { path: 'src/index.ts', content: 'console.log("hello");' },
      { path: '.gitignore', content: 'node_modules/\n' },
    ]);
    const findings = scanEnv(ctx);

    assert.equal(findings.filter(f => f.ruleId === 'ENV-003').length, 0);
  });
});

describe('Environment Scanner — ENV-004 (Production Source Maps)', () => {
  it('flags productionBrowserSourceMaps: true in next.config.js', () => {
    const nextConfig = `
      module.exports = {
        reactStrictMode: true,
        productionBrowserSourceMaps: true,
      };
    `;
    const ctx = makeContext([{ path: 'next.config.js', content: nextConfig }]);
    const findings = scanEnv(ctx);

    const smFinding = findings.find(f => f.ruleId === 'ENV-004');
    assert.ok(smFinding, 'Should detect production source map in next.config.js');
    assert.equal(smFinding?.severity, 'medium');
    assert.equal(smFinding?.cwe, 'CWE-540');
    assert.equal(smFinding?.line, 4);
  });

  it('flags build.sourcemap: true in vite.config.ts', () => {
    const viteConfig = `
      import { defineConfig } from 'vite';
      export default defineConfig({
        build: {
          sourcemap: true,
        },
      });
    `;
    const ctx = makeContext([{ path: 'vite.config.ts', content: viteConfig }]);
    const findings = scanEnv(ctx);

    const smFinding = findings.find(f => f.ruleId === 'ENV-004');
    assert.ok(smFinding, 'Should detect sourcemap in vite.config.ts');
    assert.equal(smFinding?.severity, 'medium');
  });

  it('flags devtool: "source-map" in webpack.config.js', () => {
    const webpackConfig = `
      module.exports = {
        mode: 'production',
        devtool: 'source-map',
      };
    `;
    const ctx = makeContext([{ path: 'webpack.config.js', content: webpackConfig }]);
    const findings = scanEnv(ctx);

    const smFinding = findings.find(f => f.ruleId === 'ENV-004');
    assert.ok(smFinding, 'Should detect devtool sourcemap in webpack.config.js');
  });

  it('ignores commented-out sourcemap options', () => {
    const nextConfig = `
      module.exports = {
        // productionBrowserSourceMaps: true,
        reactStrictMode: true,
      };
    `;
    const ctx = makeContext([{ path: 'next.config.js', content: nextConfig }]);
    const findings = scanEnv(ctx);

    assert.equal(findings.filter(f => f.ruleId === 'ENV-004').length, 0);
  });

  it('ignores productionBrowserSourceMaps: false', () => {
    const nextConfig = `
      module.exports = {
        productionBrowserSourceMaps: false,
      };
    `;
    const ctx = makeContext([{ path: 'next.config.js', content: nextConfig }]);
    const findings = scanEnv(ctx);

    assert.equal(findings.filter(f => f.ruleId === 'ENV-004').length, 0);
  });
});

describe('Environment Scanner — Helpers', () => {
  it('correctly classifies real env files vs template files', () => {
    assert.equal(isRealEnvFile('.env'), true);
    assert.equal(isRealEnvFile('.env.local'), true);
    assert.equal(isRealEnvFile('.env.production'), true);
    assert.equal(isRealEnvFile('subfolder/.env'), true);

    assert.equal(isRealEnvFile('.env.example'), false);
    assert.equal(isRealEnvFile('.env.sample'), false);
    assert.equal(isRealEnvFile('.env.template'), false);
    assert.equal(isRealEnvFile('src/index.ts'), false);
  });

  it('correctly evaluates isEnvIgnoredByGitignore patterns', () => {
    const gitignoreExact = '.env\nnode_modules\n';
    assert.equal(isEnvIgnoredByGitignore('.env', gitignoreExact), true);
    assert.equal(isEnvIgnoredByGitignore('.env.local', gitignoreExact), false);

    const gitignoreWildcard = '.env*\nnode_modules\n';
    assert.equal(isEnvIgnoredByGitignore('.env', gitignoreWildcard), true);
    assert.equal(isEnvIgnoredByGitignore('.env.local', gitignoreWildcard), true);
    assert.equal(isEnvIgnoredByGitignore('.env.production', gitignoreWildcard), true);

    const gitignoreStarEnv = '*.env\n';
    assert.equal(isEnvIgnoredByGitignore('.env', gitignoreStarEnv), true);
    assert.equal(isEnvIgnoredByGitignore('local.env', gitignoreStarEnv), true);
  });
});

