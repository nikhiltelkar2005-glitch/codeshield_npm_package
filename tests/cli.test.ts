/**
 * cli.test.ts
 * Tests for CLI argument parsing, help, version, scan, and verify commands.
 */

import * as assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { runCli } from '../src/cli.js';

describe('CLI - codeshield', () => {
  it('prints version and exits with 0 on --version', async () => {
    const code = await runCli(['--version']);
    assert.equal(code, 0);
  });

  it('prints version and exits with 0 on -v', async () => {
    const code = await runCli(['-v']);
    assert.equal(code, 0);
  });

  it('prints help and exits with 0 on --help', async () => {
    const code = await runCli(['--help']);
    assert.equal(code, 0);
  });

  it('prints help and exits with 0 on -h', async () => {
    const code = await runCli(['-h']);
    assert.equal(code, 0);
  });

  it('prints help when called with no arguments', async () => {
    const code = await runCli([]);
    assert.equal(code, 0);
  });

  it('handles scan command with target path on clean fixture', async () => {
    const code = await runCli(['scan', './fixtures/projects/plain-html']);
    assert.equal(code, 0);
  });

  it('handles scan command with --offline and --json flags', async () => {
    const code = await runCli(['scan', './fixtures/projects/plain-html', '--offline', '--json']);
    assert.equal(code, 0);
  });

  it('handles scan command with --detailed flag', async () => {
    const code = await runCli(['scan', './fixtures/projects/plain-html', '--detailed']);
    assert.equal(code, 0);
  });

  it('handles scan command with --sarif flag', async () => {
    const code = await runCli(['scan', './fixtures/projects/plain-html', '--sarif']);
    assert.equal(code, 0);
  });

  it('respects --fail-on threshold on clean project', async () => {
    const code = await runCli(['scan', './fixtures/projects/plain-html', '--fail-on', 'critical']);
    assert.equal(code, 0);
  });

  it('rejects invalid severity level with exit code 2', async () => {
    const code = await runCli(['scan', './fixtures/projects/plain-html', '--severity', 'super-critical']);
    assert.equal(code, 2);
  });

  it('rejects invalid fail-on level with exit code 2', async () => {
    const code = await runCli(['scan', './fixtures/projects/plain-html', '--fail-on', 'ultra-high']);
    assert.equal(code, 2);
  });

  it('verify without package name returns exit code 2', async () => {
    const code = await runCli(['verify']);
    assert.equal(code, 2);
  });

  it('verify with invalid package name returns exit code 2', async () => {
    const code = await runCli(['verify', 'Invalid Package Name!']);
    assert.equal(code, 2);
  });

  it('handles fix command with --yes on clean directory', async () => {
    const code = await runCli(['fix', './fixtures/projects/plain-html', '--yes']);
    assert.equal(code, 0);
  });

  it('returns exit code 2 on unknown command', async () => {
    const code = await runCli(['invalid-command']);
    assert.equal(code, 2);
  });
});
