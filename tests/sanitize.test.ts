/**
 * sanitize.test.ts
 * Unit tests for sanitize() and maskSecret() using node:test.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { sanitize, maskSecret } from '../src/utils/sanitize.js';

describe('sanitize', () => {
  it('passes through plain text unchanged', () => {
    assert.equal(sanitize('hello world'), 'hello world');
  });

  it('strips SGR colour codes', () => {
    assert.equal(sanitize('\x1b[31mred\x1b[0m'), 'red');
  });

  it('strips bold/dim sequences', () => {
    assert.equal(sanitize('\x1b[1mBold\x1b[22m'), 'Bold');
  });

  it('strips OSC sequences (hyperlinks)', () => {
    // OSC 8 hyperlink: ESC ] 8 ; params ; uri ST
    const link = '\x1b]8;;https://evil.com\x07click\x1b]8;;\x07';
    assert.equal(sanitize(link), 'click');
  });

  it('strips bare ESC bytes', () => {
    assert.equal(sanitize('before\x1bafter'), 'beforeafter');
  });

  it('strips C0 control characters but keeps TAB, LF, CR', () => {
    // NULL, BEL, BS should be stripped
    assert.equal(sanitize('\x00\x07\x08'), '');
    // TAB (0x09), LF (0x0a), CR (0x0d) must survive
    assert.equal(sanitize('\t\n\r'), '\t\n\r');
  });

  it('strips DEL (0x7f)', () => {
    assert.equal(sanitize('a\x7fb'), 'ab');
  });

  it('leaves multi-line plain text intact', () => {
    const text = 'line1\nline2\r\nline3\ttabbed';
    assert.equal(sanitize(text), text);
  });

  it('handles empty string', () => {
    assert.equal(sanitize(''), '');
  });

  it('does not loop catastrophically on long input (ReDoS guard)', () => {
    // 100 000 'a' characters — should complete in well under 1 second.
    const big = 'a'.repeat(100_000);
    const start = Date.now();
    sanitize(big);
    assert.ok(Date.now() - start < 1_000, 'sanitize took too long');
  });
});

describe('maskSecret', () => {
  it('shows first 4 chars then ****', () => {
    assert.equal(maskSecret('AKIAIOSFODNN7EXAMPLE'), 'AKIA****'); // codeshield-ignore
  });

  it('masks short values entirely', () => {
    assert.equal(maskSecret('abc'), '****');
    assert.equal(maskSecret(''), '****');
    assert.equal(maskSecret('1234'), '****');
  });

  it('masks value exactly 5 chars', () => {
    assert.equal(maskSecret('12345'), '1234****');
  });
});
