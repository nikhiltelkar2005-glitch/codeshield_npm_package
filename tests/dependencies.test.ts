/**
 * tests/dependencies.test.ts
 * Tests for src/scanners/dependencies.ts
 *
 * Network is NEVER used — all registry calls are injected via mockFetch.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { IncomingMessage, ClientRequest } from 'node:http';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { EventEmitter } from 'node:events';

import {
  scanDependencies,
  isValidNpmName,
} from '../src/scanners/dependencies.js';
import { levenshtein } from '../src/utils/levenshtein.js';
import type { RegistryFetchFn } from '../src/utils/registry.js';
import type { ScanContext } from '../src/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const fixturesDir = join(process.cwd(), 'fixtures');

/** Build a minimal ScanContext from a package.json string. */
function makeContext(pkgJsonContent: string, root = '/fake'): ScanContext {
  return {
    root,
    projectType: 'unknown',
    files: [
      {
        path: join(root, 'package.json'),
        relativePath: 'package.json',
        content: pkgJsonContent,
        lines: pkgJsonContent.split('\n'),
      },
    ],
  };
}

/**
 * Build a mock RegistryFetchFn.
 * responses maps encoded package name → mock response.
 */
type MockResponse =
  | { status: 200; body: Record<string, unknown> }
  | { status: 404 }
  | { status: number }
  | 'error';

function mockFetch(responses: Record<string, MockResponse>): RegistryFetchFn {
  return (url, _options, callback): ClientRequest => {
    // Extract package name from URL
    const encoded = url.replace('https://registry.npmjs.org/', '');
    const pkgName = decodeURIComponent(encoded);

    const mockResp = responses[pkgName];

    // Build a fake ClientRequest
    const reqEmitter = new EventEmitter() as ClientRequest;
    (reqEmitter as unknown as Record<string, unknown>)['destroy'] = () => reqEmitter;
    (reqEmitter as unknown as Record<string, unknown>)['end'] = () => reqEmitter;

    setImmediate(() => {
      if (mockResp === 'error') {
        reqEmitter.emit('error', new Error('Network error'));
        return;
      }

      if (!mockResp) {
        reqEmitter.emit('error', new Error('Unknown mock package'));
        return;
      }

      // Build a fake IncomingMessage
      const resEmitter = new EventEmitter() as IncomingMessage;
      (resEmitter as unknown as Record<string, unknown>)['statusCode'] = mockResp.status;
      (resEmitter as unknown as Record<string, unknown>)['resume'] = () => {};
      (resEmitter as unknown as Record<string, unknown>)['destroy'] = () => {};

      callback(resEmitter);

      setImmediate(() => {
        if (mockResp.status === 404 || mockResp.status !== 200) {
          resEmitter.emit('end');
          return;
        }

        const body = JSON.stringify((mockResp as { status: 200; body: Record<string, unknown> }).body);
        resEmitter.emit('data', Buffer.from(body));
        resEmitter.emit('end');
      });
    });

    return reqEmitter;
  };
}

/** Create a fake registry document for a package. */
function registryDoc(opts: {
  name: string;
  createdDaysAgo?: number;
  scripts?: Record<string, string>;
}): Record<string, unknown> {
  const createdAt = new Date(
    Date.now() - (opts.createdDaysAgo ?? 365) * 24 * 60 * 60 * 1000,
  ).toISOString();

  return {
    name: opts.name,
    'dist-tags': { latest: '1.0.0' },
    time: { created: createdAt, modified: createdAt },
    versions: {
      '1.0.0': {
        name: opts.name,
        version: '1.0.0',
        ...(opts.scripts ? { scripts: opts.scripts } : {}),
      },
    },
  };
}

// ---------------------------------------------------------------------------
// isValidNpmName & ReDoS tests
// ---------------------------------------------------------------------------

describe('isValidNpmName', () => {
  it('accepts simple names', () => {
    assert.ok(isValidNpmName('express'));
    assert.ok(isValidNpmName('lodash'));
    assert.ok(isValidNpmName('react-dom'));
    assert.ok(isValidNpmName('ts-node'));
  });

  it('accepts scoped names', () => {
    assert.ok(isValidNpmName('@scope/pkg'));
    assert.ok(isValidNpmName('@babel/core'));
  });

  it('rejects empty string', () => {
    assert.ok(!isValidNpmName(''));
  });

  it('rejects names with uppercase letters', () => {
    assert.ok(!isValidNpmName('MyPkg'));
    assert.ok(!isValidNpmName('React'));
  });

  it('rejects names over 214 chars', () => {
    assert.ok(!isValidNpmName('a'.repeat(215)));
  });

  it('rejects names with spaces', () => {
    assert.ok(!isValidNpmName('my package'));
  });

  it('runs safely in linear time on 100,000-character adversarial input (ReDoS guard)', () => {
    const long = 'a'.repeat(100_000);
    const start = Date.now();
    assert.equal(isValidNpmName(long), false);
    assert.ok(Date.now() - start < 1000, 'isValidNpmName took too long');
  });
});

// ---------------------------------------------------------------------------
// levenshtein utility
// ---------------------------------------------------------------------------

describe('levenshtein', () => {
  it('returns 0 for identical strings', () => {
    assert.equal(levenshtein('express', 'express'), 0);
  });

  it('returns 1 for single substitution', () => {
    assert.equal(levenshtein('expres', 'express'), 1);   // deletion
    assert.equal(levenshtein('expresss', 'express'), 1); // insertion
    assert.equal(levenshtein('axpress', 'express'), 1);  // substitution
  });

  it('supports transposition of adjacent characters (1 edit)', () => {
    assert.equal(levenshtein('lodahs', 'lodash'), 1);
    assert.equal(levenshtein('reakt', 'react'), 1);
  });

  it('handles empty strings', () => {
    assert.equal(levenshtein('', 'abc'), 3);
    assert.equal(levenshtein('abc', ''), 3);
    assert.equal(levenshtein('', ''), 0);
  });

  it('is symmetric', () => {
    assert.equal(levenshtein('kitten', 'sitting'), levenshtein('sitting', 'kitten'));
  });
});

// ---------------------------------------------------------------------------
// DEP-001: Hallucinated / non-existent package
// ---------------------------------------------------------------------------

describe('DEP-001: hallucinated package', () => {
  it('flags package returning 404 as CRITICAL', async () => {
    const context = makeContext(JSON.stringify({
      dependencies: { 'made-up-nonexistent-pkg': '^1.0.0' },
    }));

    const findings = await scanDependencies(context, {
      fetchFn: mockFetch({ 'made-up-nonexistent-pkg': { status: 404 } }),
    });

    const f = findings.find((x) => x.ruleId === 'DEP-001');
    assert.ok(f, 'DEP-001 finding expected');
    assert.equal(f!.severity, 'critical');
    assert.ok(f!.title.includes('made-up-nonexistent-pkg'));
    assert.ok(f!.cwe === 'CWE-829');
  });

  it('does not flag a package that exists', async () => {
    const context = makeContext(JSON.stringify({
      dependencies: { express: '^4.0.0' },
    }));

    const findings = await scanDependencies(context, {
      fetchFn: mockFetch({
        express: { status: 200, body: registryDoc({ name: 'express', createdDaysAgo: 3650 }) },
      }),
    });

    assert.ok(!findings.find((x) => x.ruleId === 'DEP-001'));
  });
});

// ---------------------------------------------------------------------------
// DEP-002: Newly published package (< 30 days)
// ---------------------------------------------------------------------------

describe('DEP-002: newly published package', () => {
  it('flags package published 5 days ago', async () => {
    const context = makeContext(JSON.stringify({
      dependencies: { 'brand-new-pkg': '^1.0.0' },
    }));

    const findings = await scanDependencies(context, {
      fetchFn: mockFetch({
        'brand-new-pkg': {
          status: 200,
          body: registryDoc({ name: 'brand-new-pkg', createdDaysAgo: 5 }),
        },
      }),
    });

    const f = findings.find((x) => x.ruleId === 'DEP-002');
    assert.ok(f, 'DEP-002 finding expected');
    assert.equal(f!.severity, 'high');
  });

  it('does not flag package published 60 days ago', async () => {
    const context = makeContext(JSON.stringify({
      dependencies: { 'old-enough-pkg': '^1.0.0' },
    }));

    const findings = await scanDependencies(context, {
      fetchFn: mockFetch({
        'old-enough-pkg': {
          status: 200,
          body: registryDoc({ name: 'old-enough-pkg', createdDaysAgo: 60 }),
        },
      }),
    });

    assert.ok(!findings.find((x) => x.ruleId === 'DEP-002'));
  });
});

// ---------------------------------------------------------------------------
// DEP-003: Install scripts
// ---------------------------------------------------------------------------

describe('DEP-003: install scripts', () => {
  it('flags postinstall script as HIGH', async () => {
    const context = makeContext(JSON.stringify({
      dependencies: { 'has-postinstall': '^1.0.0' },
    }));

    const findings = await scanDependencies(context, {
      fetchFn: mockFetch({
        'has-postinstall': {
          status: 200,
          body: registryDoc({
            name: 'has-postinstall',
            createdDaysAgo: 365,
            scripts: { postinstall: 'node setup.js' },
          }),
        },
      }),
    });

    const f = findings.find((x) => x.ruleId === 'DEP-003');
    assert.ok(f, 'DEP-003 finding expected');
    assert.equal(f!.severity, 'high');
    assert.ok(f!.title.includes('postinstall'));
  });

  it('flags install script as HIGH', async () => {
    const context = makeContext(JSON.stringify({
      dependencies: { 'has-install': '^1.0.0' },
    }));

    const findings = await scanDependencies(context, {
      fetchFn: mockFetch({
        'has-install': {
          status: 200,
          body: registryDoc({
            name: 'has-install',
            createdDaysAgo: 100,
            scripts: { install: 'node install.js' },
          }),
        },
      }),
    });

    assert.ok(findings.find((x) => x.ruleId === 'DEP-003'));
  });

  it('does not flag package with no install scripts', async () => {
    const context = makeContext(JSON.stringify({
      dependencies: { 'clean-pkg': '^1.0.0' },
    }));

    const findings = await scanDependencies(context, {
      fetchFn: mockFetch({
        'clean-pkg': {
          status: 200,
          body: registryDoc({
            name: 'clean-pkg',
            createdDaysAgo: 200,
            scripts: { build: 'tsc', test: 'node --test' },
          }),
        },
      }),
    });

    assert.ok(!findings.find((x) => x.ruleId === 'DEP-003'));
  });
});

// ---------------------------------------------------------------------------
// DEP-004: Typosquat detection
// ---------------------------------------------------------------------------

describe('DEP-004: typosquat detection', () => {
  it('flags "expres" as typosquat of "express"', async () => {
    const context = makeContext(JSON.stringify({
      dependencies: { expres: '^4.0.0' },
    }));

    const findings = await scanDependencies(context, {
      fetchFn: mockFetch({
        expres: { status: 200, body: registryDoc({ name: 'expres', createdDaysAgo: 400 }) },
      }),
    });

    const f = findings.find((x) => x.ruleId === 'DEP-004');
    assert.ok(f, 'DEP-004 finding expected for "expres"');
    assert.equal(f!.severity, 'high');
    assert.ok(f!.title.includes('express'));
  });

  it('flags "lodahs" as typosquat of "lodash"', async () => {
    const context = makeContext(JSON.stringify({
      dependencies: { lodahs: '^4.0.0' },
    }));

    const findings = await scanDependencies(context, {
      fetchFn: mockFetch({
        lodahs: { status: 200, body: registryDoc({ name: 'lodahs', createdDaysAgo: 400 }) },
      }),
    });

    const f = findings.find((x) => x.ruleId === 'DEP-004');
    assert.ok(f, 'DEP-004 finding expected for "lodahs"');
  });

  it('does not flag "express" (exact match to popular package)', async () => {
    const context = makeContext(JSON.stringify({
      dependencies: { express: '^4.0.0' },
    }));

    const findings = await scanDependencies(context, {
      fetchFn: mockFetch({
        express: { status: 200, body: registryDoc({ name: 'express', createdDaysAgo: 3650 }) },
      }),
    });

    assert.ok(!findings.find((x) => x.ruleId === 'DEP-004'));
  });

  it('does not flag "my-custom-library" (not close to any popular package)', async () => {
    const context = makeContext(JSON.stringify({
      dependencies: { 'my-custom-library': '^1.0.0' },
    }));

    const findings = await scanDependencies(context, {
      fetchFn: mockFetch({
        'my-custom-library': {
          status: 200,
          body: registryDoc({ name: 'my-custom-library', createdDaysAgo: 400 }),
        },
      }),
    });

    assert.ok(!findings.find((x) => x.ruleId === 'DEP-004'));
  });

  it('typosquat check works in --offline mode', async () => {
    const context = makeContext(JSON.stringify({
      dependencies: { reakt: '^18.0.0' }, // 1 edit from 'react'
    }));

    // No fetchFn — offline mode must NOT call it
    const findings = await scanDependencies(context, { offline: true });

    const f = findings.find((x) => x.ruleId === 'DEP-004');
    assert.ok(f, 'Typosquat still detected in offline mode');
  });
});

// ---------------------------------------------------------------------------
// DEP-005: Network error / timeout
// ---------------------------------------------------------------------------

describe('DEP-005: network errors', () => {
  it('reports "could not check" on network error — does NOT crash', async () => {
    const context = makeContext(JSON.stringify({
      dependencies: { 'some-pkg': '^1.0.0' },
    }));

    const findings = await scanDependencies(context, {
      fetchFn: mockFetch({ 'some-pkg': 'error' }),
    });

    const f = findings.find((x) => x.ruleId === 'DEP-005');
    assert.ok(f, 'DEP-005 info finding expected on network error');
    assert.equal(f!.severity, 'info');
    assert.ok(f!.title.includes('Could not check'));
  });

  it('reports info finding on non-200 non-404 response', async () => {
    const context = makeContext(JSON.stringify({
      dependencies: { 'server-error-pkg': '^1.0.0' },
    }));

    const findings = await scanDependencies(context, {
      fetchFn: mockFetch({ 'server-error-pkg': { status: 500 } }),
    });

    const f = findings.find((x) => x.ruleId === 'DEP-005');
    assert.ok(f, 'DEP-005 expected for HTTP 500');
  });
});

// ---------------------------------------------------------------------------
// Offline mode
// ---------------------------------------------------------------------------

describe('--offline flag', () => {
  it('skips all registry checks when offline=true', async () => {
    let networkCalled = false;

    const spyFetch: RegistryFetchFn = (url, options, callback) => {
      networkCalled = true;
      return mockFetch({})(url, options, callback);
    };

    const context = makeContext(JSON.stringify({
      dependencies: { express: '^4.0.0', lodash: '^4.0.0' },
    }));

    await scanDependencies(context, { offline: true, fetchFn: spyFetch });

    assert.ok(!networkCalled, 'Network must NOT be called in offline mode');
  });

  it('returns no DEP-001/002/003 findings in offline mode (only typosquat)', async () => {
    const context = makeContext(JSON.stringify({
      dependencies: { express: '^4.0.0' },
    }));

    const findings = await scanDependencies(context, { offline: true });

    assert.ok(!findings.find((x) => x.ruleId === 'DEP-001'));
    assert.ok(!findings.find((x) => x.ruleId === 'DEP-002'));
    assert.ok(!findings.find((x) => x.ruleId === 'DEP-003'));
    assert.ok(!findings.find((x) => x.ruleId === 'DEP-005'));
  });
});

// ---------------------------------------------------------------------------
// No package.json in context
// ---------------------------------------------------------------------------

describe('missing package.json', () => {
  it('returns empty findings when no package.json present', async () => {
    const context: ScanContext = {
      root: '/fake',
      projectType: 'unknown',
      files: [],
    };

    const findings = await scanDependencies(context, { offline: true });
    assert.deepEqual(findings, []);
  });
});

// ---------------------------------------------------------------------------
// Invalid package name validation — URL must never be built
// ---------------------------------------------------------------------------

describe('invalid package name validation', () => {
  it('skips registry call for invalid package names', async () => {
    let networkCalled = false;

    const spyFetch: RegistryFetchFn = (url, options, callback) => {
      networkCalled = true;
      return mockFetch({})(url, options, callback);
    };

    // "UPPERCASE" is invalid per npm naming rules
    const context = makeContext(JSON.stringify({
      dependencies: { UPPERCASE_PKG: '^1.0.0' },
    }));

    await scanDependencies(context, { fetchFn: spyFetch });

    assert.ok(!networkCalled, 'Network must NOT be called for invalid package names');
  });
});

// ---------------------------------------------------------------------------
// Multiple packages — semaphore / concurrent requests
// ---------------------------------------------------------------------------

describe('multiple packages', () => {
  it('processes multiple packages and collects findings from each', async () => {
    const context = makeContext(JSON.stringify({
      dependencies: {
        express: '^4.0.0',
        'brand-new-dep': '^1.0.0',
        'fake-nonexistent': '^1.0.0',
      },
    }));

    const findings = await scanDependencies(context, {
      fetchFn: mockFetch({
        express: { status: 200, body: registryDoc({ name: 'express', createdDaysAgo: 3650 }) },
        'brand-new-dep': {
          status: 200,
          body: registryDoc({ name: 'brand-new-dep', createdDaysAgo: 2 }),
        },
        'fake-nonexistent': { status: 404 },
      }),
    });

    // brand-new-dep: DEP-002
    const newPkgF = findings.find(
      (x) => x.ruleId === 'DEP-002' && x.title.includes('brand-new-dep'),
    );
    assert.ok(newPkgF, 'DEP-002 for brand-new-dep');

    // fake-nonexistent: DEP-001
    const hallF = findings.find(
      (x) => x.ruleId === 'DEP-001' && x.title.includes('fake-nonexistent'),
    );
    assert.ok(hallF, 'DEP-001 for fake-nonexistent');
  });
});

// ---------------------------------------------------------------------------
// Real fixture: dep-project
// ---------------------------------------------------------------------------

describe('dep-project fixture', () => {
  it('scans dep-project fixture without errors', async () => {
    const pkgPath = join(fixturesDir, 'dep-project', 'package.json');
    const pkgContent = readFileSync(pkgPath, 'utf8');

    const context = makeContext(pkgContent, join(fixturesDir, 'dep-project'));

    const findings = await scanDependencies(context, {
      fetchFn: mockFetch({
        express: { status: 200, body: registryDoc({ name: 'express', createdDaysAgo: 3650 }) },
        axios: { status: 200, body: registryDoc({ name: 'axios', createdDaysAgo: 1000 }) },
        typescript: {
          status: 200,
          body: registryDoc({ name: 'typescript', createdDaysAgo: 2000 }),
        },
      }),
    });

    // No critical findings for well-known packages
    const criticals = findings.filter((x) => x.severity === 'critical');
    assert.equal(criticals.length, 0, 'No critical findings for known clean packages');
  });
});
