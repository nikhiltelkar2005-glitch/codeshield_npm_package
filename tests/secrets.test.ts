/**
 * secrets.test.ts
 * Tests for secrets scanner: all rules SEC-001..SEC-010, false positive filtering,
 * masking verification, and 100,000-character ReDoS adversarial string tests.
 */

import * as assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { scanSecrets, SECRET_RULES, secretsScanner } from '../src/scanners/secrets.js';
import { ScanContext, ScannedFile } from '../src/types.js';

function makeContext(files: { path: string; content: string }[]): ScanContext {
  const scannedFiles: ScannedFile[] = files.map(f => ({
    path: f.path,
    relativePath: f.path.replace(/^\//, ''),
    content: f.content,
    lines: f.content.split(/\r?\n/),
  }));

  return {
    root: '/test-project',
    projectType: 'unknown',
    files: scannedFiles,
  };
}

function scanSnippet(snippet: string, filePath = 'src/app.ts') {
  return scanSecrets(makeContext([{ path: filePath, content: snippet }]));
}

describe('Secrets Scanner — SEC-001 (AWS Access Key)', () => {
  it('detects valid AWS Access Key and masks secret in output', () => {
    // Fake key for testing (Rule 8)
    const fakeKey = 'AKIAIOSFODNN7EXAMPLE';
    const findings = scanSnippet(`const awsKey = "${fakeKey}";`);

    assert.equal(findings.length, 1);
    const f = findings[0]!;
    assert.equal(f.ruleId, 'SEC-001');
    assert.equal(f.severity, 'critical');
    assert.equal(f.cwe, 'CWE-798');
    assert.ok(f.aiPrompt.includes('AKIA****'));
    assert.ok(!f.aiPrompt.includes(fakeKey));
  });

  it('ignores placeholder AWS key', () => {
    const findings = scanSnippet('const key = "AKIA0000000000000000";');
    assert.equal(findings.length, 0);
  });
});

describe('Secrets Scanner — SEC-002 (Stripe Live Key)', () => {
  it('detects live Stripe secret key and masks it', () => {
    const fakeKey = 'sk_' + 'live_51AbcdEFGhijklMNOPqrstuvwxyz123';
    const findings = scanSnippet(`const stripeSecret = "${fakeKey}";`);

    assert.equal(findings.length, 1);
    const f = findings[0]!;
    assert.equal(f.ruleId, 'SEC-002');
    assert.equal(f.severity, 'critical');
    assert.ok(f.aiPrompt.includes('sk_l****'));
    assert.ok(!f.aiPrompt.includes(fakeKey));
  });

  it('ignores Stripe test keys (sk_test_...)', () => {
    const findings = scanSnippet('const stripeTest = "sk_test_51AbcdEFGhijklMNOPqrstuvwxyz";');
    assert.equal(findings.length, 0);
  });
});

describe('Secrets Scanner — SEC-003 (GitHub Token)', () => {
  it('detects GitHub Personal Access Token (ghp_)', () => {
    const fakeToken = 'ghp_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const findings = scanSnippet(`const token = "${fakeToken}";`);

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.ruleId, 'SEC-003');
    assert.ok(findings[0]?.aiPrompt.includes('ghp_****'));
    assert.ok(!findings[0]?.aiPrompt.includes(fakeToken));
  });
});

describe('Secrets Scanner — SEC-004 (AI Provider API Key)', () => {
  it('detects OpenAI project key and masks it', () => {
    const fakeKey = 'sk-proj-FAKEKEY1234567890abcdef1234567890';
    const findings = scanSnippet(`const openAiKey = "${fakeKey}";`);

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.ruleId, 'SEC-004');
    assert.ok(findings[0]?.aiPrompt.includes('sk-p****'));
    assert.ok(!findings[0]?.aiPrompt.includes(fakeKey));
  });

  it('detects Anthropic API key and masks it', () => {
    const fakeKey = 'sk-ant-FAKEKEY1234567890abcdef1234567890';
    const findings = scanSnippet(`const anthropicKey = "${fakeKey}";`);

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.ruleId, 'SEC-004');
    assert.ok(findings[0]?.aiPrompt.includes('sk-a****'));
    assert.ok(!findings[0]?.aiPrompt.includes(fakeKey));
  });

  it('ignores placeholder OpenAI key', () => {
    const findings = scanSnippet('const key = "sk-YOUR_API_KEY_HERE_PLACEHOLDER";');
    assert.equal(findings.length, 0);
  });
});

describe('Secrets Scanner — SEC-005 (Supabase service_role Key)', () => {
  it('detects hardcoded Supabase service_role key', () => {
    const fakeJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InNlcnZpY2Vfcm9sZSJ9.FAKESIGNATURE1234567890';
    const findings = scanSnippet(`const SUPABASE_SERVICE_ROLE = "${fakeJwt}";`);

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.ruleId, 'SEC-005');
    assert.equal(findings[0]?.severity, 'critical');
    assert.ok(findings[0]?.aiPrompt.includes('eyJh****'));
    assert.ok(!findings[0]?.aiPrompt.includes(fakeJwt));
  });
});

describe('Secrets Scanner — SEC-006 (Private Key Block)', () => {
  it('detects unencrypted private key header', () => {
    const snippet = 'const privKey = `-----BEGIN RSA PRIVATE KEY-----\\nMIIE...`;';
    const findings = scanSnippet(snippet);

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.ruleId, 'SEC-006');
    assert.equal(findings[0]?.severity, 'critical');
  });
});

describe('Secrets Scanner — SEC-007 (Database URL with Password)', () => {
  it('detects raw database connection string with credentials', () => {
    const dbUrl = 'postgres://admin_user:super_secret_pw99@db.prod.internal:5432/mydb';
    const findings = scanSnippet(`const url = "${dbUrl}";`);

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.ruleId, 'SEC-007');
    assert.equal(findings[0]?.severity, 'high');
    assert.ok(findings[0]?.aiPrompt.includes('supe****'));
    assert.ok(!findings[0]?.aiPrompt.includes('super_secret_pw99'));
  });

  it('ignores database URL with placeholder password', () => {
    const findings = scanSnippet('const url = "postgres://user:your_password@localhost:5432/db";');
    assert.equal(findings.length, 0);
  });
});

describe('Secrets Scanner — SEC-008 (JWT Secret)', () => {
  it('detects hardcoded JWT secret in jwt.sign', () => {
    const findings = scanSnippet('const token = jwt.sign(payload, "supersecretjwtkey2026");');

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.ruleId, 'SEC-008');
    assert.ok(findings[0]?.aiPrompt.includes('supe****'));
    assert.ok(!findings[0]?.aiPrompt.includes('supersecretjwtkey2026'));
  });

  it('detects hardcoded JWT_SECRET assignment', () => {
    const findings = scanSnippet('const JWT_SECRET = "production_secret_key_12345";');

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.ruleId, 'SEC-008');
  });

  it('ignores placeholder JWT secret', () => {
    const findings = scanSnippet('const jwtSecret = "your_jwt_secret";');
    assert.equal(findings.length, 0);
  });
});

describe('Secrets Scanner — SEC-009 (Generic API Secret)', () => {
  it('detects generic high-entropy API secret assignment', () => {
    const secret = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6';
    const findings = scanSnippet(`const apiSecret = "${secret}";`);

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.ruleId, 'SEC-009');
    assert.ok(findings[0]?.aiPrompt.includes('a1b2****'));
    assert.ok(!findings[0]?.aiPrompt.includes(secret));
  });

  it('ignores placeholder generic API key', () => {
    const findings = scanSnippet('const apiKey = "YOUR_API_KEY_HERE_TODO";');
    assert.equal(findings.length, 0);
  });
});

describe('Secrets Scanner — SEC-010 (NEXT_PUBLIC_* / VITE_* Leakage)', () => {
  it('detects NEXT_PUBLIC_ variable holding private secret', () => {
    const findings = scanSnippet('NEXT_PUBLIC_SERVICE_ROLE_TOKEN = "secret_service_token_val123";');

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.ruleId, 'SEC-010');
    assert.equal(findings[0]?.severity, 'critical');
    assert.equal(findings[0]?.cwe, 'CWE-200');
  });

  it('detects VITE_ variable holding private key', () => {
    const findings = scanSnippet('VITE_ADMIN_SECRET = "adm_secret_key_987654321";');

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.ruleId, 'SEC-010');
  });

  it('does not flag normal safe NEXT_PUBLIC_ API URL or config', () => {
    const findings = scanSnippet('NEXT_PUBLIC_API_URL = "https://api.example.com";\nNEXT_PUBLIC_APP_NAME = "MyApp";');
    assert.equal(findings.length, 0);
  });
});

describe('Secrets Scanner — False Positive & Ignore Guards', () => {
  it('skips lines with inline codeshield-ignore comment', () => {
    const snippet = 'const awsKey = "AKIAIOSFODNN7EXAMPLE"; // codeshield-ignore';
    const findings = scanSnippet(snippet);
    assert.equal(findings.length, 0);
  });

  it('skips files explicitly marked with codeshield-ignore-file', () => {
    const content = '// codeshield-ignore-file\nconst awsKey = "AKIAIOSFODNN7EXAMPLE";';
    const findings = scanSnippet(content, 'test/mock.ts');
    assert.equal(findings.length, 0);
  });

  it('does not false-positive on clean code with env lookups', () => {
    const cleanCode = `
      const awsKey = process.env.AWS_ACCESS_KEY_ID;
      const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
      const dbUrl = process.env.DATABASE_URL;
      const jwtSecret = process.env.JWT_SECRET;
    `;
    const findings = scanSnippet(cleanCode);
    assert.equal(findings.length, 0);
  });
});

describe('Secrets Scanner — ReDoS Safety (100,000-character adversarial string)', () => {
  // Test every single secret regex against long adversarial input
  const adversarialString = 'a'.repeat(50_000) + ' ' + 'sk_'.repeat(10_000) + ' ' + '1'.repeat(40_000);

  for (const rule of SECRET_RULES) {
    it(`rule ${rule.id} finishes in < 50ms on 100k adversarial string`, () => {
      const re = new RegExp(rule.regex.source, rule.regex.flags);
      const start = Date.now();
      re.test(adversarialString);
      const duration = Date.now() - start;

      assert.ok(
        duration < 50,
        `Rule ${rule.id} took ${duration}ms (exceeded 50ms ReDoS threshold)`
      );
    });
  }
});

