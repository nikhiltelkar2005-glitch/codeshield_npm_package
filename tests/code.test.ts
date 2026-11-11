/**
 * tests/code.test.ts
 * Tests for src/scanners/code.ts (Rules COD-001 through COD-013).
 *
 * Requirements:
 *   - Positive tests for every rule.
 *   - False-positive tests for every rule (safe code must NOT be flagged).
 *   - Safe against catastrophic backtracking (ReDoS guard on 100k strings).
 *   - Respects inline ignore comments and codeshield-ignore-file.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { scanCode, codeScanner, CODE_RULES } from '../src/scanners/code.js';
import type { ScanContext, ScannedFile } from '../src/types.js';

function makeFile(relativePath: string, content: string): ScannedFile {
  return {
    path: `/app/${relativePath}`,
    relativePath,
    content,
    lines: content.split('\n'),
  };
}

function makeContext(files: ScannedFile[]): ScanContext {
  return {
    root: '/app',
    projectType: 'express',
    files,
  };
}

function scanSnippet(code: string, fileName = 'src/app.ts') {
  const file = makeFile(fileName, code);
  const context = makeContext([file]);
  return scanCode(context);
}

// ---------------------------------------------------------------------------
// COD-001: eval / new Function
// ---------------------------------------------------------------------------
describe('COD-001: eval / new Function', () => {
  it('detects eval() call', () => {
    const findings = scanSnippet('const result = eval(userInput);');
    const f = findings.find(x => x.ruleId === 'COD-001');
    assert.ok(f, 'COD-001 expected');
    assert.equal(f!.severity, 'critical');
    assert.equal(f!.cwe, 'CWE-95');
  });

  it('detects new Function() constructor', () => {
    const findings = scanSnippet('const fn = new Function("a", "b", userInput);');
    assert.ok(findings.some(x => x.ruleId === 'COD-001'));
  });

  it('does NOT flag safe identifiers or comments (false positive guard)', () => {
    const findings = scanSnippet(`
      // eval(userInput);
      /* new Function() */
      const evaluate = (x: number) => x * 2;
      const evaluation = evaluate(10);
      console.log("evaluation:", evaluation);
    `);
    assert.equal(findings.filter(x => x.ruleId === 'COD-001').length, 0);
  });
});

// ---------------------------------------------------------------------------
// COD-002: SQL concatenation
// ---------------------------------------------------------------------------
describe('COD-002: SQL Query Concatenation', () => {
  it('detects SQL built with template literal interpolation', () => {
    const findings = scanSnippet('const sql = `SELECT * FROM users WHERE id = ${userId}`;');
    const f = findings.find(x => x.ruleId === 'COD-002');
    assert.ok(f, 'COD-002 expected');
    assert.equal(f!.severity, 'critical');
    assert.equal(f!.cwe, 'CWE-89');
  });

  it('detects SQL built with string concatenation (+)', () => {
    const findings = scanSnippet('const query = "SELECT * FROM accounts WHERE user_id = " + req.params.id;');
    assert.ok(findings.some(x => x.ruleId === 'COD-002'));
  });

  it('detects db.query with dynamic interpolation', () => {
    const findings = scanSnippet('db.query("INSERT INTO logs (msg) VALUES (\'" + msg + "\')");');
    assert.ok(findings.some(x => x.ruleId === 'COD-002'));
  });

  it('does NOT flag parameterized queries or static queries (false positive guard)', () => {
    const findings = scanSnippet(`
      const query1 = 'SELECT id, username FROM users WHERE active = true';
      db.query('SELECT * FROM users WHERE id = $1', [userId]);
      pool.execute('UPDATE accounts SET balance = balance + 10 WHERE id = ?', [accId]);
    `);
    assert.equal(findings.filter(x => x.ruleId === 'COD-002').length, 0);
  });
});

// ---------------------------------------------------------------------------
// COD-003: NoSQL Injection
// ---------------------------------------------------------------------------
describe('COD-003: NoSQL Injection', () => {
  it('detects req.body passed straight to findOne', () => {
    const findings = scanSnippet('const user = await User.findOne(req.body);');
    const f = findings.find(x => x.ruleId === 'COD-003');
    assert.ok(f, 'COD-003 expected');
    assert.equal(f!.severity, 'high');
    assert.equal(f!.cwe, 'CWE-943');
  });

  it('detects req.query passed straight to deleteMany', () => {
    const findings = scanSnippet('await db.collection("items").deleteMany(req.query);');
    assert.ok(findings.some(x => x.ruleId === 'COD-003'));
  });

  it('does NOT flag explicit field lookups (false positive guard)', () => {
    const findings = scanSnippet(`
      const user = await User.findOne({ email: req.body.email, password: req.body.password });
      const item = await db.collection("items").find({ ownerId: req.params.id });
    `);
    assert.equal(findings.filter(x => x.ruleId === 'COD-003').length, 0);
  });
});

// ---------------------------------------------------------------------------
// COD-004: child_process.exec with variables
// ---------------------------------------------------------------------------
describe('COD-004: Command Injection (child_process.exec)', () => {
  it('detects exec with template literal', () => {
    const findings = scanSnippet('child_process.exec(`ping ${targetHost}`);');
    const f = findings.find(x => x.ruleId === 'COD-004');
    assert.ok(f, 'COD-004 expected');
    assert.equal(f!.severity, 'critical');
    assert.equal(f!.cwe, 'CWE-78');
  });

  it('detects exec with string concatenation', () => {
    const findings = scanSnippet('exec("git clone " + repoUrl);');
    assert.ok(findings.some(x => x.ruleId === 'COD-004'));
  });

  it('detects exec with variable command argument', () => {
    const findings = scanSnippet('exec(userCommand, (err, out) => {});');
    assert.ok(findings.some(x => x.ruleId === 'COD-004'));
  });

  it('does NOT flag static string literal exec or execFile (false positive guard)', () => {
    const findings = scanSnippet(`
      exec("git status", (err) => {});
      exec('npm --version');
      execFile("ls", ["-la", dirPath]);
    `);
    assert.equal(findings.filter(x => x.ruleId === 'COD-004').length, 0);
  });
});

// ---------------------------------------------------------------------------
// COD-005: Math.random() for tokens / passwords
// ---------------------------------------------------------------------------
describe('COD-005: Math.random() for Security Values', () => {
  it('detects Math.random() used to generate tokens', () => {
    const findings = scanSnippet('const resetToken = Math.random().toString(36).substring(2);');
    const f = findings.find(x => x.ruleId === 'COD-005');
    assert.ok(f, 'COD-005 expected');
    assert.equal(f!.severity, 'high');
    assert.equal(f!.cwe, 'CWE-338');
  });

  it('detects Math.random() used for password generation', () => {
    const findings = scanSnippet('function generateTempPassword() { return "pass_" + Math.random(); }');
    assert.ok(findings.some(x => x.ruleId === 'COD-005'));
  });

  it('does NOT flag Math.random() in games, animations, or UI (false positive guard)', () => {
    const findings = scanSnippet(`
      const opacity = Math.random();
      const randomColor = colors[Math.floor(Math.random() * colors.length)];
      const x = Math.random() * canvas.width;
    `);
    assert.equal(findings.filter(x => x.ruleId === 'COD-005').length, 0);
  });
});

// ---------------------------------------------------------------------------
// COD-006: MD5 / SHA1 for passwords
// ---------------------------------------------------------------------------
describe('COD-006: MD5 / SHA1 for Passwords', () => {
  it('detects MD5 used for password hashing', () => {
    const findings = scanSnippet('const hashedPass = crypto.createHash("md5").update(password).digest("hex");');
    const f = findings.find(x => x.ruleId === 'COD-006');
    assert.ok(f, 'COD-006 expected');
    assert.equal(f!.severity, 'high');
    assert.equal(f!.cwe, 'CWE-327');
  });

  it('detects SHA1 used for user credentials', () => {
    const findings = scanSnippet('const pwdHash = createHash("sha1").update(userPwd).digest("hex");');
    assert.ok(findings.some(x => x.ruleId === 'COD-006'));
  });

  it('does NOT flag MD5 for file checksums or modern hashing (false positive guard)', () => {
    const findings = scanSnippet(`
      const fileEtag = crypto.createHash("md5").update(fileBuffer).digest("hex");
      const secureHash = await bcrypt.hash(password, 12);
      const sha256Hash = crypto.createHash("sha256").update(password).digest("hex");
    `);
    assert.equal(findings.filter(x => x.ruleId === 'COD-006').length, 0);
  });
});

// ---------------------------------------------------------------------------
// COD-007: dangerouslySetInnerHTML / innerHTML with variables
// ---------------------------------------------------------------------------
describe('COD-007: Unescaped HTML Injection', () => {
  it('detects dangerouslySetInnerHTML with variable', () => {
    const findings = scanSnippet('<div dangerouslySetInnerHTML={{ __html: userBio }} />', 'src/Bio.tsx');
    const f = findings.find(x => x.ruleId === 'COD-007');
    assert.ok(f, 'COD-007 expected');
    assert.equal(f!.severity, 'high');
    assert.equal(f!.cwe, 'CWE-79');
  });

  it('detects element.innerHTML assignment with variable', () => {
    const findings = scanSnippet('card.innerHTML = "<h3>" + post.title + "</h3>";');
    assert.ok(findings.some(x => x.ruleId === 'COD-007'));
  });

  it('does NOT flag clearing innerHTML or static string literals (false positive guard)', () => {
    const findings = scanSnippet(`
      container.innerHTML = "";
      panel.innerHTML = "<p>Loading records...</p>";
      card.textContent = post.title;
    `);
    assert.equal(findings.filter(x => x.ruleId === 'COD-007').length, 0);
  });
});

// ---------------------------------------------------------------------------
// COD-008: cors({ origin: '*' })
// ---------------------------------------------------------------------------
describe('COD-008: Overly Permissive CORS Policy', () => {
  it('detects cors with wildcard origin', () => {
    const findings = scanSnippet('app.use(cors({ origin: "*" }));');
    const f = findings.find(x => x.ruleId === 'COD-008');
    assert.ok(f, 'COD-008 expected');
    assert.equal(f!.severity, 'medium');
    assert.equal(f!.cwe, 'CWE-942');
  });

  it('detects Access-Control-Allow-Origin header set to *', () => {
    const findings = scanSnippet('res.setHeader("Access-Control-Allow-Origin", "*");');
    assert.ok(findings.some(x => x.ruleId === 'COD-008'));
  });

  it('does NOT flag explicit origin whitelist (false positive guard)', () => {
    const findings = scanSnippet(`
      app.use(cors({ origin: "https://myfrontend.com" }));
      app.use(cors({ origin: ["https://site1.com", "https://site2.com"] }));
    `);
    assert.equal(findings.filter(x => x.ruleId === 'COD-008').length, 0);
  });
});

// ---------------------------------------------------------------------------
// COD-009: cookies without httpOnly / secure
// ---------------------------------------------------------------------------
describe('COD-009: Insecure Cookies', () => {
  it('detects cookie set without httpOnly or secure', () => {
    const findings = scanSnippet('res.cookie("sessionToken", token, { maxAge: 86400 });');
    const f = findings.find(x => x.ruleId === 'COD-009');
    assert.ok(f, 'COD-009 expected');
    assert.equal(f!.severity, 'medium');
  });

  it('detects cookie set with httpOnly: false', () => {
    const findings = scanSnippet('res.cookie("auth", token, { httpOnly: false, secure: true });');
    assert.ok(findings.some(x => x.ruleId === 'COD-009'));
  });

  it('does NOT flag cookies with both httpOnly: true and secure: true (false positive guard)', () => {
    const findings = scanSnippet('res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "strict" });');
    assert.equal(findings.filter(x => x.ruleId === 'COD-009').length, 0);
  });
});

// ---------------------------------------------------------------------------
// COD-010: JWT sign without expiresIn
// ---------------------------------------------------------------------------
describe('COD-010: JWT Sign Without Expiration', () => {
  it('detects jwt.sign without expiresIn option', () => {
    const findings = scanSnippet('const token = jwt.sign({ sub: user.id }, JWT_SECRET);');
    const f = findings.find(x => x.ruleId === 'COD-010');
    assert.ok(f, 'COD-010 expected');
    assert.equal(f!.severity, 'medium');
    assert.equal(f!.cwe, 'CWE-613');
  });

  it('does NOT flag jwt.sign with expiresIn (false positive guard)', () => {
    const findings = scanSnippet('const token = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: "1h" });');
    assert.equal(findings.filter(x => x.ruleId === 'COD-010').length, 0);
  });
});

// ---------------------------------------------------------------------------
// COD-011: Missing helmet in Express apps
// ---------------------------------------------------------------------------
describe('COD-011: Missing Helmet in Express App', () => {
  it('detects Express app without helmet', () => {
    const appCode = `
      import express from 'express';
      const app = express();
      app.get('/', (req, res) => res.send('ok'));
      app.listen(3000);
    `;
    const findings = scanSnippet(appCode, 'src/server.ts');
    const f = findings.find(x => x.ruleId === 'COD-011');
    assert.ok(f, 'COD-011 expected');
    assert.equal(f!.severity, 'medium');
    assert.equal(f!.cwe, 'CWE-693');
  });

  it('does NOT flag Express app using helmet (false positive guard)', () => {
    const appCode = `
      import express from 'express';
      import helmet from 'helmet';
      const app = express();
      app.use(helmet());
      app.listen(3000);
    `;
    const findings = scanSnippet(appCode, 'src/server.ts');
    assert.equal(findings.filter(x => x.ruleId === 'COD-011').length, 0);
  });

  it('does NOT flag non-Express files (false positive guard)', () => {
    const utilityCode = 'export const add = (a: number, b: number) => a + b;';
    const findings = scanSnippet(utilityCode, 'src/math.ts');
    assert.equal(findings.filter(x => x.ruleId === 'COD-011').length, 0);
  });
});

// ---------------------------------------------------------------------------
// COD-012: Stack trace sent in error responses
// ---------------------------------------------------------------------------
describe('COD-012: Stack Trace in HTTP Responses', () => {
  it('detects res.send(err.stack)', () => {
    const findings = scanSnippet('app.use((err, req, res, next) => res.status(500).send(err.stack));');
    const f = findings.find(x => x.ruleId === 'COD-012');
    assert.ok(f, 'COD-012 expected');
    assert.equal(f!.severity, 'high');
    assert.equal(f!.cwe, 'CWE-209');
  });

  it('detects res.json({ error: error.stack })', () => {
    const findings = scanSnippet('res.json({ message: "failed", stack: error.stack });');
    assert.ok(findings.some(x => x.ruleId === 'COD-012'));
  });

  it('does NOT flag server-side console.error logging (false positive guard)', () => {
    const findings = scanSnippet(`
      console.error(err.stack);
      res.status(500).json({ error: "Internal server error" });
    `);
    assert.equal(findings.filter(x => x.ruleId === 'COD-012').length, 0);
  });
});

// ---------------------------------------------------------------------------
// COD-013: Supabase service_role in client code
// ---------------------------------------------------------------------------
describe('COD-013: Supabase service_role in Client Code', () => {
  it('detects service_role in file with "use client"', () => {
    const clientCode = `
      "use client";
      import { createClient } from '@supabase/supabase-js';
      const supabase = createClient(URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
    `;
    const findings = scanSnippet(clientCode, 'src/components/UserList.tsx');
    const f = findings.find(x => x.ruleId === 'COD-013');
    assert.ok(f, 'COD-013 expected');
    assert.equal(f!.severity, 'critical');
    assert.equal(f!.cwe, 'CWE-798');
  });

  it('detects service_role in React component (.tsx)', () => {
    const componentCode = 'export const Admin = () => { const key = "service_role"; return null; };';
    const findings = scanSnippet(componentCode, 'src/pages/Admin.tsx');
    assert.ok(findings.some(x => x.ruleId === 'COD-013'));
  });

  it('does NOT flag service_role in backend API route (false positive guard)', () => {
    const backendCode = `
      import { createClient } from '@supabase/supabase-js';
      const admin = createClient(URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
    `;
    const findings = scanSnippet(backendCode, 'src/api/admin.ts');
    assert.equal(findings.filter(x => x.ruleId === 'COD-013').length, 0);
  });
});

// ---------------------------------------------------------------------------
// Ignore Guards & Non-Code Files
// ---------------------------------------------------------------------------
describe('Code Scanner — Ignore Directives and File Types', () => {
  it('skips lines with inline codeshield-ignore comment', () => {
    const code = 'const res = eval(userInput); // codeshield-ignore';
    const findings = scanSnippet(code);
    assert.equal(findings.length, 0);
  });

  it('skips files containing codeshield-ignore-file', () => {
    const code = `
      // codeshield-ignore-file
      eval(userInput);
      res.cookie("token", token);
    `;
    const findings = scanSnippet(code);
    assert.equal(findings.length, 0);
  });

  it('ignores non-code files (e.g. .md, .txt, .json)', () => {
    const findings = scanSnippet('eval("danger")', 'README.md');
    assert.equal(findings.length, 0);
  });
});

// ---------------------------------------------------------------------------
// ReDoS Safety: 100,000-character adversarial string
// ---------------------------------------------------------------------------
describe('Code Scanner — ReDoS Safety', () => {
  const adversarial = 'a'.repeat(100_000);

  for (const rule of CODE_RULES) {
    it(`rule ${rule.id} completes in < 50ms on 100k adversarial string`, () => {
      const file = makeFile('test.ts', adversarial);
      const context = makeContext([file]);

      const start = Date.now();
      rule.check(file, context);
      const duration = Date.now() - start;

      assert.ok(duration < 50, `Rule ${rule.id} took ${duration}ms (exceeded 50ms ReDoS threshold)`);
    });
  }
});

