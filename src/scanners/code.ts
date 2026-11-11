import * as path from 'node:path';
import { Finding, ScanContext, ScannedFile, Scanner, Severity } from '../types.js';
import { sanitize } from '../utils/sanitize.js';

export const CODE_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs']);

export function isCodeFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return CODE_EXTENSIONS.has(ext);
}

function isCommentLine(line: string): boolean {
  const trimmed = line.trim();
  return (
    trimmed.startsWith('//') ||
    trimmed.startsWith('*') ||
    trimmed.startsWith('/*') ||
    trimmed.startsWith('<!--')
  );
}

function isLineIgnored(line: string): boolean {
  return /codeshield-ignore|@codeshield-ignore|codeshield-disable/i.test(line);
}

function isIgnoredFile(content: string): boolean {
  return content.includes('codeshield-ignore-file');
}

export interface RuleMatch {
  line: number;
  snippet?: string;
  customExplanation?: string;
}

export interface CodeRule {
  id: string;
  severity: Severity;
  title: string;
  cwe: string;
  plainExplanation: string;
  fix: string;
  aiPromptTemplate: string;
  check: (file: ScannedFile, context: ScanContext) => RuleMatch[];
}

function matchLineRegex(
  file: ScannedFile,
  matcher: (line: string, lineNum: number) => boolean,
): RuleMatch[] {
  const matches: RuleMatch[] = [];
  for (let i = 0; i < file.lines.length; i++) {
    const line = file.lines[i] ?? '';
    if (isCommentLine(line) || isLineIgnored(line)) continue;
    if (matcher(line, i + 1)) {
      matches.push({ line: i + 1, snippet: line.trim() });
    }
  }
  return matches;
}

const EVAL_RE = /\b(?:eval\s*\(|new\s+Function\s*\()/;
const SQL_KEYWORD_RE = /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b/i;

function isSqlConcatenation(line: string): boolean {
  const hasJsConcat = /['"`]\s*\+|\+\s*['"`]/.test(line);
  const hasTemplateVar = /\$\{[^}]+\}/.test(line) && line.includes('`');

  if (SQL_KEYWORD_RE.test(line)) {
    if (hasTemplateVar) return true;
    if (hasJsConcat) return true;
  }
  if (/\.(?:query|raw|execute)\s*\(/.test(line)) {
    if (hasTemplateVar || hasJsConcat) return true;
  }
  return false;
}

const NOSQL_INJECTION_RE = /\b(?:\w+\.)?(?:find|findOne|findOneAndUpdate|findOneAndDelete|findById|deleteMany|deleteOne|updateOne|updateMany|countDocuments)\s*\(\s*(?:req\.body|req\.query|req\.params)\s*(?:,|\))/;

const EXEC_CALL_RE = /(?:\b(?:child_process|cp)\.exec\s*\(|(?<!\.)\bexec\s*\()/;
const STATIC_STRING_EXEC_RE = /(?:\b(?:child_process|cp)\.exec|(?<!\.)\bexec)\s*\(\s*(?:'[^']*'|"[^"]*")\s*[,)]/;

const MATH_RANDOM_RE = /Math\.random\s*\(\)/;
const SENSITIVE_TOKEN_RE = /(?:token|pass(?:word|wd)?|secret|key|salt|nonce|session|otp|auth|pin|csrf)/i;

const WEAK_HASH_RE = /(?:createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)|crypto\.createHash\(\s*['"](?:md5|sha1)['"]\s*\))/i;
const PWD_CONTEXT_RE = /(?:pass(?:word|wd)?|pwd|secret|auth|credential|token|user)/i;

function isDangerousHtmlInjection(line: string): boolean {
  if (/dangerouslySetInnerHTML\s*=/.test(line)) {
    if (!/dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*['"`][^'"`${}]*['"`]\s*\}\s*\}/.test(line)) {
      return true;
    }
  }

  if (/\binnerHTML\s*=/.test(line)) {
    const parts = line.split(/innerHTML\s*=\s*/);
    const rhs = parts[1]?.trim() ?? '';
    const cleanRhs = rhs.replace(/;$/, '').trim();

    if (/^'(?:[^'\\]|\\.)*'$/.test(cleanRhs) && !cleanRhs.includes('+')) return false;
    if (/^"(?:[^"\\]|\\.)*"$/.test(cleanRhs) && !cleanRhs.includes('+')) return false;
    if (/^`[^`]*`$/.test(cleanRhs) && !cleanRhs.includes('${') && !cleanRhs.includes('+')) return false;
    return true;
  }

  return false;
}

const CORS_WILDCARD_RE = /cors\s*\(\s*\{[^}]*origin\s*:\s*(?:['"]\*['"]|true)/;
const CORS_HEADER_WILDCARD_RE = /res\.(?:setHeader|header)\s*\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"]\s*\)/;

const COOKIE_CALL_RE = /res\.cookie\s*\(/;
const JWT_SIGN_RE = /jwt\.sign\s*\(/;
const STACK_IN_RES_RE = /res\.(?:status\(\d+\)\.)?(?:send|json)\s*\([^)]*(?:err|error)\.stack\b/;
const SUPABASE_SERVICE_ROLE_RE = /\b(?:SUPABASE_SERVICE_ROLE_KEY|service_role)\b/;

export const CODE_RULES: readonly CodeRule[] = [
  {
    id: 'COD-001',
    severity: 'critical',
    title: 'Dynamic Code Execution via eval() or new Function()',
    cwe: 'CWE-95',
    plainExplanation:
      'Using `eval()` or `new Function()` executes arbitrary strings as JavaScript code. ' +
      'If any untrusted input reaches these functions, attackers can execute arbitrary code ' +
      'on your server or in your users’ browsers (Remote Code Execution / XSS).',
    fix: 'Parse structured data using `JSON.parse()`, or replace dynamic code evaluation with standard functions and object lookups.',
    aiPromptTemplate:
      'Remove `eval()` or `new Function()` on line {LINE}. Replace it with safe data parsing such as `JSON.parse()` or static lookup maps.',
    check: (file) =>
      matchLineRegex(file, (line) => EVAL_RE.test(line)),
  },
  {
    id: 'COD-002',
    severity: 'critical',
    title: 'SQL Query Built via String Concatenation (SQL Injection)',
    cwe: 'CWE-89',
    plainExplanation:
      'Constructing SQL queries using template literals (${...}) or string concatenation (+) allows ' +
      'attackers to inject malicious SQL clauses (SQL Injection). This can bypass authentication, ' +
      'leak confidential records, or destroy database tables.',
    fix: 'Use parameterized queries or prepared statements (e.g., `db.query("SELECT * FROM users WHERE id = $1", [id])`) or a type-safe ORM/query builder.',
    aiPromptTemplate:
      'Refactor the SQL query on line {LINE} to use parameterized queries with placeholders ($1, ?, or named parameters) instead of string concatenation.',
    check: (file) =>
      matchLineRegex(file, (line) => isSqlConcatenation(line)),
  },
  {
    id: 'COD-003',
    severity: 'high',
    title: 'Unsanitized Request Body in Database Query (NoSQL Injection)',
    cwe: 'CWE-943',
    plainExplanation:
      'Passing `req.body`, `req.query`, or `req.params` directly to database query methods (e.g. `find(req.body)`) ' +
      'allows attackers to pass objects containing NoSQL operators like `{ "$gt": "" }` to bypass password checks or extract all records.',
    fix: 'Extract and validate individual primitive fields explicitly (e.g., `{ email: String(req.body.email) }`) or validate payloads with Zod.',
    aiPromptTemplate:
      'Refactor the database query on line {LINE} to pass only explicitly validated primitive fields instead of the whole `req.body` object.',
    check: (file) =>
      matchLineRegex(file, (line) => NOSQL_INJECTION_RE.test(line)),
  },
  {
    id: 'COD-004',
    severity: 'critical',
    title: 'Command Injection Risk in child_process.exec()',
    cwe: 'CWE-78',
    plainExplanation:
      'Calling `child_process.exec()` with variables or string concatenation passes input directly to an OS shell. ' +
      'If arguments contain shell metacharacters (`;`, `|`, `&&`, `$()`), attackers can execute arbitrary OS commands.',
    fix: 'Use `child_process.execFile()` or `spawn()` with an array of arguments, and ensure `{ shell: false }`.',
    aiPromptTemplate:
      'Replace `child_process.exec()` on line {LINE} with `execFile()` or `spawn()`, passing arguments as an array instead of string concatenation.',
    check: (file) =>
      matchLineRegex(file, (line) => {
        if (!EXEC_CALL_RE.test(line)) return false;
        if (STATIC_STRING_EXEC_RE.test(line) && !line.includes('+') && !line.includes('${')) {
          return false;
        }
        return true;
      }),
  },
  {
    id: 'COD-005',
    severity: 'high',
    title: 'Insecure PRNG (Math.random) Used for Security-Sensitive Value',
    cwe: 'CWE-338',
    plainExplanation:
      '`Math.random()` is not cryptographically secure; its sequence can be predicted by attackers. ' +
      'Using it for tokens, session IDs, OTPs, or passwords allows attackers to guess generated values.',
    fix: 'Use Node.js `crypto.randomBytes(32).toString("hex")` or `crypto.randomUUID()` for cryptographically secure randomness.',
    aiPromptTemplate:
      'Replace `Math.random()` on line {LINE} with `crypto.randomBytes()` or `crypto.randomUUID()` from `node:crypto`.',
    check: (file) =>
      matchLineRegex(file, (line) => {
        if (!MATH_RANDOM_RE.test(line)) return false;
        return SENSITIVE_TOKEN_RE.test(line);
      }),
  },
  {
    id: 'COD-006',
    severity: 'high',
    title: 'Weak Hash Algorithm (MD5/SHA1) Used for Credentials',
    cwe: 'CWE-327',
    plainExplanation:
      'MD5 and SHA-1 are cryptographically broken algorithms susceptible to collisions and fast brute-force/rainbow table attacks. ' +
      'They must never be used for storing or hashing passwords.',
    fix: 'Use an adaptive, salted password hashing algorithm such as `bcrypt`, `argon2`, or `scrypt`.',
    aiPromptTemplate:
      'Replace MD5/SHA-1 on line {LINE} with a dedicated password hashing library such as `bcrypt` or `argon2`.',
    check: (file) =>
      matchLineRegex(file, (line) => {
        if (!WEAK_HASH_RE.test(line)) return false;
        return PWD_CONTEXT_RE.test(line);
      }),
  },
  {
    id: 'COD-007',
    severity: 'high',
    title: 'Unescaped HTML Injection via innerHTML or dangerouslySetInnerHTML',
    cwe: 'CWE-79',
    plainExplanation:
      'Rendering dynamic content through `dangerouslySetInnerHTML` or `element.innerHTML` bypasses framework XSS sanitization. ' +
      'If user-controlled data is injected, attackers can execute malicious scripts in victims’ browsers (Cross-Site Scripting).',
    fix: 'Use standard text rendering (`{text}` in JSX or `element.textContent`), or sanitize HTML with DOMPurify before inserting.',
    aiPromptTemplate:
      'Refactor line {LINE} to use safe text interpolation or sanitize HTML using `DOMPurify.sanitize()` before setting innerHTML.',
    check: (file) =>
      matchLineRegex(file, (line) => isDangerousHtmlInjection(line)),
  },
  {
    id: 'COD-008',
    severity: 'medium',
    title: 'Overly Permissive CORS Policy (Wildcard Origin)',
    cwe: 'CWE-942',
    plainExplanation:
      'Configuring CORS with `origin: "*"` or `Access-Control-Allow-Origin: *` allows any website on the internet ' +
      'to make requests to your API. If your API handles authentication cookies or private data, malicious sites can read responses.',
    fix: 'Specify an explicit array of approved frontend domains or validate the request Origin header against an allowlist.',
    aiPromptTemplate:
      'Update the CORS configuration on line {LINE} to specify allowed origin domains explicitly rather than using wildcard "*".',
    check: (file) =>
      matchLineRegex(file, (line) => {
        if (CORS_WILDCARD_RE.test(line)) return true;
        if (CORS_HEADER_WILDCARD_RE.test(line)) return true;
        return false;
      }),
  },
  {
    id: 'COD-009',
    severity: 'medium',
    title: 'Cookie Set Without httpOnly or secure Flags',
    cwe: 'CWE-1004',
    plainExplanation:
      'Cookies set without `httpOnly: true` can be accessed by JavaScript, exposing session credentials to Cross-Site Scripting (XSS) theft. ' +
      'Missing `secure: true` allows cookies to be transmitted over unencrypted HTTP.',
    fix: 'Configure cookies with `{ httpOnly: true, secure: true, sameSite: "lax" }`.',
    aiPromptTemplate:
      'Add `{ httpOnly: true, secure: true, sameSite: "lax" }` to the cookie options on line {LINE}.',
    check: (file) =>
      matchLineRegex(file, (line) => {
        if (!COOKIE_CALL_RE.test(line)) return false;
        const hasHttpOnly = /httpOnly\s*:\s*true/.test(line);
        const hasSecure = /secure\s*:\s*true/.test(line);
        return !hasHttpOnly || !hasSecure;
      }),
  },
  {
    id: 'COD-010',
    severity: 'medium',
    title: 'JWT Token Signed Without Expiration (expiresIn)',
    cwe: 'CWE-613',
    plainExplanation:
      'JSON Web Tokens created without an `expiresIn` option remain valid indefinitely. ' +
      'If a token is ever intercepted or leaked, attackers maintain permanent access unless you build a token revocation system.',
    fix: 'Specify an expiration window in the `jwt.sign()` options, e.g. `{ expiresIn: "1h" }` or `{ expiresIn: "15m" }`.',
    aiPromptTemplate:
      'Add an expiration option to `jwt.sign()` on line {LINE}, such as `{ expiresIn: "1h" }`.',
    check: (file) =>
      matchLineRegex(file, (line) => {
        if (!JWT_SIGN_RE.test(line)) return false;
        return !/expiresIn\s*:/.test(line);
      }),
  },
  {
    id: 'COD-011',
    severity: 'medium',
    title: 'Missing Security Headers Middleware (Helmet) in Express App',
    cwe: 'CWE-693',
    plainExplanation:
      'This Express application does not use `helmet` to set secure HTTP headers. ' +
      'Helmet protects your app against MIME-type sniffing, clickjacking, XSS framing, and information disclosure.',
    fix: 'Install helmet (`npm install helmet`) and add `app.use(helmet())` near the top of your Express middleware stack.',
    aiPromptTemplate:
      'Import `helmet` from "helmet" and add `app.use(helmet())` right after initializing the Express application.',
    check: (file) => {
      const content = file.content;
      const isExpressApp =
        /\bexpress\s*\(\s*\)/.test(content) &&
        /\b\.listen\s*\(/.test(content);

      if (!isExpressApp) return [];

      const hasHelmet =
        /\bhelmet\b/.test(content) ||
        /\bapp\.use\s*\(\s*helmet/.test(content);

      if (!hasHelmet) {
        return [{ line: 1, customExplanation: 'Express application initialized without helmet() security headers middleware.' }];
      }
      return [];
    },
  },
  {
    id: 'COD-012',
    severity: 'high',
    title: 'Server Stack Trace Exposed in HTTP Response',
    cwe: 'CWE-209',
    plainExplanation:
      'Returning `err.stack` or raw error objects in HTTP responses leaks internal code paths, database queries, ' +
      'library versions, and architecture details to potential attackers.',
    fix: 'Log the stack trace on the server with `console.error(err)` and return a generic error message (e.g. `{ error: "Internal Server Error" }`) to the client.',
    aiPromptTemplate:
      'Remove `err.stack` from the HTTP response on line {LINE}. Log it server-side using `console.error(err)` and return a generic error message to clients.',
    check: (file) =>
      matchLineRegex(file, (line) => STACK_IN_RES_RE.test(line)),
  },
  {
    id: 'COD-013',
    severity: 'critical',
    title: 'Supabase service_role Admin Key Used in Client-Side Code',
    cwe: 'CWE-798',
    plainExplanation:
      'The Supabase `service_role` key bypasses all Row Level Security (RLS) policies and grants complete admin access to your database. ' +
      'Referencing it in client components or browser bundles leaks your entire database to any web visitor.',
    fix: 'Use the public `anon` key (`NEXT_PUBLIC_SUPABASE_ANON_KEY`) in client code, and restrict `service_role` strictly to backend API routes.',
    aiPromptTemplate:
      'Remove the `service_role` key from client code on line {LINE}. Use the public `anon` key instead and enforce Row Level Security in Supabase.',
    check: (file) => {
      const isExplicitClient = file.content.includes("'use client'") || file.content.includes('"use client"');
      const ext = path.extname(file.relativePath).toLowerCase();
      const isReactComponent = (ext === '.jsx' || ext === '.tsx') && !file.relativePath.includes('/api/') && !file.relativePath.includes('/server/');

      if (!isExplicitClient && !isReactComponent) return [];

      return matchLineRegex(file, (line) => SUPABASE_SERVICE_ROLE_RE.test(line));
    },
  },
];

export function scanCode(context: ScanContext): Finding[] {
  const findings: Finding[] = [];

  for (const file of context.files) {
    if (!isCodeFile(file.relativePath)) continue;
    if (isIgnoredFile(file.content)) continue;

    for (const rule of CODE_RULES) {
      try {
        const matches = rule.check(file, context);
        for (const match of matches) {
          const lineNum = match.line;
          const snippet = match.snippet ? sanitize(match.snippet) : '';
          const explanation = match.customExplanation ?? rule.plainExplanation;

          findings.push({
            ruleId: rule.id,
            severity: rule.severity,
            title: rule.title,
            cwe: rule.cwe,
            plainExplanation: explanation,
            file: file.relativePath,
            line: lineNum,
            fix: rule.fix,
            aiPrompt: rule.aiPromptTemplate.replace('{LINE}', String(lineNum)) + (snippet ? ` Code: \`${snippet}\`` : ''),
            ...(snippet ? { snippet } : {}),
          });
        }
      } catch {
        // rule failure should not crash scanner
      }
    }
  }

  return findings;
}

export const codeScanner: Scanner = {
  name: 'code',
  scan: scanCode,
};
