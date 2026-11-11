import { Finding, ScanContext, Scanner, Severity } from '../types.js';
import { maskSecret, sanitize } from '../utils/sanitize.js';

const PLACEHOLDER_STRINGS = new Set([
  'your_api_key',
  'your_secret_key',
  'your_jwt_secret',
  'your_password',
  'your_token',
  'your_key_here',
  'my_api_key',
  'my_secret_key',
  'changeme',
  'replace_me',
  'placeholder',
  'dummy_token',
  'example_key',
  'test_secret',
  'undefined',
  'null',
]);

const PLACEHOLDER_REGEXES = [
  /your[_-]?(?:api[_-]?)?(?:key|secret|token|password)/i,
  /replace[_-]?me/i,
  /enter[_-]?your/i,
  /insert[_-]?here/i,
  /<[^>]+>/,
  /\.{3,}/,
  /0{12,}/,
  /x{12,}/i,
  /^1234567890*$/,
];

export function isPlaceholder(val: string): boolean {
  const clean = val.trim().toLowerCase();
  if (clean.length < 6) return true;
  if (PLACEHOLDER_STRINGS.has(clean)) return true;
  return PLACEHOLDER_REGEXES.some(re => re.test(clean));
}

export function isLineIgnored(line: string): boolean {
  return /codeshield-ignore|@codeshield-ignore|codeshield-disable/i.test(line);
}

export function isTestOrFixture(relativePath: string, content: string): boolean {
  if (content.includes('codeshield-ignore-file')) return true;
  return false;
}

export interface SecretRuleDefinition {
  id: string;
  severity: Severity;
  title: string;
  cwe?: string;
  plainExplanation: string;
  fix: string;
  aiPromptTemplate: string;
  regex: RegExp;
  extractSecret?: (match: RegExpExecArray) => string | null;
}

export const SECRET_RULES: SecretRuleDefinition[] = [
  {
    id: 'SEC-001',
    severity: 'critical',
    title: 'Hardcoded AWS Access Key',
    cwe: 'CWE-798',
    plainExplanation:
      'An Amazon Web Services (AWS) Access Key ID was found directly in your source code. If committed to GitHub or shared, attackers can scan for this key and access your cloud infrastructure, potentially deleting services or incurring thousands of dollars in unauthorized usage.',
    fix: 'Store the AWS Access Key in an environment variable (such as AWS_ACCESS_KEY_ID) or use IAM Roles instead of hardcoded credentials.',
    aiPromptTemplate:
      'Refactor this code to remove the hardcoded AWS Access Key on line {LINE}. Use process.env.AWS_ACCESS_KEY_ID and update .env.example with a placeholder.',
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    extractSecret: m => m[1] ?? null,
  },
  {
    id: 'SEC-002',
    severity: 'critical',
    title: 'Hardcoded Stripe Live Secret Key',
    cwe: 'CWE-798',
    plainExplanation:
      'A live Stripe secret API key was found in your code. Live Stripe keys have full administrative access to your Stripe account, allowing anyone who finds them to view customer payment details, initiate refunds, or charge cards.',
    fix: 'Move your Stripe secret key to a server-side environment variable (e.g., STRIPE_SECRET_KEY in a .env file that is ignored by Git). Never commit live secret keys.',
    aiPromptTemplate:
      'Remove the hardcoded Stripe live key on line {LINE}. Use process.env.STRIPE_SECRET_KEY and document how to configure it in .env.',
    regex: /\b(sk_live_[0-9a-zA-Z]{24,})\b/g,
    extractSecret: m => m[1] ?? null,
  },
  {
    id: 'SEC-003',
    severity: 'critical',
    title: 'Hardcoded GitHub Personal Access Token',
    cwe: 'CWE-798',
    plainExplanation:
      'A GitHub personal access token (PAT) or OAuth token was found in your code. Anyone with this token can access your private GitHub repositories, alter code, or delete repositories.',
    fix: 'Revoke this token immediately in your GitHub developer settings, generate a new one, and inject it securely via environment variables or CI/CD secrets (e.g. GITHUB_TOKEN).',
    aiPromptTemplate:
      'Replace the hardcoded GitHub token on line {LINE} with process.env.GITHUB_TOKEN.',
    regex: /\b(ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{22,})\b/g,
    extractSecret: m => m[1] ?? null,
  },
  {
    id: 'SEC-004',
    severity: 'critical',
    title: 'Hardcoded AI Provider API Key (OpenAI / Anthropic)',
    cwe: 'CWE-798',
    plainExplanation:
      'An API key for an AI model provider (OpenAI or Anthropic) was found hardcoded in this file. Exposed AI keys are frequently scraped by bots within minutes of being pushed, resulting in immediate unauthorized API usage and billing fees.',
    fix: 'Move the key to your .env file as OPENAI_API_KEY or ANTHROPIC_API_KEY, and make sure .env is included in your .gitignore.',
    aiPromptTemplate:
      'Refactor this code to remove the hardcoded AI API key on line {LINE}. Load it from process.env.OPENAI_API_KEY (or ANTHROPIC_API_KEY) and verify that error handling exists if the environment variable is missing.',
    regex: /\b(sk-(?:proj-|ant-)?[0-9a-zA-Z_-]{20,})\b/g,
    extractSecret: m => m[1] ?? null,
  },
  {
    id: 'SEC-005',
    severity: 'critical',
    title: 'Hardcoded Supabase service_role Key',
    cwe: 'CWE-798',
    plainExplanation:
      'A Supabase service_role key was found hardcoded in your code. The service_role key completely bypasses all Supabase Row Level Security (RLS) policies and grants full administrative access to your entire database. It must NEVER be hardcoded or exposed to the frontend.',
    fix: 'Store the service_role key in a secure server-side environment variable (SUPABASE_SERVICE_ROLE_KEY). For client-side code, use only the public anon key with strict RLS policies.',
    aiPromptTemplate:
      'Refactor line {LINE} to remove the hardcoded Supabase service_role key. Use process.env.SUPABASE_SERVICE_ROLE_KEY on the backend, and ensure this key is never passed to frontend components.',
    regex: /(?:service_role|supabase_service)[^=\n]{0,30}=\s*['"](eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,})['"]/i,
    extractSecret: m => m[1] ?? null,
  },
  {
    id: 'SEC-006',
    severity: 'critical',
    title: 'Hardcoded Private Cryptographic Key',
    cwe: 'CWE-321',
    plainExplanation:
      'An unencrypted private encryption or signing key block was found in this file. Private keys are meant to be kept secret; exposing them allows attackers to decrypt private communications, forge signatures, or impersonate your server.',
    fix: 'Store private keys in a secrets manager or load them at runtime from a secure file path specified in an environment variable (e.g. PRIVATE_KEY_PATH).',
    aiPromptTemplate:
      'Remove the hardcoded private key block starting at line {LINE}. Load the key securely from an environment variable or file system path configured via process.env.',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    extractSecret: m => m[0],
  },
  {
    id: 'SEC-007',
    severity: 'high',
    title: 'Database Connection String with Embedded Password',
    cwe: 'CWE-798',
    plainExplanation:
      'A database connection string containing a raw username and password was found in your code. Exposing database credentials allows unauthorized users to read, modify, or drop your database tables.',
    fix: 'Extract the database connection string into a DATABASE_URL environment variable in your .env file, and ensure .env is listed in .gitignore.',
    aiPromptTemplate:
      'Remove the hardcoded database connection string on line {LINE}. Use process.env.DATABASE_URL instead and provide a .env.example with dummy credentials.',
    regex: /\b(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|mariadb):\/\/[^:\s'"]+:([^@\s'"]+)@[^\s'"]+/g,
    extractSecret: m => m[1] ?? null,
  },
  {
    id: 'SEC-008',
    severity: 'high',
    title: 'Hardcoded or Weak JWT Secret',
    cwe: 'CWE-798',
    plainExplanation:
      'A JSON Web Token (JWT) secret key was found hardcoded as a plain string. Attackers can use this secret to forge authentication tokens and impersonate any user, including administrators.',
    fix: 'Move the JWT secret to process.env.JWT_SECRET and ensure it is generated using a cryptographically secure random value with at least 256 bits of entropy.',
    aiPromptTemplate:
      'Update line {LINE} to remove the hardcoded JWT secret. Use process.env.JWT_SECRET and throw an error if the environment variable is not set.',
    regex: /\b(?:jwt(?:Secret|_secret)?|JWT_SECRET)\s*[:=]\s*['"]([^'"]{4,})['"]|\bjwt\.sign\s*\([^,]+,\s*['"]([^'"]{4,})['"]/g,
    extractSecret: m => m[1] ?? m[2] ?? null,
  },
  {
    id: 'SEC-009',
    severity: 'high',
    title: 'Hardcoded Generic API Secret or Token',
    cwe: 'CWE-798',
    plainExplanation:
      'A generic secret key, API token, or access credential was found hardcoded. Anyone who views this source code will have access to the associated third-party service.',
    fix: 'Store this secret in an environment variable and load it via process.env.',
    aiPromptTemplate:
      'Extract the hardcoded API credential on line {LINE} into an environment variable loaded through process.env.',
    regex: /\b(?:api_key|apiKey|api_secret|apiSecret|access_token|accessToken|secret_key|secretKey|private_token)\s*[:=]\s*['"]([0-9a-zA-Z_\-]{24,})['"]/g,
    extractSecret: m => m[1] ?? null,
  },
  {
    id: 'SEC-010',
    severity: 'critical',
    title: 'Private Key or Secret Leaked to Public Client Variable',
    cwe: 'CWE-200',
    plainExplanation:
      'Environment variables prefixed with NEXT_PUBLIC_ or VITE_ are embedded into the client-side JavaScript bundle during build and sent to every browser that visits your website. A private key, service role key, or administrative secret was assigned to a public variable name, exposing it directly to all site visitors.',
    fix: 'Remove the NEXT_PUBLIC_ or VITE_ prefix so the secret remains strictly on the server, and only access it in server-side routes (e.g. Next.js API routes or server components).',
    aiPromptTemplate:
      'The secret on line {LINE} is prefixed with NEXT_PUBLIC_ or VITE_, which bundles it into client-side code sent to users. Refactor this to remove the public prefix, move the secret to server-only code, and handle any necessary operations via a backend API route.',
    regex: /\b(NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|PRIVATE_KEY|SERVICE_ROLE|ADMIN_KEY|TOKEN)|VITE_[A-Z0-9_]*(?:SECRET|PRIVATE_KEY|SERVICE_ROLE|ADMIN_KEY|TOKEN))\s*[:=]\s*['"]?([^'"\s;,\n]+)/g,
    extractSecret: m => m[2] ?? null,
  },
];

export function scanSecrets(context: ScanContext): Finding[] {
  const findings: Finding[] = [];

  for (const file of context.files) {
    if (isTestOrFixture(file.relativePath, file.content)) {
      continue;
    }

    for (let lineIdx = 0; lineIdx < file.lines.length; lineIdx++) {
      const line = file.lines[lineIdx] ?? '';

      if (isLineIgnored(line)) {
        continue;
      }

      for (const rule of SECRET_RULES) {
        const re = new RegExp(rule.regex.source, rule.regex.flags);
        let match: RegExpExecArray | null;

        while ((match = re.exec(line)) !== null) {
          const rawSecret = rule.extractSecret ? rule.extractSecret(match) : match[0];

          if (!rawSecret || isPlaceholder(rawSecret)) {
            if (!re.global) break;
            if (match.index === re.lastIndex) re.lastIndex++;
            continue;
          }

          const maskedVal = maskSecret(rawSecret);
          const sanitizedLine = sanitize(line.trim());
          const maskedSnippet = sanitizedLine.replace(rawSecret, maskedVal);

          const aiPrompt = `${rule.aiPromptTemplate.replace('{LINE}', String(lineIdx + 1))} Code: ${maskedSnippet}`;

          const finding: Finding = {
            ruleId: rule.id,
            severity: rule.severity,
            title: rule.title,
            plainExplanation: rule.plainExplanation,
            file: file.relativePath,
            line: lineIdx + 1,
            fix: rule.fix,
            aiPrompt,
            snippet: maskedSnippet,
            ...(rule.cwe ? { cwe: rule.cwe } : {}),
          };

          findings.push(finding);

          if (!re.global) break;
          if (match.index === re.lastIndex) re.lastIndex++;
        }
      }
    }
  }

  return findings;
}

export const secretsScanner: Scanner = {
  name: 'secrets',
  scan: scanSecrets,
};
