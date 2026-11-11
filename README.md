# CodeShield

> **A fast, zero-dependency security scanner for AI-generated codebases.**

AI coding assistants (Cursor, Copilot, ChatGPT, Claude, v0, Bolt) are extraordinary at writing code quickly, but they frequently introduce dangerous security flaws: hardcoding API keys, hallucinating nonexistent npm packages, writing SQL queries with string concatenation, using `Math.random()` for auth tokens, or forgetting basic security headers like `helmet`.

**CodeShield** acts as an instant security guardrail for your development workflow and CI/CD pipelines.

---

## ⚡ 30-Second Quick Start

No installation required. Run directly with `npx`:

```bash
# Scan current project
npx @nikhil_telkar/codeshield scan .

# Automatically apply safe fixes (.gitignore, .env.example)
npx @nikhil_telkar/codeshield fix .

# Check if an npm package is real, safe, or an AI hallucination
npx @nikhil_telkar/codeshield verify express
```

Or install globally to use the short `codeshield` command anywhere:

```bash
npm install -g @nikhil_telkar/codeshield
codeshield scan .
```

---

## 🖥️ Clean, Developer-Friendly Terminal Output

```text
CodeShield — scanning /Users/dev/my-ai-app
(offline mode: npm registry checks skipped)

────────────────────────────────────────────────────────────
Security Score : 54/100 [Grade C] (Needs Attention)
Files Scanned  : 42 files
Findings       : 3 [1 critical, 1 high, 1 medium]
Duration       : 28ms
────────────────────────────────────────────────────────────

🎯 Fix These First (Top Priorities):

🔴 CRITICAL [SEC-001] Hardcoded AWS Access Key
  File      : src/config/aws.ts:14
  Line      : AWS_ACCESS_KEY_ID=AKIA****
  Issue     : An AWS Access Key ID was found directly in your code. Anyone with access to this repo can compromise your AWS account.
  Fix       : Move credentials to process.env.AWS_ACCESS_KEY_ID or use IAM roles.
  AI Prompt : Refactor src/config/aws.ts to load AWS credentials from process.env.AWS_ACCESS_KEY_ID.

🟠 HIGH [COD-002] SQL Query Built via String Concatenation (SQL Injection)
  File      : src/routes/users.ts:28
  Line      : const query = "SELECT * FROM users WHERE id = '" + req.query.id + "'";
  Issue     : Constructing SQL queries using template literals or string concatenation allows SQL Injection.
  Fix       : Use parameterized queries (e.g., db.query("SELECT * FROM users WHERE id = $1", [id])).
  AI Prompt : Refactor the SQL query on line 28 to use parameterized queries with placeholders.

🟡 MEDIUM [COD-011] Missing Security Headers Middleware (Helmet) in Express App
  File      : src/server.ts:1
  Issue     : Express application initialized without helmet() security headers middleware.
  Fix       : Install helmet (`npm install helmet`) and add `app.use(helmet())` near the top of your Express middleware stack.
  AI Prompt : Import `helmet` from "helmet" and add `app.use(helmet())` right after initializing the Express application.
```

---

## 🔍 What CodeShield Checks

CodeShield evaluates codebases across four core dimensions with **zero runtime dependencies**:

### 1. Secrets Scanner
- **AWS Credentials:** Hardcoded `AKIA...` access keys (`CWE-798`).
- **Stripe Keys:** Live API keys (`sk_live_...`) (`CWE-798`).
- **GitHub Tokens:** Personal access tokens (`ghp_...`, `github_pat_...`) (`CWE-798`).
- **AI Provider API Keys:** OpenAI (`sk-...`), Anthropic (`sk-ant-...`) keys (`CWE-798`).
- **Supabase Service Keys:** Hardcoded `service_role` administrative keys (`CWE-798`).
- **Database Connection Strings:** URLs containing embedded passwords (`postgres://user:pass@host/db`) (`CWE-256`).
- **Private Key Headers:** Unencrypted PEM blocks (`BEGIN RSA/OPENSSH PRIVATE KEY`) (`CWE-312`).
- **Hardcoded JWT Secrets:** Literal strings passed to `jwt.sign()` (`CWE-798`).
- **Generic API Credentials:** High-entropy API key and token assignments (`CWE-798`).
- **Public Client Leaks:** Private keys placed in `NEXT_PUBLIC_*` or `VITE_*` variables (`CWE-200`).

### 2. Dependency Scanner (AI Hallucination Guard)
- **Hallucinated Packages (DEP-001):** Verifies all dependencies in `package.json` against the npm registry to catch non-existent packages invented by AI tools (`CWE-829`).
- **Newly Published Packages (DEP-002):** Warns if dependencies were published $< 30$ days ago (`CWE-829`).
- **Install Scripts (DEP-003):** Flags packages that run `preinstall`, `install`, or `postinstall` shell scripts (`CWE-829`).
- **Typosquatting (DEP-004):** Detects packages that are 1 character away from popular libraries (`expres`, `lodahs`) (`CWE-829`).

### 3. Environment & Config Scanner
- **Unignored `.env` Files:** Credentials exposed to git tracking (`CWE-552`).
- **Missing `.env.example`:** Repositories with `.env` but no sanitized template for collaborators (`CWE-552`).
- **Production Source Maps:** `productionBrowserSourceMaps: true` or `sourcemap: true` leaking unminified code in production (`CWE-540`).

### 4. Code Pattern Scanner
- **Dynamic Code Execution:** `eval()` and `new Function()` (`CWE-95`).
- **SQL Injection:** String concatenation in `db.query()`, `prisma.$queryRawUnsafe()`, etc. (`CWE-89`).
- **NoSQL Injection:** Raw `req.body` or `req.query` passed directly into MongoDB/Mongoose queries (`CWE-943`).
- **Command Injection:** `child_process.exec()` called with variables (`CWE-78`).
- **Insecure Randomness:** `Math.random()` used for tokens, passwords, or session IDs (`CWE-338`).
- **Broken Cryptography:** MD5 or SHA-1 used for password hashing (`CWE-328`).
- **Cross-Site Scripting (XSS):** `dangerouslySetInnerHTML` or `element.innerHTML` with dynamic variables (`CWE-79`).
- **Permissive CORS:** `cors({ origin: '*' })` (`CWE-942`).
- **Insecure Cookies:** `res.cookie()` without `httpOnly: true` or `secure: true` (`CWE-1004`, `CWE-614`).
- **Indefinite JWTs:** `jwt.sign()` calls missing an `expiresIn` option (`CWE-613`).
- **Missing Helmet:** Express applications without `helmet` security header middleware (`CWE-693`).
- **Stack Trace Leakage:** Returning `err.stack` in HTTP responses (`CWE-209`).
- **Client-Side Supabase Admin:** Using Supabase `service_role` keys inside frontend components (`CWE-200`).

---

## 🛠️ CLI Commands & Options

```text
Usage:
  codeshield scan [path] [options]    Scan directory (default: current dir)
  codeshield fix [path] [--yes]       Apply safe, reversible fixes automatically
  codeshield verify <package>         Check a single npm package
  codeshield --help                   Show this help
  codeshield --version                Show version
```

### Scan Options

| Option | Description |
| :--- | :--- |
| `--detailed` | Show full metadata for all findings (CWE, rule ID, file, line, explanation). |
| `--json` | Output machine-readable JSON (ideal for CI pipelines). |
| `--sarif` | Output static analysis results in SARIF v2.1.0 format (for GitHub Security). |
| `--fail-on <severity>` | Set exit code to 1 if any findings match or exceed `<severity>` (`critical`, `high`, `medium`, `low`, `info`). Default: `info`. |
| `--severity <severity>` | Filter the report to only include findings at or above `<severity>`. Default: `info`. |
| `--offline` | Skip all npm registry lookups (runs purely offline in $< 50\text{ms}$). |

### Fix Options

| Option | Description |
| :--- | :--- |
| `-y, --yes` | Apply safe fixes automatically without an interactive prompt. |

*Safety guarantee:* `codeshield fix` only applies reversible, non-destructive changes (`.gitignore` additions, creating `.env.example`). It creates `.codeshield.bak` backups before modifying files and never writes outside the scan root.

### Exit Codes

| Code | Meaning |
| :---: | :--- |
| `0` | **Passed:** No findings at or above the `--fail-on` threshold. |
| `1` | **Failed:** One or more findings detected at or above the `--fail-on` threshold. |
| `2` | **Tool Error:** Invalid CLI arguments, missing files, or unreadable directory. |

---

## 📊 How the Security Score Works

CodeShield calculates an objective score between **0 and 100**:

$$\text{Score} = \max\left(0, 100 - \sum \text{Capped Deductions}\right)$$

### Severity Weights & Deductions

| Severity | Points Deducted per Finding | Maximum Deductions per Rule |
| :--- | :---: | :---: |
| **Critical** | -25 | Capped at -35 max per rule |
| **High** | -15 | Capped at -35 max per rule |
| **Medium** | -8 | Capped at -35 max per rule |
| **Low** | -3 | Capped at -35 max per rule |
| **Info** | 0 | 0 |

### Anti-Noise Rule Capping
To prevent a single repetitive issue (such as 50 missing cookie flags) from zeroing out the entire score, deductions for any single rule are capped at **35 points**.

### Grade Scale
- **90–100 [Grade A]** — Excellent: Clean security posture.
- **75–89 [Grade B]** — Good: Minor low/medium issues.
- **60–74 [Grade C]** — Needs Attention: High-risk findings present.
- **40–59 [Grade D]** — Poor: Multiple severe vulnerabilities.
- **0–39 [Grade F]** — Critical: Immediate attention required.

---

## 🤖 CI / CD Integration

Add `.github/workflows/security.yml`:

```yaml
name: CodeShield Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      # Option A: Fail the build on high/critical findings
      - name: Run CodeShield Scan
        run: npx @nikhil_telkar/codeshield scan . --fail-on high

      # Option B: Upload SARIF report to GitHub Advanced Security tab
      - name: Generate SARIF report
        if: always()
        run: npx @nikhil_telkar/codeshield scan . --sarif > results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## 🔒 Privacy & Security Statement

- **100% Local Execution:** CodeShield never uploads your source code, filenames, or directory paths to external servers.
- **Zero Telemetry:** No analytics, no phone-home pings, no cookies, no tracking.
- **Zero Runtime Dependencies:** Zero third-party packages installed in production. Zero supply chain risk.
- **Strict Read-Only Scanning:** CodeShield inspects text files using Node built-in file APIs. It **never** dynamically evaluates, requires, or imports your code.
- **Optional Network Access:** The only network request CodeShield can make is an HTTPS query to `https://registry.npmjs.org/<package>` to verify npm packages during `codeshield verify` or standard scans. Pass `--offline` to run completely disconnected.

---

## 📄 License

[MIT](LICENSE) © 2026 Nikhil Telkar
