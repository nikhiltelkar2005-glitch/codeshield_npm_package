# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-11

### Added
- **Core Engine & File Walker:**
  - High-performance, zero-runtime-dependency directory walker with symlink escape prevention, cycle detection, file size limits (1 MiB), and total file caps (10,000 files).
  - Framework and project type auto-detection (Next.js, Vite, Express, Remix, Create React App).
- **Secrets Scanner (`src/scanners/secrets.ts`):**
  - 10 pattern rules (SEC-001 through SEC-010): AWS Access Keys, Stripe Live Keys, GitHub Tokens, AI Provider API Keys (OpenAI, Anthropic), Supabase service_role keys, Private Key Blocks, Database connection strings with passwords, JWT secrets, Generic high-entropy API secrets, and Client-side leaked environment variables (`NEXT_PUBLIC_*`, `VITE_*`).
  - Automatic masking (`AKIA****`) and placeholder exclusion heuristics.
- **Environment Scanner (`src/scanners/env.ts`):**
  - Rules ENV-001 through ENV-004: `.env` files not covered by `.gitignore`, committed `.env` files, missing `.env.example` templates, and enabled production source maps.
- **Dependency Scanner & Verification (`src/scanners/dependencies.ts`):**
  - Rules DEP-001 through DEP-005: Hallucinated / non-existent packages on npm registry, newly published packages (< 30 days old), packages with `install` or `postinstall` scripts, and typosquatting detection using Damerau-Levenshtein distance against top npm packages.
  - CLI command: `codeshield verify <package>`.
  - Offline support via `--offline`.
- **Code Scanner (`src/scanners/code.ts`):**
  - 13 AST-free security rules (COD-001 through COD-013) targeting common AI coding model traps: `eval` / `new Function`, SQL injection via string concatenation, NoSQL query injection via raw `req.body`, Command injection via `child_process.exec`, Insecure `Math.random()` for tokens/passwords, Weak hashing (MD5/SHA-1) for passwords, XSS via `dangerouslySetInnerHTML` / `.innerHTML`, Overly permissive CORS (`*`), Insecure cookies without `httpOnly`/`secure`, JWT signed without `expiresIn`, Missing `helmet` security headers in Express apps, Leaking error stack traces in API responses, and Client-side usage of Supabase `service_role` keys.
- **Reporting & Scoring Engine (`src/report/`):**
  - 0–100 Security Scoring formula with per-rule noise capping.
  - Three output modes: Simple (default, beginner-friendly with actionable AI prompts), Detailed (`--detailed`), JSON (`--json`), and SARIF v2.1.0 (`--sarif`).
  - Terminal color styling using `node:util styleText` with automatic NO_COLOR and TTY detection.
  - Terminal sanitization removing ANSI escape injection, C0 control characters, and OSC hyperlinks.
- **Auto-Fixer & Scan History (`src/fix/`):**
  - `codeshield fix`: Applies safe, reversible remediations (e.g. adding `.env` to `.gitignore`, creating `.env.example` with sanitized placeholders). Interactive confirmation diff with `--yes` override and automatic `.codeshield.bak` backups.
  - Scan history tracking via `.codeshield/last-scan.json` comparing previous and current scan scores.

