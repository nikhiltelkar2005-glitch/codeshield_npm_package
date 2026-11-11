# Security Policy

## Supported Versions

We release patches and security fixes for the following versions of CodeShield:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

---

## Reporting a Vulnerability

If you discover a potential security vulnerability in CodeShield itself (such as path traversal, command injection, denial-of-service via ReDoS, or unauthorized code execution), **please do not open a public GitHub issue**.

Instead, report it privately using one of the following methods:

1. **GitHub Private Vulnerability Advisory:** Submit a report via the [Security Advisories tab](https://github.com/nikhiltelkar/codeshield/security/advisories/new) on GitHub.
2. **Email:** Send details directly to Nikhil Telkar at `nikhiltelkar19@gmail.com` with the subject line `[SECURITY] Vulnerability in CodeShield`.

### What to Include

To help us triage and resolve the issue quickly, please provide:
- A description of the vulnerability and its potential impact.
- Steps to reproduce or a minimal proof-of-concept repository/file.
- The version of CodeShield and Node.js environment where the issue was observed.
- Any suggested mitigations or patches (if available).

### Response Timeline

- **Initial Response:** Within 48 hours to confirm receipt of your report.
- **Triage & Assessment:** Within 5 business days with an assessment and estimated timeline.
- **Fix & Advisory:** We adhere to responsible disclosure principles. Once a fix is verified, a patch release and CVE / security advisory will be published simultaneously.

---

## CodeShield Security Guarantees & Constraints

When assessing potential issues in CodeShield, our design guarantees:

1. **Zero Runtime Dependencies:** CodeShield runs solely on Node.js built-ins (`node:fs`, `node:path`, `node:https`, `node:util`).
2. **Read-Only Code Analysis:** CodeShield *never* executes, `eval`s, `import`s, or requires the scanned source files.
3. **No Code Uploads / No Telemetry:** CodeShield operates entirely offline by default (or skips registry lookups with `--offline`). It never sends your source code to external servers.
4. **Strict Path Traversal Bounds:** File traversal and automated fix operations (`codeshield fix`) are strictly bounded to the target root directory using `resolveSafePath`.
5. **ReDoS Guard:** All built-in regular expressions are bounded and benchmarked to execute in $< 50\text{ms}$ on $100,000$-character adversarial inputs.

