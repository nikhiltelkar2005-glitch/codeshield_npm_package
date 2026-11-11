# Contributing to CodeShield

Thank you for contributing to CodeShield! We welcome contributions that help developers identify and fix security vulnerabilities in AI-generated codebases.

---

## Architecture & Design Principles

Before contributing code, please keep these core tenets in mind:

1. **Zero Runtime Dependencies:** CodeShield runs with 0 production dependencies. All CLI parsing, file walking, sanitization, HTTP requests, and reporting use Node.js built-ins (`node:util`, `node:fs`, `node:path`, `node:https`, `node:test`).
2. **Never Execute Target Code:** Scanners perform static inspection only. CodeShield never imports, executes, evaluates, or dynamically requires scanned files.
3. **ReDoS Immunity:** Every regular expression must be linear-time and bounded. All rules are tested against 100,000-character adversarial inputs to verify execution finishes in $< 50\text{ms}$.
4. **Beginner-Friendly Output & AI Prompts:** Every finding must provide a plain-English explanation, a direct remediation recommendation, and an exact copy-paste AI prompt so users can prompt their AI assistant to fix the code.

---

## Development Setup

CodeShield requires **Node.js >= 20.12**.

```bash
# Clone the repository
git clone https://github.com/nikhiltelkar/codeshield.git
cd codeshield

# Install development dependencies (TypeScript and @types/node only)
npm install

# Run the test suite
npm test

# Typecheck without emitting
npm run lint

# Build the project
npm run build

# Run the complete verification suite
npm run prepublishOnly
```

---

## How to Add a Rule

CodeShield uses a **data-driven rule registry**. Adding a new security rule to CodeShield requires no changes to the traversal engine or reporting system.

### 1. Identify the Target Scanner

Choose the appropriate scanner under `src/scanners/`:
- [`src/scanners/code.ts`](file:///Users/nikhiltelkar19gmail.com/Desktop/CODESHILD/src/scanners/code.ts) – Static code patterns in `.js`, `.ts`, `.jsx`, `.tsx` files.
- [`src/scanners/secrets.ts`](file:///Users/nikhiltelkar19gmail.com/Desktop/CODESHILD/src/scanners/secrets.ts) – API keys, private tokens, and credentials.
- [`src/scanners/env.ts`](file:///Users/nikhiltelkar19gmail.com/Desktop/CODESHILD/src/scanners/env.ts) – Environment configuration, `.env` leakage, and build artifacts.
- [`src/scanners/dependencies.ts`](file:///Users/nikhiltelkar19gmail.com/Desktop/CODESHILD/src/scanners/dependencies.ts) – Package manifest and registry integrity.

### 2. Define the Rule Object

For code rules, add an entry to the `CODE_RULES` array in [`src/scanners/code.ts`](file:///Users/nikhiltelkar19gmail.com/Desktop/CODESHILD/src/scanners/code.ts):

```typescript
{
  id: 'COD-014',
  severity: 'high',
  cwe: 'CWE-312',
  title: 'Sensitive Information Stored in LocalStorage',
  explanation:
    'Writing sensitive authentication tokens or credentials to localStorage exposes them to Cross-Site Scripting (XSS) attacks. Any JavaScript executing on your page can access localStorage.',
  fix: 'Store sensitive session tokens in secure, HttpOnly, SameSite cookies instead of localStorage.',
  prompt:
    'Refactor this code to remove token storage in localStorage. Provide an implementation using an HttpOnly, secure cookie or an in-memory session handler.',
  matches(line: string, _file: ScannedFile): boolean {
    return /localStorage\.setItem\s*\(\s*['"`](?:token|jwt|auth|password)['"`]/i.test(line);
  },
}
```

### 3. Add Inline & File-Level Ignore Handling

Rules in `src/scanners/code.ts` and `src/scanners/secrets.ts` automatically respect ignore comments when using the built-in runner:
- `// codeshield-ignore` skips the current line.
- `// codeshield-ignore-file` skips the entire file.

If your rule implements custom matching logic, ensure it checks `isLineIgnored(line)` or `isIgnoredFile(file)`.

### 4. Write Unit & False-Positive Tests

Add comprehensive tests to the corresponding test file in `tests/`:

1. **Detection Test:** Verify that dangerous patterns trigger the finding with the expected severity and CWE ID.
2. **False-Positive Test:** Verify that clean, idiomatic code is **never** flagged.
3. **ReDoS Benchmark Test:** Test your regex against a $100,000$-character adversarial string and assert execution completes in under $50\text{ms}$.

Example test pattern:

```typescript
describe('Code Scanner — COD-014 (LocalStorage Tokens)', () => {
  it('flags token written to localStorage', () => {
    const file = makeFile('localStorage.setItem("jwt_token", userToken);');
    const findings = runCodeRule('COD-014', file);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'high');
  });

  it('does not flag non-sensitive items in localStorage', () => {
    const file = makeFile('localStorage.setItem("theme", "dark");');
    const findings = runCodeRule('COD-014', file);
    assert.equal(findings.length, 0);
  });

  it('runs safely in < 50ms on 100k-character adversarial string', () => {
    const adversarial = 'localStorage.setItem(' + 'a'.repeat(100_000);
    const start = Date.now();
    runCodeRule('COD-014', makeFile(adversarial));
    assert.ok(Date.now() - start < 50);
  });
});
```

### 5. Verify the Entire Suite

Run the full pre-publish verification suite to confirm linting, tests, and build all pass:

```bash
npm run prepublishOnly
```

---

## Submitting Pull Requests

1. Create a feature branch: `git checkout -b feature/my-new-rule`.
2. Commit with descriptive messages.
3. Ensure test coverage for all new rules (including false positives and ReDoS).
4. Submit a Pull Request targeting the `main` branch.

