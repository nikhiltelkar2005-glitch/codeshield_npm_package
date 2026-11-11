import { Finding, ScanContext, Scanner } from '../types.js';
import { fetchRegistry, type RegistryFetchFn } from '../utils/registry.js';
import { levenshtein } from '../utils/levenshtein.js';

const NPM_NAME_RE =
  /^(?:@[a-z0-9-*~][a-z0-9-*._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;

export function isValidNpmName(name: string): boolean {
  if (name.length === 0 || name.length > 214) return false;
  return NPM_NAME_RE.test(name);
}

const POPULAR_PACKAGES: readonly string[] = [
  'react', 'react-dom', 'react-router', 'react-router-dom',
  'next', 'nuxt', 'vue', 'angular', 'svelte',
  'express', 'fastify', 'koa', 'hapi',
  'lodash', 'underscore', 'ramda',
  'axios', 'node-fetch', 'got', 'superagent',
  'typescript', 'ts-node', 'tsx',
  'webpack', 'vite', 'rollup', 'esbuild', 'parcel',
  'jest', 'vitest', 'mocha', 'jasmine', 'ava', 'tap',
  'eslint', 'prettier', 'husky', 'lint-staged',
  'dotenv', 'cors', 'helmet', 'morgan', 'body-parser',
  'mongoose', 'sequelize', 'prisma', 'typeorm', 'knex',
  'socket.io', 'ws', 'jsonwebtoken', 'bcrypt', 'bcryptjs',
  'uuid', 'dayjs', 'moment', 'date-fns',
  'chalk', 'colors', 'ora', 'inquirer',
  'zod', 'yup', 'joi',
  'sharp', 'multer', 'formidable',
];

function findTyposquat(name: string): string | undefined {
  const bare = name.includes('/') ? (name.split('/')[1] ?? name) : name;
  for (const popular of POPULAR_PACKAGES) {
    if (levenshtein(bare, popular) === 1) {
      return popular;
    }
  }
  return undefined;
}

class Semaphore {
  private running = 0;
  private queue: Array<() => void> = [];

  constructor(private readonly limit: number) {}

  async run<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }

  private acquire(): Promise<void> {
    if (this.running < this.limit) {
      this.running++;
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      this.queue.push(resolve);
    });
  }

  private release(): void {
    const next = this.queue.shift();
    if (next) {
      next();
    } else {
      this.running--;
    }
  }
}

export interface DepScanOptions {
  offline?: boolean;
  fetchFn?: RegistryFetchFn;
}

function findingHallucinated(pkgName: string, pkgFile: string): Finding {
  return {
    ruleId: 'DEP-001',
    severity: 'critical',
    title: `Package "${pkgName}" does not exist on npm`,
    plainExplanation:
      `The package "${pkgName}" was not found on the npm registry. ` +
      'AI assistants sometimes invent package names that do not exist — ' +
      'called "package hallucination". Installing a non-existent package may ' +
      'succeed if a malicious actor has since published one with that name.',
    file: pkgFile,
    line: 1,
    fix: `Search for "${pkgName}" on npmjs.com to find the correct package name, or remove the dependency.`,
    aiPrompt:
      `The package "${pkgName}" does not exist on npm. ` +
      'Please find the correct package name or suggest an alternative that actually exists.',
    cwe: 'CWE-829',
  };
}

function findingNewPackage(pkgName: string, pkgFile: string, createdAt: string): Finding {
  return {
    ruleId: 'DEP-002',
    severity: 'high',
    title: `Package "${pkgName}" was first published less than 30 days ago`,
    plainExplanation:
      `"${pkgName}" appeared on npm only recently (${createdAt}). ` +
      'Very new packages have not been reviewed by the community and could be ' +
      'malicious or abandoned. Confirm this is the package you intended.',
    file: pkgFile,
    line: 1,
    fix: `Verify "${pkgName}" on npmjs.com. Prefer well-established packages with a track record.`,
    aiPrompt:
      `The package "${pkgName}" was published less than 30 days ago. ` +
      'Is there a more established alternative? If this package is intentional, explain why.',
    cwe: 'CWE-1104',
  };
}

function findingInstallScript(pkgName: string, pkgFile: string, scriptName: string): Finding {
  return {
    ruleId: 'DEP-003',
    severity: 'high',
    title: `Package "${pkgName}" runs a "${scriptName}" script on install`,
    plainExplanation:
      `"${pkgName}" defines a \`${scriptName}\` script that runs automatically when you do \`npm install\`. ` +
      'This is a common vector for supply-chain attacks: malicious code can ' +
      'exfiltrate secrets, install backdoors, or modify your files at install time.',
    file: pkgFile,
    line: 1,
    fix: `Audit the source of "${pkgName}" before installing, or use \`npm install --ignore-scripts\` and verify manually.`,
    aiPrompt:
      `The package "${pkgName}" has an \`${scriptName}\` script. ` +
      'Is this script necessary? What does it do, and is there a safer alternative?',
    cwe: 'CWE-506',
  };
}

function findingTyposquat(pkgName: string, pkgFile: string, similarTo: string): Finding {
  return {
    ruleId: 'DEP-004',
    severity: 'high',
    title: `Package "${pkgName}" looks like a typosquat of "${similarTo}"`,
    plainExplanation:
      `"${pkgName}" is one character away from the popular package "${similarTo}". ` +
      'Typosquatting is an attack where a malicious package is published with a name ' +
      'nearly identical to a trusted one, hoping developers will mistype it.',
    file: pkgFile,
    line: 1,
    fix: `Double-check whether you meant "${similarTo}". If not, verify "${pkgName}" is legitimate on npmjs.com.`,
    aiPrompt:
      `The package "${pkgName}" is one character away from "${similarTo}". ` +
      `Did you mean "${similarTo}"? If "${pkgName}" is intentional, please confirm it is a known package.`,
    cwe: 'CWE-829',
  };
}

function findingCouldNotCheck(pkgName: string, pkgFile: string, reason: string): Finding {
  return {
    ruleId: 'DEP-005',
    severity: 'info',
    title: `Could not check package "${pkgName}" against npm registry`,
    plainExplanation:
      `CodeShield tried to look up "${pkgName}" on the npm registry but failed: ${reason}. ` +
      'The package has NOT been verified as safe — please check it manually.',
    file: pkgFile,
    line: 1,
    fix: `Manually verify "${pkgName}" at https://www.npmjs.com/package/${pkgName}`,
    aiPrompt:
      `The npm registry check for "${pkgName}" failed (${reason}). ` +
      'Please manually confirm this package is legitimate.',
  };
}

function extractDependencies(pkgJson: Record<string, unknown>): string[] {
  const deps: string[] = [];
  for (const field of ['dependencies', 'devDependencies', 'peerDependencies'] as const) {
    const section = pkgJson[field];
    if (section !== null && typeof section === 'object') {
      deps.push(...Object.keys(section as object));
    }
  }
  return [...new Set(deps)];
}

export async function scanDependencies(
  context: ScanContext,
  options: DepScanOptions = {},
): Promise<Finding[]> {
  const findings: Finding[] = [];

  const pkgFile = context.files.find(
    (f) => f.relativePath === 'package.json' || f.relativePath === './package.json',
  );

  if (!pkgFile) return findings;

  let pkgJson: Record<string, unknown>;
  try {
    pkgJson = JSON.parse(pkgFile.content) as Record<string, unknown>;
  } catch {
    return findings;
  }

  const depNames = extractDependencies(pkgJson);
  if (depNames.length === 0) return findings;

  const pkgFilePath = pkgFile.relativePath;

  if (options.offline) {
    for (const name of depNames) {
      if (!isValidNpmName(name)) continue;
      const typosquat = findTyposquat(name);
      if (typosquat) findings.push(findingTyposquat(name, pkgFilePath, typosquat));
    }
    return findings;
  }

  const sem = new Semaphore(5);
  const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;

  const tasks = depNames.map((name) =>
    sem.run(async (): Promise<Finding[]> => {
      const local: Finding[] = [];

      const typosquat = findTyposquat(name);
      if (typosquat) local.push(findingTyposquat(name, pkgFilePath, typosquat));

      if (!isValidNpmName(name)) {
        return local;
      }

      let result;
      try {
        result = await fetchRegistry(name, 5_000, options.fetchFn);
      } catch (err: unknown) {
        const reason = err instanceof Error ? err.message : String(err);
        local.push(findingCouldNotCheck(name, pkgFilePath, reason));
        return local;
      }

      if (result.status === 'not-found') {
        local.push(findingHallucinated(name, pkgFilePath));
        return local;
      }

      if (result.status === 'error') {
        local.push(findingCouldNotCheck(name, pkgFilePath, result.reason));
        return local;
      }

      const { data } = result;

      if (data.created) {
        const createdMs = Date.parse(data.created);
        if (!isNaN(createdMs) && Date.now() - createdMs < thirtyDaysMs) {
          local.push(findingNewPackage(name, pkgFilePath, data.created));
        }
      }

      for (const scriptName of ['install', 'postinstall', 'preinstall'] as const) {
        if (scriptName in data.latestScripts) {
          local.push(findingInstallScript(name, pkgFilePath, scriptName));
          break;
        }
      }

      return local;
    }),
  );

  const allResults = await Promise.all(tasks);
  for (const result of allResults) {
    findings.push(...result);
  }

  return findings;
}

export const depScanner: Scanner = {
  name: 'dependencies',
  scan: (_context: ScanContext): Finding[] => {
    return [];
  },
};
