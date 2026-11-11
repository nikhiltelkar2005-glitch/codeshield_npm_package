import * as fs from 'node:fs';
import * as path from 'node:path';
import { ProjectType } from '../types.js';

interface PackageJsonStructure {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

export function readPackageJson(root: string): PackageJsonStructure | null {
  const pkgPath = path.join(root, 'package.json');
  try {
    if (!fs.existsSync(pkgPath)) return null;
    const raw = fs.readFileSync(pkgPath, 'utf8');
    return JSON.parse(raw) as PackageJsonStructure;
  } catch {
    return null;
  }
}

export function detectProjectType(root: string, existingFilePaths?: string[]): ProjectType {
  const resolvedRoot = path.resolve(root);
  const pkg = readPackageJson(resolvedRoot);

  const deps = pkg?.dependencies ?? {};
  const devDeps = pkg?.devDependencies ?? {};
  const allDeps = { ...deps, ...devDeps };

  if ('next' in allDeps) return 'nextjs';

  const nextConfigExists = ['next.config.js', 'next.config.mjs', 'next.config.ts'].some(cfg =>
    fs.existsSync(path.join(resolvedRoot, cfg))
  );
  if (nextConfigExists) return 'nextjs';

  const hasVite = 'vite' in allDeps ||
    fs.existsSync(path.join(resolvedRoot, 'vite.config.js')) ||
    fs.existsSync(path.join(resolvedRoot, 'vite.config.ts')) ||
    fs.existsSync(path.join(resolvedRoot, 'vite.config.mjs'));
  const hasReact = 'react' in allDeps;

  if (hasVite && hasReact) return 'vite-react';

  if ('express' in deps) return 'express';

  const indexHtmlRoot = fs.existsSync(path.join(resolvedRoot, 'index.html'));
  const indexHtmlPublic = fs.existsSync(path.join(resolvedRoot, 'public', 'index.html'));
  if (indexHtmlRoot || indexHtmlPublic) {
    const hasFrameworkDeps = ['vue', 'angular', 'svelte', '@angular/core'].some(d => d in allDeps);
    if (!hasFrameworkDeps && !hasVite) return 'plain-html';
  }

  return 'unknown';
}
