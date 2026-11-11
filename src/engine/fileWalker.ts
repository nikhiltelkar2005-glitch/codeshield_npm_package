import * as fs from 'node:fs';
import * as path from 'node:path';
import { ScannedFile } from '../types.js';
import {
  BINARY_EXTENSIONS,
  MAX_FILE_BYTES,
  MAX_FILE_COUNT,
  SKIP_DIRS,
  TEXT_EXTENSIONS,
} from '../utils/constants.js';

export interface FileWalkerOptions {
  root: string;
  maxFiles?: number;
  maxBytes?: number;
  onSkip?: (filePath: string, reason: string) => void;
}

export interface FileWalkerResult {
  files: ScannedFile[];
  filesVisited: number;
  filesSkipped: number;
  truncated: boolean;
}

export function walkFiles(root: string, options: Partial<FileWalkerOptions> = {}): FileWalkerResult {
  const resolvedRoot = path.resolve(root);
  let canonicalRoot: string;
  try {
    canonicalRoot = fs.realpathSync(resolvedRoot);
  } catch {
    canonicalRoot = resolvedRoot;
  }
  const maxFiles = options.maxFiles ?? MAX_FILE_COUNT;
  const maxBytes = options.maxBytes ?? MAX_FILE_BYTES;
  const onSkip = options.onSkip;

  const files: ScannedFile[] = [];
  let filesVisited = 0;
  let filesSkipped = 0;
  let truncated = false;

  let rootStat: fs.Stats;
  try {
    rootStat = fs.statSync(resolvedRoot);
  } catch {
    return { files: [], filesVisited: 0, filesSkipped: 1, truncated: false };
  }

  if (rootStat.isFile()) {
    const ext = path.extname(resolvedRoot).toLowerCase();
    const fileName = path.basename(resolvedRoot);
    const isKnownDotfile = fileName === '.gitignore' || fileName === '.env' || fileName.startsWith('.env.');
    if (BINARY_EXTENSIONS.has(ext)) {
      onSkip?.(resolvedRoot, 'binary extension');
      return { files: [], filesVisited: 0, filesSkipped: 1, truncated: false };
    }
    if (!isKnownDotfile && ext !== '' && !TEXT_EXTENSIONS.has(ext)) {
      onSkip?.(resolvedRoot, `unknown extension (${ext})`);
      return { files: [], filesVisited: 0, filesSkipped: 1, truncated: false };
    }
    if (rootStat.size > maxBytes) {
      onSkip?.(resolvedRoot, 'file too large');
      return { files: [], filesVisited: 0, filesSkipped: 1, truncated: false };
    }
    try {
      const content = fs.readFileSync(resolvedRoot, 'utf8');
      const lines = content.split(/\r?\n/);
      return {
        files: [{ path: resolvedRoot, relativePath: path.basename(resolvedRoot), content, lines }],
        filesVisited: 1,
        filesSkipped: 0,
        truncated: false,
      };
    } catch {
      return { files: [], filesVisited: 0, filesSkipped: 1, truncated: false };
    }
  }

  function recurse(dir: string): void {
    if (truncated) return;

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      onSkip?.(dir, 'unreadable directory');
      filesSkipped++;
      return;
    }

    for (const entry of entries) {
      if (truncated) return;

      const fullPath = path.join(dir, entry.name);

      if (entry.isSymbolicLink()) {
        let realTarget: string;
        try {
          realTarget = fs.realpathSync(fullPath);
        } catch {
          onSkip?.(fullPath, 'broken symlink');
          filesSkipped++;
          continue;
        }

        const escapes =
          (!realTarget.startsWith(resolvedRoot + path.sep) && realTarget !== resolvedRoot) &&
          (!realTarget.startsWith(canonicalRoot + path.sep) && realTarget !== canonicalRoot);
        if (escapes) {
          onSkip?.(fullPath, 'symlink escapes scan root');
          filesSkipped++;
          continue;
        }

        let targetStat: fs.Stats;
        try {
          targetStat = fs.statSync(realTarget);
        } catch {
          filesSkipped++;
          continue;
        }

        if (targetStat.isDirectory()) {
          onSkip?.(fullPath, 'symlink to directory (skipped to avoid cycle)');
          filesSkipped++;
          continue;
        }
      }

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) {
          onSkip?.(fullPath, `skipped directory (${entry.name})`);
          filesSkipped++;
          continue;
        }
        recurse(fullPath);
        continue;
      }

      if (!entry.isFile() && !entry.isSymbolicLink()) {
        onSkip?.(fullPath, 'non-regular file');
        filesSkipped++;
        continue;
      }

      const ext = path.extname(entry.name).toLowerCase();

      if (BINARY_EXTENSIONS.has(ext)) {
        onSkip?.(fullPath, 'binary extension');
        filesSkipped++;
        continue;
      }

      const isKnownDotfile = entry.name === '.gitignore' || entry.name === '.env' || entry.name.startsWith('.env.');
      if (!isKnownDotfile && ext !== '' && !TEXT_EXTENSIONS.has(ext)) {
        onSkip?.(fullPath, `unknown extension (${ext})`);
        filesSkipped++;
        continue;
      }

      let stat: fs.Stats;
      try {
        stat = fs.statSync(fullPath);
      } catch {
        onSkip?.(fullPath, 'stat failed');
        filesSkipped++;
        continue;
      }

      if (stat.size > maxBytes) {
        onSkip?.(fullPath, `file exceeds size limit (${stat.size} bytes)`);
        filesSkipped++;
        continue;
      }

      if (filesVisited >= maxFiles) {
        truncated = true;
        return;
      }

      let content: string;
      try {
        content = fs.readFileSync(fullPath, 'utf8');
      } catch {
        onSkip?.(fullPath, 'read error');
        filesSkipped++;
        continue;
      }

      filesVisited++;
      const relativePath = path.relative(resolvedRoot, fullPath);
      files.push({
        path: fullPath,
        relativePath,
        content,
        lines: content.split(/\r?\n/),
      });
    }
  }

  recurse(resolvedRoot);
  return { files, filesVisited, filesSkipped, truncated };
}
