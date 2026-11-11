import { Severity } from '../types.js';

export const MAX_FILE_BYTES = 1_048_576;

export const MAX_FILE_COUNT = 5_000;

export const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  '.codeshield',
  'dist',
  'dist-test',
  'build',
  'coverage',
  '.yarn',
  '.pnp',
]);

export const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.tiff', '.svg',
  '.mp3', '.mp4', '.wav', '.ogg', '.flac', '.avi', '.mov', '.mkv',
  '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
  '.exe', '.dll', '.so', '.dylib', '.class', '.pyc', '.wasm',
  '.pdf', '.docx', '.xlsx', '.pptx',
  '.ttf', '.otf', '.woff', '.woff2',
  '.bin', '.lock',
]);

export const TEXT_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.json', '.jsonc',
  '.env', '.env.local', '.env.development', '.env.production', '.env.test',
  '.yaml', '.yml',
  '.toml',
  '.sh', '.bash', '.zsh',
  '.py',
  '.rb',
  '.php',
  '.go',
  '.java',
  '.cs',
  '.c', '.cpp', '.h', '.hpp',
  '.rs',
  '.html', '.htm',
  '.css', '.scss', '.sass',
  '.md', '.mdx',
  '.txt',
  '.xml',
  '.ini', '.cfg', '.conf',
  '.Dockerfile', '',
]);

export const SEVERITIES: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'] as const;

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};
