const ANSI_RE =
  /\x1b\[[0-9;]*[A-Za-z]|\x1b\][^\x07]*(?:\x07|\x1b\\)|\x1b|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g;

export function sanitize(s: string): string {
  return s.replace(ANSI_RE, '');
}

export function maskSecret(value: string): string {
  if (value.length <= 4) return '****';
  return `${value.slice(0, 4)}****`;
}
