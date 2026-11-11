import { styleText } from 'node:util';
import { Severity } from '../types.js';

export interface ColorOptions {
  enabled?: boolean;
}

export function areColorsEnabled(options?: ColorOptions): boolean {
  if (options?.enabled !== undefined) {
    return options.enabled;
  }
  if (process.env['NO_COLOR'] !== undefined && process.env['NO_COLOR'] !== '') {
    return false;
  }
  return Boolean(process.stdout && process.stdout.isTTY);
}

export class Colorizer {
  private readonly enabled: boolean;

  constructor(options?: ColorOptions) {
    this.enabled = areColorsEnabled(options);
  }

  private style(format: Parameters<typeof styleText>[0], text: string): string {
    return this.enabled ? styleText(format, text, { validateStream: false }) : text;
  }

  bold(text: string): string {
    return this.style('bold', text);
  }

  dim(text: string): string {
    return this.style('dim', text);
  }

  red(text: string): string {
    return this.style('red', text);
  }

  green(text: string): string {
    return this.style('green', text);
  }

  yellow(text: string): string {
    return this.style('yellow', text);
  }

  cyan(text: string): string {
    return this.style('cyan', text);
  }

  blue(text: string): string {
    return this.style('blue', text);
  }

  magenta(text: string): string {
    return this.style('magenta', text);
  }

  severityBadge(sev: Severity): string {
    switch (sev) {
      case 'critical':
        return this.bold(this.red('🔴 CRITICAL'));
      case 'high':
        return this.bold(this.yellow('🟠 HIGH'));
      case 'medium':
        return this.yellow('🟡 MEDIUM');
      case 'low':
        return this.blue('🔵 LOW');
      case 'info':
        return this.dim('⚪ INFO');
    }
  }

  scoreBadge(score: number, grade: string): string {
    const label = `${score}/100 [Grade ${grade}]`;
    if (score >= 90) return this.bold(this.green(label));
    if (score >= 75) return this.bold(this.cyan(label));
    if (score >= 60) return this.bold(this.yellow(label));
    if (score >= 40) return this.bold(this.red(label));
    return this.bold(this.red(`⚠️  ${label}`));
  }
}
