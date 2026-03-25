/**
 * Formatting utilities
 */

import type { Severity } from '../types/vulnerability.js';
import { SEVERITY_CONFIG } from '../constants/severities.js';

/**
 * Format a finding ID for display
 */
export function formatFindingId(id: string): string {
  return id.slice(0, 12);
}

/**
 * Format duration in milliseconds to human readable
 */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3600000) {
    const minutes = Math.floor(ms / 60000);
    const seconds = Math.floor((ms % 60000) / 1000);
    return `${minutes}m ${seconds}s`;
  }
  const hours = Math.floor(ms / 3600000);
  const minutes = Math.floor((ms % 3600000) / 60000);
  return `${hours}h ${minutes}m`;
}

/**
 * Format a timestamp to ISO string
 */
export function formatTimestamp(date: Date = new Date()): string {
  return date.toISOString();
}

/**
 * Format a number with commas
 */
export function formatNumber(num: number): string {
  return num.toLocaleString();
}

/**
 * Format bytes to human readable
 */
export function formatBytes(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) {
    bytes /= 1024;
    i++;
  }
  return `${bytes.toFixed(1)} ${units[i]}`;
}

/**
 * Format severity with color (for terminal)
 */
export function formatSeverity(severity: Severity): string {
  const config = SEVERITY_CONFIG[severity];
  const colors: Record<Severity, string> = {
    critical: '\x1b[31m', // red
    high: '\x1b[33m', // yellow
    medium: '\x1b[33m', // yellow
    low: '\x1b[32m', // green
    info: '\x1b[37m', // white
  };
  const reset = '\x1b[0m';
  return `${colors[severity]}${config.icon} ${config.label}${reset}`;
}

/**
 * Format a percentage
 */
export function formatPercentage(value: number, decimals: number = 1): string {
  return `${value.toFixed(decimals)}%`;
}

/**
 * Truncate string with ellipsis
 */
export function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - 3) + '...';
}

/**
 * Format code snippet for display
 */
export function formatCodeSnippet(code: string, maxLines: number = 10): string {
  const lines = code.split('\n');
  if (lines.length <= maxLines) return code;
  return lines.slice(0, maxLines).join('\n') + '\n...';
}

/**
 * Create a table from data (for terminal)
 */
export function formatTable(
  headers: string[],
  rows: string[][],
  options: { padding?: number; separator?: string } = {}
): string {
  const padding = (options.padding !== undefined ? options.padding : 2) as number;
  const separator = options.separator ?? '│';

  // Calculate column widths
  const widths = headers.map((header, i) => {
    const maxRowWidth = Math.max(...rows.map(row => row[i]?.length ?? 0));
    return Math.max(header.length, maxRowWidth);
  });

  // Build separator line
  const separatorLine = widths.map(w => '─'.repeat(w + padding)).join('┼');

  // Format row
  const formatRow = (cells: string[]) =>
    separator +
    cells.map((cell, i) => ' '.repeat(padding / 2) + cell.padEnd(widths[i]!) + ' '.repeat(padding / 2)).join(separator) +
    separator;

  // Build table
  const table: string[] = [];
  table.push(separatorLine);
  table.push(formatRow(headers));
  table.push(separatorLine);
  rows.forEach(row => table.push(formatRow(row)));
  table.push(separatorLine);

  return table.join('\n');
}

/**
 * Format a URL for display (truncate if too long)
 */
export function formatUrl(url: string, maxLength: number = 60): string {
  if (url.length <= maxLength) return url;
  try {
    const parsed = new URL(url);
    const display = `${parsed.protocol}//${parsed.host}${parsed.pathname.slice(0, 20)}${parsed.pathname.length > 20 ? '...' : ''}`;
    return display.length > maxLength ? display.slice(0, maxLength - 3) + '...' : display;
  } catch {
    return url.slice(0, maxLength - 3) + '...';
  }
}

/**
 * Format findings summary
 */
export function formatFindingsSummary(findings: { severity: Severity }[]): string {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const f of findings) {
    counts[f.severity]++;
  }

  return `
Critical: ${counts.critical}
High:     ${counts.high}
Medium:   ${counts.medium}
Low:      ${counts.low}
Info:     ${counts.info}
Total:    ${findings.length}
`.trim();
}