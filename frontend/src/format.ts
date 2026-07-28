export function formatCount(value: number | null | undefined): string {
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 }).format(value ?? 0);
}

export function formatPercent(value: number | null | undefined): string {
  return new Intl.NumberFormat(undefined, {
    style: 'percent',
    maximumFractionDigits: 0,
  }).format(value ?? 0);
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return 'none';
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return 'invalid';
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}

export function formatDuration(seconds: number | null | undefined): string {
  const value = Math.max(0, Math.round(seconds ?? 0));
  const hours = Math.floor(value / 3600);
  const minutes = Math.floor((value % 3600) / 60);
  const secs = value % 60;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutes) return `${minutes}m ${secs}s`;
  return `${secs}s`;
}

export function formatScore(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return 'none';
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 4 }).format(value);
}

export function shortValue(value: string | null | undefined, length = 10): string {
  if (!value) return 'none';
  if (value.length <= length + 4) return value;
  return `${value.slice(0, length)}...`;
}

export function maskProfile(value: string | null | undefined): string {
  if (!value) return 'profile:none';
  return `profile:${shortValue(value.replace(/[^a-zA-Z0-9:_-]/g, ''), 8)}`;
}

export function metricText(metrics: Record<string, unknown> | null | undefined, key: string): string {
  const value = metrics?.[key];
  if (typeof value === 'number') return formatScore(value);
  if (typeof value === 'string') return value;
  return 'none';
}

export function jsonPreview(value: unknown): string {
  return JSON.stringify(value ?? {}, null, 2).slice(0, 1600);
}
