/** Parsing `--until` / `--failsafe` values and formatting spans of time. */

const UNIT_MS: Record<string, number> = {
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
  w: 7 * 86_400_000,
  y: 365 * 86_400_000,
};

export const DAY_MS = UNIT_MS.d!;

/** "10m", "2d", "1h30m", "1y" → milliseconds, or null if it isn't a duration. */
export function parseDuration(input: string): number | null {
  const s = input.trim().toLowerCase();
  if (!/^(\d+[smhdwy])+$/.test(s)) return null;
  let total = 0;
  for (const [, n, unit] of s.matchAll(/(\d+)([smhdwy])/g)) total += Number(n) * UNIT_MS[unit!]!;
  return total > 0 ? total : null;
}

/**
 * A duration (relative to `now`) or an absolute ISO 8601 time. A time of day needs an
 * explicit zone ("Z" or "+02:00") so a lock never depends on the laptop's time zone setting;
 * a bare date ("2027-01-01") means midnight UTC.
 */
export function parseWhen(input: string, now: Date): Date {
  const d = parseDuration(input);
  if (d !== null) return new Date(now.getTime() + d);
  const s = input.trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return new Date(`${s}T00:00:00Z`);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/i.test(s)) {
    if (/^\d{4}-\d{2}-\d{2}T/.test(s)) {
      throw new Error(`"${input}" has no time zone; add Z (UTC) or an offset like +01:00`);
    }
    throw new Error(`can't read "${input}" as a time (2027-01-01T09:00Z) or a duration (10m, 2d, 1y)`);
  }
  const t = new Date(s);
  if (Number.isNaN(t.getTime())) throw new Error(`invalid time "${input}"`);
  return t;
}

/** 3725 s → "1h 2m", 90 s → "1m 30s", 400 days → "1y 35d". */
export function formatSpan(ms: number): string {
  let s = Math.max(0, Math.round(ms / 1000));
  const parts: string[] = [];
  for (const [unit, size] of [["y", 31_536_000], ["d", 86_400], ["h", 3_600], ["m", 60], ["s", 1]] as const) {
    if (s >= size) {
      parts.push(`${Math.floor(s / size)}${unit}`);
      s %= size;
    }
  }
  return parts.slice(0, 2).join(" ") || "0s";
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}
