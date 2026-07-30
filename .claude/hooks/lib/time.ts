/**
 * Shared Time Utilities
 *
 * Consistent timestamp generation across the hook system.
 * Reads timezone from settings.json via principal.timezone.
 * Used by: all hooks that need timestamps.
 *
 * Implementation note: everything goes through Intl.DateTimeFormat with an
 * explicit timeZone. The old `new Date(date.toLocaleString(...))` round-trip
 * re-parsed through the machine's local zone and silently produced wrong
 * times; toLocaleString also throws RangeError on non-IANA values like "PDT".
 * An invalid configured zone now falls back to UTC instead of crashing hooks.
 */

import { getPrincipal } from './identity';

function getTimezone(): string {
  const tz = getPrincipal().timezone || 'UTC';
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return tz;
  } catch {
    return 'UTC';
  }
}

interface TimeParts {
  year: string;
  month: string;
  day: string;
  hour: string;
  minute: string;
  second: string;
}

function partsIn(timezone: string, date: Date): TimeParts {
  const fmt = new Intl.DateTimeFormat('en-US', {
    timeZone: timezone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  });
  const out: Partial<Record<string, string>> = {};
  for (const part of fmt.formatToParts(date)) {
    out[part.type] = part.value;
  }
  return {
    year: out.year ?? '1970',
    month: out.month ?? '01',
    day: out.day ?? '01',
    hour: out.hour ?? '00',
    minute: out.minute ?? '00',
    second: out.second ?? '00',
  };
}

function tzShortName(timezone: string, date: Date): string {
  const fmt = new Intl.DateTimeFormat('en-US', {
    timeZone: timezone,
    timeZoneName: 'short',
  });
  return fmt.formatToParts(date).find((p) => p.type === 'timeZoneName')?.value || 'UTC';
}

function utcOffset(timezone: string, date: Date): string {
  const fmt = new Intl.DateTimeFormat('en-US', {
    timeZone: timezone,
    timeZoneName: 'longOffset',
  });
  const name = fmt.formatToParts(date).find((p) => p.type === 'timeZoneName')?.value || '';
  const match = name.match(/GMT([+-]\d{2}:\d{2})/);
  return match ? match[1] : '+00:00';
}

/**
 * Get full timestamp string: "YYYY-MM-DD HH:MM:SS TZ"
 */
export function getPSTTimestamp(): string {
  const timezone = getTimezone();
  const now = new Date();
  const t = partsIn(timezone, now);
  return `${t.year}-${t.month}-${t.day} ${t.hour}:${t.minute}:${t.second} ${tzShortName(timezone, now)}`;
}

/**
 * Get date only: "YYYY-MM-DD"
 */
export function getPSTDate(): string {
  const t = partsIn(getTimezone(), new Date());
  return `${t.year}-${t.month}-${t.day}`;
}

/**
 * Get year-month for directory structure: "YYYY-MM"
 */
export function getYearMonth(): string {
  return getPSTDate().substring(0, 7);
}

/**
 * Get ISO8601 timestamp with timezone offset
 */
export function getISOTimestamp(): string {
  const timezone = getTimezone();
  const now = new Date();
  const t = partsIn(timezone, now);
  return `${t.year}-${t.month}-${t.day}T${t.hour}:${t.minute}:${t.second}${utcOffset(timezone, now)}`;
}

/**
 * Get timestamp formatted for filenames: "YYYY-MM-DD-HHMMSS"
 */
export function getFilenameTimestamp(): string {
  const t = partsIn(getTimezone(), new Date());
  return `${t.year}-${t.month}-${t.day}-${t.hour}${t.minute}${t.second}`;
}

/**
 * Get timestamp components for custom formatting
 */
export function getPSTComponents(): {
  year: number;
  month: string;
  day: string;
  hours: string;
  minutes: string;
  seconds: string;
} {
  const t = partsIn(getTimezone(), new Date());
  return {
    year: parseInt(t.year, 10),
    month: t.month,
    day: t.day,
    hours: t.hour,
    minutes: t.minute,
    seconds: t.second,
  };
}

/**
 * Get timezone string for display
 */
export function getTimezoneDisplay(): string {
  const timezone = getTimezone();
  return tzShortName(timezone, new Date());
}
