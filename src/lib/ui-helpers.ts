/**
 * SentinelAI — frontend UI helpers (owned by the frontend agent).
 * Severity color system, classification/status styles, formatters, source icons.
 */
import { format, formatDistanceToNowStrict, parseISO } from "date-fns";
import {
  Activity,
  BrickWall,
  Crosshair,
  Database,
  FileText,
  Fingerprint,
  Globe,
  Radar,
  Satellite,
  ScanSearch,
  Server,
  Shield,
  Terminal,
  Wifi,
  type LucideIcon,
} from "lucide-react";
import type {
  Classification,
  IncidentStatus,
  Severity,
} from "@/lib/types";

// ------------------------------------------------------------------
// Severity system — Critical=red-500, High=amber-500, Medium=yellow-400,
// Low=emerald-400, False Positive=slate-500
// ------------------------------------------------------------------

export type SeverityKey = Severity | "Info";

export const SEVERITY_STYLES: Record<
  string,
  { text: string; bg: string; border: string; dot: string; hex: string; label: string }
> = {
  Critical: {
    text: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/30",
    dot: "bg-red-500",
    hex: "#ef4444",
    label: "Critical",
  },
  High: {
    text: "text-amber-400",
    bg: "bg-amber-500/10",
    border: "border-amber-500/30",
    dot: "bg-amber-500",
    hex: "#f59e0b",
    label: "High",
  },
  Medium: {
    text: "text-yellow-300",
    bg: "bg-yellow-400/10",
    border: "border-yellow-400/30",
    dot: "bg-yellow-400",
    hex: "#facc15",
    label: "Medium",
  },
  Low: {
    text: "text-emerald-400",
    bg: "bg-emerald-400/10",
    border: "border-emerald-400/30",
    dot: "bg-emerald-400",
    hex: "#34d399",
    label: "Low",
  },
  "False Positive": {
    text: "text-slate-400",
    bg: "bg-slate-500/10",
    border: "border-slate-500/30",
    dot: "bg-slate-500",
    hex: "#64748b",
    label: "False Positive",
  },
  Info: {
    text: "text-slate-300",
    bg: "bg-slate-500/10",
    border: "border-slate-500/25",
    dot: "bg-slate-400",
    hex: "#94a3b8",
    label: "Info",
  },
};

export function severityStyle(sev: string | null | undefined) {
  if (!sev) return SEVERITY_STYLES["Info"];
  return SEVERITY_STYLES[sev] ?? SEVERITY_STYLES["Info"];
}

/** rawSeverity ("low" | "medium" | ...) → display severity key */
export function rawSeverityLabel(raw: string): SeverityKey {
  switch (raw.toLowerCase()) {
    case "critical":
      return "Critical";
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
    default:
      return "Info";
  }
}

/** Threat score (0-100) → hex color ramp for gauges/bars */
export function scoreHex(score: number): string {
  if (score >= 80) return SEVERITY_STYLES.Critical.hex;
  if (score >= 60) return SEVERITY_STYLES.High.hex;
  if (score >= 40) return SEVERITY_STYLES.Medium.hex;
  if (score >= 20) return SEVERITY_STYLES.Low.hex;
  return SEVERITY_STYLES["False Positive"].hex;
}

/** Threat score → text color class */
export function scoreTextClass(score: number): string {
  if (score >= 80) return "text-red-400";
  if (score >= 60) return "text-amber-400";
  if (score >= 40) return "text-yellow-300";
  if (score >= 20) return "text-emerald-400";
  return "text-slate-400";
}

// ------------------------------------------------------------------
// Classification & status styles
// ------------------------------------------------------------------

export const CLASSIFICATION_STYLES: Record<
  Classification,
  { chip: string; label: string }
> = {
  "Genuine Threat": {
    chip: "border-red-500/40 bg-red-500/10 text-red-300",
    label: "Genuine Threat",
  },
  "False Positive": {
    chip: "border-slate-500/40 bg-slate-500/10 text-slate-300",
    label: "False Positive",
  },
  "Under Review": {
    chip: "border-amber-500/40 bg-amber-500/10 text-amber-300",
    label: "Under Review",
  },
};

export const STATUS_STYLES: Record<
  IncidentStatus,
  { chip: string; dot: string; label: string }
> = {
  Open: {
    chip: "border-red-500/40 bg-red-500/10 text-red-300",
    dot: "bg-red-500",
    label: "Open",
  },
  Investigating: {
    chip: "border-amber-500/40 bg-amber-500/10 text-amber-300",
    dot: "bg-amber-500",
    label: "Investigating",
  },
  Contained: {
    chip: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
    dot: "bg-emerald-500",
    label: "Contained",
  },
  Resolved: {
    chip: "border-slate-500/40 bg-slate-500/10 text-slate-300",
    dot: "bg-slate-500",
    label: "Resolved",
  },
};

// ------------------------------------------------------------------
// Source icon mapping (machine source key → icon)
// ------------------------------------------------------------------

const SOURCE_ICONS: Record<string, LucideIcon> = {
  siem: Server,
  firewall: BrickWall,
  auth: Fingerprint,
  "file-server": Database,
  edr: Shield,
  "dns-sensor": Globe,
  ids: Radar,
  "threat-intel": Crosshair,
  waf: ScanSearch,
  scanner: ScanSearch,
  satellite: Satellite,
  "intel-report": FileText,
  email: Wifi,
  proxy: Activity,
  endpoint: Terminal,
};

export function sourceIcon(source: string): LucideIcon {
  return SOURCE_ICONS[source.toLowerCase()] ?? Activity;
}

// ------------------------------------------------------------------
// Formatting
// ------------------------------------------------------------------

/** "3 min ago" style relative time from an ISO timestamp */
export function timeAgo(iso: string): string {
  try {
    return formatDistanceToNowStrict(parseISO(iso), { addSuffix: true });
  } catch {
    return iso;
  }
}

/** HH:mm:ss in local time */
export function formatTime(iso: string): string {
  try {
    return format(parseISO(iso), "HH:mm:ss");
  } catch {
    return iso;
  }
}

/** "MMM d, HH:mm:ss" local */
export function formatDateTime(iso: string): string {
  try {
    return format(parseISO(iso), "MMM d, HH:mm:ss");
  } catch {
    return iso;
  }
}

/** Format bytes-ish numbers compactly: 1234 → "1,234" */
export function formatCount(n: number): string {
  return n.toLocaleString("en-US");
}

/**
 * Defensive narrowing for list endpoints: the backend may return a bare
 * array or an envelope like { alerts: [...] } / { incidents: [...] }.
 */
export function unwrapList<T>(data: unknown, key?: string): T[] {
  if (Array.isArray(data)) return data as T[];
  if (data && typeof data === "object" && key) {
    const maybe = (data as Record<string, unknown>)[key];
    if (Array.isArray(maybe)) return maybe as T[];
  }
  return [];
}
