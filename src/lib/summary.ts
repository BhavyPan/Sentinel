/**
 * Shared serializers + dashboard summary helper.
 * Used by the dashboard route, incidents routes, correlate route and copilot route.
 */
import { db } from "@/lib/db";
import type { Alert, Incident, IncidentEvent } from "@prisma/client";
import type {
  AlertDTO,
  Classification,
  DashboardSummary,
  IncidentDTO,
  IncidentDetailDTO,
  IncidentEventDTO,
  IncidentStatus,
  MitreTechnique,
  RiskSignal,
  Severity,
} from "./types";

// ---------------------------------------------------------------- serializers

export function parseJsonSafe<T>(raw: string | null | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    const v = JSON.parse(raw) as unknown;
    return v as T;
  } catch {
    return fallback;
  }
}

export function toAlertDTO(a: Alert): AlertDTO {
  return {
    id: a.id,
    alertId: a.alertId,
    source: a.source,
    sourceLabel: a.sourceLabel || a.source,
    timestamp: a.timestamp.toISOString(),
    user: a.user,
    device: a.device,
    ip: a.ip,
    event: a.event,
    description: a.description,
    rawSeverity: a.rawSeverity,
    rawFormat: a.rawFormat,
    metadata: parseJsonSafe<Record<string, unknown>>(a.metadata, {}),
    incidentId: a.incidentId,
    acknowledged: a.acknowledged,
    correlated: a.incidentId != null,
  };
}

export interface IncidentWithAlerts extends Incident {
  alerts: Alert[];
  events?: IncidentEvent[];
}

export function toIncidentDTO(i: IncidentWithAlerts): IncidentDTO {
  const sources = [...new Set(i.alerts.map((a) => a.sourceLabel || a.source))];
  return {
    id: i.id,
    incidentId: i.incidentId,
    title: i.title,
    classification: i.classification as Classification,
    severity: i.severity as Severity,
    threatScore: i.threatScore,
    confidence: i.confidence,
    mitre: parseJsonSafe<MitreTechnique[]>(i.mitre, []),
    bluf: i.bluf,
    explanation: i.explanation,
    evidence: parseJsonSafe<string[]>(i.evidence, []),
    recommendedActions: parseJsonSafe<string[]>(i.recommendedActions, []),
    status: i.status as IncidentStatus,
    analyzed: i.analyzed,
    riskSignals: parseJsonSafe<RiskSignal[]>(i.riskSignals, []),
    alertCount: i.alerts.length,
    sources,
    createdAt: i.createdAt.toISOString(),
    updatedAt: i.updatedAt.toISOString(),
  };
}

/** Detail = list DTO + full related alerts sorted timestamp ascending + case activity */
export function toIncidentDetailDTO(i: IncidentWithAlerts): IncidentDetailDTO {
  return {
    ...toIncidentDTO(i),
    alerts: [...i.alerts]
      .sort((a, b) => +a.timestamp - +b.timestamp)
      .map(toAlertDTO),
    events: (i.events ?? []).slice(0, 15).map((e) => ({
      id: e.id,
      kind: e.kind as IncidentEventDTO["kind"],
      actor: e.actor,
      detail: e.detail,
      createdAt: e.createdAt.toISOString(),
    })),
  };
}

// ---------------------------------------------------------------- ranking

const SEVERITY_RANK: Record<string, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  "False Positive": 4,
};

export function rankIncidents<T extends { severity: string; threatScore: number; updatedAt: Date | string }>(
  incidents: T[]
): T[] {
  return [...incidents].sort((a, b) => {
    const ra = SEVERITY_RANK[a.severity] ?? 9;
    const rb = SEVERITY_RANK[b.severity] ?? 9;
    if (ra !== rb) return ra - rb;
    if (b.threatScore !== a.threatScore) return b.threatScore - a.threatScore;
    return +new Date(b.updatedAt) - +new Date(a.updatedAt);
  });
}

// ---------------------------------------------------------------- summary

function capitalizeSeverity(raw: string): string {
  const s = (raw || "").trim().toLowerCase();
  if (!s) return "Info";
  return s.charAt(0).toUpperCase() + s.slice(1);
}

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info", "False Positive"];

export async function getDashboardSummary(): Promise<DashboardSummary> {
  const [alerts, incidents] = await Promise.all([
    db.alert.findMany({ include: { incident: true }, orderBy: { timestamp: "desc" } }),
    db.incident.findMany({ include: { alerts: true } }),
  ]);

  const correlatedAlerts = alerts.filter((a) => a.incidentId != null).length;
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    falsePositive: 0,
    genuineThreats: 0,
    analyzed: 0,
    open: 0,
    unacknowledgedAlerts: 0,
  };
  counts.unacknowledgedAlerts = alerts.filter((a) => !a.acknowledged).length;
  for (const inc of incidents) {
    const sev = inc.severity as Severity;
    if (sev === "Critical") counts.critical++;
    else if (sev === "High") counts.high++;
    else if (sev === "Medium") counts.medium++;
    else if (sev === "Low") counts.low++;
    else if (sev === "False Positive") counts.falsePositive++;
    if (inc.classification === "Genuine Threat") counts.genuineThreats++;
    if (inc.analyzed) counts.analyzed++;
    if (inc.status === "Open") counts.open++;
  }

  // alertsBySeverity: incident severity when correlated, else capitalized rawSeverity
  const sevCount = new Map<string, number>();
  for (const a of alerts) {
    const sev = a.incident ? a.incident.severity : capitalizeSeverity(a.rawSeverity);
    sevCount.set(sev, (sevCount.get(sev) ?? 0) + 1);
  }
  const alertsBySeverity = [...sevCount.entries()]
    .map(([severity, count]) => ({ severity, count }))
    .sort((a, b) => {
      const ia = SEVERITY_ORDER.indexOf(a.severity);
      const ib = SEVERITY_ORDER.indexOf(b.severity);
      if (ia !== -1 && ib !== -1) return ia - ib;
      if (ia !== -1) return -1;
      if (ib !== -1) return 1;
      return a.severity.localeCompare(b.severity);
    });

  const srcCount = new Map<string, { sourceLabel: string; count: number }>();
  for (const a of alerts) {
    const prev = srcCount.get(a.source);
    srcCount.set(a.source, { sourceLabel: a.sourceLabel || a.source, count: (prev?.count ?? 0) + 1 });
  }
  const alertsBySource = [...srcCount.entries()]
    .map(([source, v]) => ({ source, sourceLabel: v.sourceLabel, count: v.count }))
    .sort((a, b) => b.count - a.count || a.source.localeCompare(b.source));

  // alertsByHour: last 12 distinct hours present in alert timestamps ("HH:00", UTC)
  const hourKeys = new Map<string, { label: string; count: number }>();
  for (const a of alerts) {
    const d = a.timestamp;
    const key = `${d.getUTCFullYear()}-${d.getUTCMonth()}-${d.getUTCDate()}-${d.getUTCHours()}`;
    const prev = hourKeys.get(key);
    hourKeys.set(key, {
      label: `${String(d.getUTCHours()).padStart(2, "0")}:00`,
      count: (prev?.count ?? 0) + 1,
    });
  }
  const alertsByHour = [...hourKeys.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : 1))
    .slice(-12)
    .map(([, v]) => ({ hour: v.label, count: v.count }));

  const ranked = rankIncidents(incidents.map(toIncidentDTO));
  const newest = alerts.reduce<Date | null>(
    (acc, a) => (acc === null || a.timestamp > acc ? a.timestamp : acc),
    null
  );

  return {
    totalAlerts: alerts.length,
    correlatedAlerts,
    uncorrelatedAlerts: alerts.length - correlatedAlerts,
    totalIncidents: incidents.length,
    counts,
    alertsBySeverity,
    alertsBySource,
    alertsByHour,
    topIncidents: ranked.slice(0, 5),
    lastUpdated: newest ? newest.toISOString() : null,
  };
}
