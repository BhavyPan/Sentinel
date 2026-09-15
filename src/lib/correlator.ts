/**
 * SentinelAI correlator (spec §6).
 * Deterministic pair scoring + Union-Find transitive closure.
 * Updates incidents in one transaction; retains stable IDs and analyst history.
 */
import { analystActions, reviewedBluf } from "./analyst-verdict";
import { db } from "@/lib/db";
import { scoreIncident, isLargeTransfer, type ScorerAlert } from "./scorer";
import {
  CORRELATION_THRESHOLD,
  CORRELATION_WINDOW_MINUTES,
  isMaliciousDomain,
  isMaliciousHash,
  isMaliciousIp,
} from "./threat-intel";
import { refreshIntel } from "./watchlist";

export interface CorrelateStats {
  incidentsBefore: number;
  incidentsAfter: number;
  alertsGrouped: number;
  alertsUngrouped: number;
}

export interface CorrAlert extends ScorerAlert {
  id: string;
  rawSeverity: string;
  metadata: Record<string, unknown>;
}

export function parseMetadata(raw: string): Record<string, unknown> {
  try {
    const v = JSON.parse(raw) as unknown;
    return typeof v === "object" && v !== null ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function isFailedLogin(a: CorrAlert): boolean {
  return /brute|(?:fail.*(?:login|auth)|(?:login|auth).*fail)/.test(a.event);
}

function isSuccessLogin(a: CorrAlert): boolean {
  return a.event.includes("successful_login") || a.event.includes("login_success");
}

function maliciousIocValues(a: CorrAlert): Set<string> {
  const out = new Set<string>();
  if (a.ip && isMaliciousIp(a.ip)) out.add(`ip:${a.ip}`);
  const iocs = (a.metadata as { iocs?: { ips?: string[]; domains?: string[]; hashes?: string[] } }).iocs;
  for (const v of iocs?.ips ?? []) if (isMaliciousIp(v)) out.add(`ip:${v}`);
  for (const v of iocs?.domains ?? []) if (isMaliciousDomain(v)) out.add(`dom:${v}`);
  for (const v of iocs?.hashes ?? []) if (isMaliciousHash(v)) out.add(`hash:${v}`);
  return out;
}

/** Pair score per spec §6. Window: |timestamp diff| <= 30 minutes. Exported for the live simulator. */
export function pairScore(a: CorrAlert, b: CorrAlert): number {
  const diff = Math.abs(+a.timestamp - +b.timestamp);
  if (diff > CORRELATION_WINDOW_MINUTES * 60_000) return 0;

  let s = 0;
  if (a.user && b.user && a.user === b.user) s += 3;
  if (a.ip && b.ip && a.ip === b.ip) s += 3;
  if (a.device && b.device && a.device === b.device) s += 2;
  const related = Boolean((a.user && a.user === b.user) || (a.device && a.device === b.device) || (a.ip && a.ip === b.ip));
  if (related && isFailedLogin(a) && isSuccessLogin(b) && +a.timestamp <= +b.timestamp) s += 4;
  else if (related && isFailedLogin(b) && isSuccessLogin(a) && +b.timestamp <= +a.timestamp) s += 4;
  if (related && isSuccessLogin(a) && isLargeTransfer(b) && +a.timestamp <= +b.timestamp) s += 4;
  else if (related && isSuccessLogin(b) && isLargeTransfer(a) && +b.timestamp <= +a.timestamp) s += 4;
  const aIocs = maliciousIocValues(a);
  if (aIocs.size > 0 && [...maliciousIocValues(b)].some((v) => aIocs.has(v))) s += 5;
  if (a.event === b.event) s += 1;
  return s;
}

/** Union-Find with path compression */
class UnionFind {
  private parent: number[];
  constructor(n: number) {
    this.parent = Array.from({ length: n }, (_, i) => i);
  }
  find(i: number): number {
    while (this.parent[i] !== i) {
      this.parent[i] = this.parent[this.parent[i]];
      i = this.parent[i];
    }
    return i;
  }
  union(i: number, j: number): void {
    const ri = this.find(i);
    const rj = this.find(j);
    if (ri !== rj) this.parent[rj] = ri;
  }
}

/** Correlate atomically, retaining stable case IDs and analyst history. */
export async function runCorrelation(): Promise<CorrelateStats> {
  await refreshIntel();
  return db.$transaction(async (tx) => {
    const previous = await tx.incident.findMany({ include: { alerts: true, events: true } });
    const rows = await tx.alert.findMany({ orderBy: [{ timestamp: "asc" }, { id: "asc" }] });
    const alerts: CorrAlert[] = rows.map((r) => ({ ...r, metadata: parseMetadata(r.metadata) }));
    const uf = new UnionFind(alerts.length);
    for (let i = 0; i < alerts.length; i++) {
      for (let j = i + 1; j < alerts.length; j++) {
        if (+alerts[j].timestamp - +alerts[i].timestamp > CORRELATION_WINDOW_MINUTES * 60_000) break;
        if (pairScore(alerts[i], alerts[j]) >= CORRELATION_THRESHOLD) uf.union(i, j);
      }
    }
    const groups = new Map<number, CorrAlert[]>();
    alerts.forEach((a, i) => {
      const key = uf.find(i);
      groups.set(key, [...(groups.get(key) ?? []), a]);
    });
    const incidentGroups = [...groups.values()].filter((g) => g.length >= 2);
    let seq = Math.max(1000, ...previous.map((i) => Number(i.incidentId.replace("INC-", "")) || 1000));
    const claimed = new Set<string>();
    for (const group of incidentGroups) {
      const ids = new Set(group.map((a) => a.id));
      const parents = previous.filter((p) => !claimed.has(p.id) && p.alerts.some((a) => ids.has(a.id)))
        .sort((a, b) => b.alerts.filter((x) => ids.has(x.id)).length - a.alerts.filter((x) => ids.has(x.id)).length || a.incidentId.localeCompare(b.incidentId));
      const existing = parents[0];
      const result = scoreIncident(group);
      const unchanged = existing && parents.length === 1 && existing.alerts.length === ids.size && existing.alerts.every((a) => ids.has(a.id));
      const keepAnalysis = unchanged && existing.analyzed && existing.riskSignals === JSON.stringify(result.riskSignals);
      const feedback = parents.flatMap((p) => p.events).filter((e) => e.kind === "classification").sort((a,b) => +b.createdAt - +a.createdAt)[0];
      const classification = feedback ? previous.find((p) => p.id === feedback.incidentId)!.classification : result.classification;
      const severity = classification === "False Positive" ? "False Positive" : result.severity === "False Positive" ? "Low" : result.severity;
      const notes = parents.map((p) => p.explanation?.match(/(?:^|\n\n)\[[^\]\n]+\][\s\S]*/)?.[0]?.trim()).filter(Boolean);
      const data = {
        title: result.title, classification, severity,
        threatScore: result.threatScore, confidence: result.confidence,
        mitre: JSON.stringify(result.mitre),
        bluf: (feedback ? reviewedBluf(result.bluf, classification) : result.bluf).replace(/^SEVERITY:.*$/m, `SEVERITY: ${severity}`),
        explanation: [result.explanation, ...notes].join("\n\n"),
        evidence: JSON.stringify(result.evidence),
        recommendedActions: JSON.stringify(feedback ? analystActions(classification) : deterministicActions(classification, group)),
        riskSignals: JSON.stringify(result.riskSignals), analyzed: false,
      };
      const incident = existing
        ? keepAnalysis ? existing : await tx.incident.update({ where: { id: existing.id }, data })
        : await tx.incident.create({ data: { ...data, incidentId: `INC-${++seq}` } });
      claimed.add(incident.id);
      await tx.alert.updateMany({ where: { id: { in: [...ids] } }, data: { incidentId: incident.id } });
      for (const merged of parents.slice(1)) {
        // Only retire a case if its entire membership merged into this case.
        if (!merged.alerts.every((a) => ids.has(a.id))) continue;
        await tx.incidentEvent.updateMany({ where: { incidentId: merged.id }, data: { incidentId: incident.id } });
        await tx.incidentEvent.create({ data: { incidentId: incident.id, kind: "correlation", actor: "SentinelAI", detail: `Merged ${merged.incidentId} into ${incident.incidentId}; prior activity retained.` } });
        await tx.incident.delete({ where: { id: merged.id } });
        claimed.add(merged.id);
      }
      if (!keepAnalysis) await tx.incidentEvent.create({ data: {
        incidentId: incident.id, kind: existing ? "correlation" : "created", actor: "SentinelAI",
        detail: existing ? `Recomputed assessment from ${group.length} alerts; analyst status and notes retained.` : `Created from ${group.length} correlated alerts.`,
      } });
    }
    // Preserve any prior case that loses correlation instead of deleting analyst work.
    return { incidentsBefore: previous.length, incidentsAfter: await tx.incident.count(), alertsGrouped: await tx.alert.count({ where: { incidentId: { not: null } } }), alertsUngrouped: await tx.alert.count({ where: { incidentId: null } }) };
  }, { maxWait: 10000, timeout: 30000 });
}

/** Default recommended actions for a fresh deterministic incident */
export function deterministicActions(classification: string, group: CorrAlert[]): string[] {
  if (classification === "False Positive") {
    return [
      "Review and close as false positive",
      "Add a tuning rule to suppress similar benign alerts",
    ];
  }
  const primary = group[0];
  return [
    primary.ip ? `Investigate activity from ${primary.ip}` : "Investigate the correlated alert timeline",
    primary.user ? `Verify legitimacy of activity by ${primary.user}` : "Identify the accounts involved",
    "Run AI analysis for a full BLUF assessment",
  ];
}
