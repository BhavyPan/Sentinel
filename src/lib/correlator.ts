/**
 * SentinelAI correlator (spec §6).
 * Deterministic pair scoring + Union-Find transitive closure.
 * Rebuilds ALL incidents from ALL alerts (documented MVP behavior:
 * re-correlation resets analysis state).
 */
import { db } from "@/lib/db";
import { scoreIncident, type ScorerAlert } from "./scorer";
import {
  CORRELATION_THRESHOLD,
  CORRELATION_WINDOW_MINUTES,
  MALICIOUS_DOMAINS,
  MALICIOUS_HASHES,
  MALICIOUS_IPS,
} from "./threat-intel";

export interface CorrelateStats {
  incidentsBefore: number;
  incidentsAfter: number;
  alertsGrouped: number;
  alertsUngrouped: number;
}

interface CorrAlert extends ScorerAlert {
  id: string;
  rawSeverity: string;
  metadata: Record<string, unknown>;
}

function parseMetadata(raw: string): Record<string, unknown> {
  try {
    const v = JSON.parse(raw) as unknown;
    return typeof v === "object" && v !== null ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function isFailedLogin(a: CorrAlert): boolean {
  return /fail|brute/.test(a.event);
}

function isSuccessLogin(a: CorrAlert): boolean {
  return a.event.includes("successful_login") || a.event.includes("login_success");
}

function isLargeTransfer(a: CorrAlert): boolean {
  return (
    /download|transfer|exfil|upload/.test(a.event) ||
    /(\d+(?:\.\d+)?)\s*gb/i.test(a.description) ||
    /large data|mass file|exfiltration/i.test(a.description)
  );
}

function maliciousIocValues(a: CorrAlert): Set<string> {
  const out = new Set<string>();
  const iocs = (a.metadata as { iocs?: { ips?: string[]; domains?: string[]; hashes?: string[] } }).iocs;
  for (const v of iocs?.ips ?? []) if (MALICIOUS_IPS.includes(v)) out.add(`ip:${v}`);
  for (const v of iocs?.domains ?? []) if (MALICIOUS_DOMAINS.includes(v)) out.add(`dom:${v}`);
  for (const v of iocs?.hashes ?? []) if (MALICIOUS_HASHES.includes(v)) out.add(`hash:${v}`);
  return out;
}

/** Pair score per spec §6. Window: |timestamp diff| <= 30 minutes. */
function pairScore(a: CorrAlert, b: CorrAlert): number {
  const diff = Math.abs(+a.timestamp - +b.timestamp);
  if (diff > CORRELATION_WINDOW_MINUTES * 60_000) return 0;

  let s = 0;
  if (a.user && b.user && a.user === b.user) s += 3;
  if (a.ip && b.ip && a.ip === b.ip) s += 3;
  if (a.device && b.device && a.device === b.device) s += 2;
  if (isFailedLogin(a) && isSuccessLogin(b) && +a.timestamp <= +b.timestamp) s += 4;
  else if (isFailedLogin(b) && isSuccessLogin(a) && +b.timestamp <= +a.timestamp) s += 4;
  if (isSuccessLogin(a) && isLargeTransfer(b) && +a.timestamp <= +b.timestamp) s += 4;
  else if (isSuccessLogin(b) && isLargeTransfer(a) && +b.timestamp <= +a.timestamp) s += 4;
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

/**
 * Rebuild every incident from every alert currently in the DB.
 * All incidents are deleted first (alerts detached) — re-correlation resets
 * LLM analysis and analyst notes (documented MVP behavior).
 */
export async function runCorrelation(): Promise<CorrelateStats> {
  const incidentsBefore = await db.incident.count();

  await db.alert.updateMany({ data: { incidentId: null } });
  await db.incident.deleteMany({});

  const rows = await db.alert.findMany({ orderBy: { timestamp: "asc" } });
  const alerts: CorrAlert[] = rows.map((r) => ({
    id: r.id,
    alertId: r.alertId,
    source: r.source,
    sourceLabel: r.sourceLabel,
    timestamp: r.timestamp,
    user: r.user,
    device: r.device,
    ip: r.ip,
    event: r.event,
    description: r.description,
    rawSeverity: r.rawSeverity,
    metadata: parseMetadata(r.metadata),
  }));

  // --- pairwise linking ---
  const uf = new UnionFind(alerts.length);
  for (let i = 0; i < alerts.length; i++) {
    for (let j = i + 1; j < alerts.length; j++) {
      if (pairScore(alerts[i], alerts[j]) >= CORRELATION_THRESHOLD) {
        uf.union(i, j);
      }
    }
  }

  // --- collect groups (transitive closure), size >= 2 become incidents ---
  const groups = new Map<number, number[]>();
  for (let i = 0; i < alerts.length; i++) {
    const root = uf.find(i);
    const list = groups.get(root) ?? [];
    list.push(i);
    groups.set(root, list);
  }
  const incidentGroups = [...groups.values()]
    .filter((idxs) => idxs.length >= 2)
    .map((idxs) => idxs.map((i) => alerts[i]).sort((a, b) => +a.timestamp - +b.timestamp))
    .sort((g1, g2) => +g1[0].timestamp - +g2[0].timestamp);

  // --- persist incidents + attach alerts (renumber from INC-1001) ---
  let seq = 1001;
  let grouped = 0;
  for (const group of incidentGroups) {
    const result = scoreIncident(group);
    const incidentId = `INC-${seq}`;
    const ids = group.map((a) => a.id);
    await db.$transaction(async (tx) => {
      const created = await tx.incident.create({
        data: {
          incidentId,
          title: result.title,
          classification: result.classification,
          severity: result.severity,
          threatScore: result.threatScore,
          confidence: result.confidence,
          mitre: JSON.stringify(result.mitre),
          bluf: result.bluf,
          explanation: null,
          evidence: JSON.stringify(result.evidence),
          recommendedActions: JSON.stringify(deterministicActions(result.classification, group)),
          status: "Open",
          analyzed: false,
          riskSignals: JSON.stringify(result.riskSignals),
        },
      });
      await tx.alert.updateMany({
        where: { id: { in: ids } },
        data: { incidentId: created.id },
      });
    });
    grouped += group.length;
    seq++;
  }

  return {
    incidentsBefore,
    incidentsAfter: incidentGroups.length,
    alertsGrouped: grouped,
    alertsUngrouped: alerts.length - grouped,
  };
}

/** Default recommended actions for a fresh deterministic incident */
function deterministicActions(classification: string, group: CorrAlert[]): string[] {
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
