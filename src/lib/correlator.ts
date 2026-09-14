/**
 * SentinelAI correlator (spec §6).
 * Deterministic pair scoring + Union-Find transitive closure.
 * Rebuilds ALL incidents from ALL alerts. When a rebuilt incident group has
 * exactly the same alert membership as a pre-existing incident, the analyst
 * state (analyzed flag, BLUF, explanation, status, classification) is carried
 * over — re-correlation no longer destroys analyst/LLM work.
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

/** Pair score per spec §6. Window: |timestamp diff| <= 30 minutes. Exported for the live simulator. */
export function pairScore(a: CorrAlert, b: CorrAlert): number {
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
 * Alert sets that exactly match a pre-existing incident carry over their
 * analyst state (analyzed / BLUF / explanation / status / classification);
 * groups that changed recompute from scratch.
 */
export async function runCorrelation(): Promise<CorrelateStats> {
  const incidentsBefore = await db.incident.count();

  // --- snapshot analyst/LLM state keyed by each incident's alert-id set ---
  const [prevIncidents, prevAlertLinks] = await Promise.all([
    db.incident.findMany({
      select: {
        id: true,
        analyzed: true,
        bluf: true,
        explanation: true,
        status: true,
        classification: true,
      },
    }),
    db.alert.findMany({
      where: { incidentId: { not: null } },
      select: { incidentId: true, id: true },
    }),
  ]);
  const prevById = new Map(prevIncidents.map((i) => [i.id, i]));
  const alertIdsByIncident = new Map<string, string[]>();
  for (const a of prevAlertLinks) {
    if (!a.incidentId) continue;
    const list = alertIdsByIncident.get(a.incidentId);
    if (list) list.push(a.id);
    else alertIdsByIncident.set(a.incidentId, [a.id]);
  }
  const carriedBySet = new Map<
    string,
    { analyzed: boolean; bluf: string | null; explanation: string | null; status: string; classification: string }
  >();
  for (const [incidentDbId, ids] of alertIdsByIncident) {
    const detail = prevById.get(incidentDbId);
    if (!detail) continue;
    carriedBySet.set(
      [...ids].sort().join("|"),
      {
        analyzed: detail.analyzed,
        bluf: detail.bluf,
        explanation: detail.explanation,
        status: detail.status,
        classification: detail.classification,
      }
    );
  }

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
  let preserved = 0;
  for (const group of incidentGroups) {
    const result = scoreIncident(group);
    const incidentId = `INC-${seq}`;
    const ids = group.map((a) => a.id);
    const carried = carriedBySet.get([...ids].sort().join("|"));
    if (carried) preserved++;
    await db.$transaction(async (tx) => {
      const created = await tx.incident.create({
        data: {
          incidentId,
          title: result.title,
          classification: carried?.classification ?? result.classification,
          severity: result.severity,
          threatScore: result.threatScore,
          confidence: result.confidence,
          mitre: JSON.stringify(result.mitre),
          bluf: carried?.bluf ?? result.bluf,
          explanation: carried?.explanation ?? null,
          evidence: JSON.stringify(result.evidence),
          recommendedActions: JSON.stringify(deterministicActions(carried?.classification ?? result.classification, group)),
          status: carried?.status ?? "Open",
          analyzed: carried?.analyzed ?? false,
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

  if (preserved > 0) {
    console.log(`[correlator] preserved analyst state for ${preserved} unchanged incident group(s)`);
  }

  return {
    incidentsBefore,
    incidentsAfter: incidentGroups.length,
    alertsGrouped: grouped,
    alertsUngrouped: alerts.length - grouped,
  };
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
