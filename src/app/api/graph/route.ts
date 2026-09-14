import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { MALICIOUS_IPS, isInternalIp } from "@/lib/threat-intel";
import type {
  Classification,
  GraphData,
  GraphEntityType,
  GraphLink,
  GraphNode,
  Severity,
} from "@/lib/types";

export const dynamic = "force-dynamic";

const SEVERITY_RANK: Record<string, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  "False Positive": 4,
  Info: 5,
};

function worstSeverity(a: string, b: string): string {
  return (SEVERITY_RANK[a] ?? 9) <= (SEVERITY_RANK[b] ?? 9) ? a : b;
}

type EntityAcc = {
  type: GraphEntityType;
  value: string;
  alertCount: number;
  incidentIds: Set<string>;
  incidentSeverities: Map<string, string>; // incidentId -> severity
};

/**
 * GET /api/graph
 * Entity ↔ incident relationship graph for the Threat Graph view.
 * Nodes: correlated incidents (kind=incident) + user/device/ip entities (kind=entity).
 * Links: entity → incident when the entity appears in ≥1 alert of that incident.
 */
export async function GET() {
  const [incidents, allAlerts] = await Promise.all([
    db.incident.findMany({ include: { alerts: true } }),
    db.alert.findMany(),
  ]);

  const nodes: GraphNode[] = [];
  const links: GraphLink[] = [];
  const entities = new Map<string, EntityAcc>();
  const sevByIncidentId = new Map<string, string>(
    incidents.map((i) => [i.id, i.severity])
  );

  // --- entity accumulator (counts alerts, incl. ungrouped ones) ---
  const trackEntities = (
    alert: { user: string | null; device: string | null; ip: string | null },
    incidentId?: string,
    severity?: string
  ) => {
    const entries: [GraphEntityType, string | null][] = [
      ["user", alert.user],
      ["device", alert.device],
      ["ip", alert.ip],
    ];
    for (const [type, value] of entries) {
      if (!value || !value.trim()) continue;
      const key = `${type}:${value}`;
      let acc = entities.get(key);
      if (!acc) {
        acc = { type, value, alertCount: 0, incidentIds: new Set(), incidentSeverities: new Map() };
        entities.set(key, acc);
      }
      acc.alertCount++;
      if (incidentId && severity) {
        acc.incidentIds.add(incidentId);
        const prev = acc.incidentSeverities.get(incidentId);
        acc.incidentSeverities.set(incidentId, prev ? worstSeverity(prev, severity) : severity);
      }
    }
  };

  for (const a of allAlerts) {
    const inc = a.incidentId ? sevByIncidentId.get(a.incidentId) : undefined;
    trackEntities(a, a.incidentId ?? undefined, inc);
  }

  // --- incident nodes + links ---
  for (const inc of incidents) {
    const severity = inc.severity as Severity;
    nodes.push({
      id: `inc:${inc.id}`,
      kind: "incident",
      label: inc.incidentId,
      sublabel: `${inc.title} · score ${inc.threatScore}`,
      severity,
      weight: inc.threatScore,
      alertCount: inc.alerts.length,
      incidentDbIds: [inc.id],
      classification: inc.classification as Classification,
    });

    const entLinkStats = new Map<string, { count: number; samples: string[] }>();
    for (const a of inc.alerts) {
      for (const [type, value] of [
        ["user", a.user],
        ["device", a.device],
        ["ip", a.ip],
      ] as [GraphEntityType, string | null][]) {
        if (!value || !value.trim()) continue;
        const key = `${type}:${value}`;
        const st = entLinkStats.get(key) ?? { count: 0, samples: [] };
        st.count += 1;
        if (st.samples.length < 3) st.samples.push(a.alertId);
        entLinkStats.set(key, st);
      }
    }
    for (const [key, stats] of entLinkStats) {
      links.push({
        source: key,
        target: `inc:${inc.id}`,
        severity,
        incidentDbId: inc.id,
        alertCount: stats.count,
        sampleAlertIds: [...stats.samples],
      });
    }
  }

  // --- entity nodes ---
  for (const [key, acc] of entities) {
    let severity: string = "Info";
    for (const sev of acc.incidentSeverities.values()) severity = worstSeverity(severity, sev);
    const incidentDbIds = [...acc.incidentIds];
    const isIp = acc.type === "ip";
    nodes.push({
      id: key,
      kind: "entity",
      entityType: acc.type,
      label: acc.value,
      sublabel:
        incidentDbIds.length > 0
          ? `${incidentDbIds.length} incident${incidentDbIds.length === 1 ? "" : "s"} · ${acc.alertCount} alert${acc.alertCount === 1 ? "" : "s"}`
          : `${acc.alertCount} alert${acc.alertCount === 1 ? "" : "s"} · unlinked`,
      severity: (severity as Severity | "Info") ?? "Info",
      weight: incidentDbIds.length,
      alertCount: acc.alertCount,
      incidentDbIds,
      ...(isIp ? { internal: isInternalIp(acc.value), malicious: MALICIOUS_IPS.includes(acc.value) } : {}),
    });
  }

  const data: GraphData = {
    nodes,
    links,
    stats: {
      entityCount: entities.size,
      incidentCount: incidents.length,
      linkCount: links.length,
      unlinkedAlerts: allAlerts.filter((a) => a.incidentId == null).length,
    },
    generatedAt: new Date().toISOString(),
  };

  return NextResponse.json(data, {
    headers: { "Cache-Control": "no-store" },
  });
}
