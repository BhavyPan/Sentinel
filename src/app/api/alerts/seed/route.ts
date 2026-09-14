import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { parseAndNormalize } from "@/lib/normalizer";
import { runCorrelation } from "@/lib/correlator";
import { buildDemoFeeds } from "@/lib/seed-data";

export const dynamic = "force-dynamic";
export const maxDuration = 120;

/** POST /api/alerts/seed — full demo reset: wipe, import all 5 feeds, correlate */
export async function POST() {
  try {
    const existing = await db.alert.count();
    if (existing >= 5) {
      // Full demo reset: chat history + incidents + alerts
      await db.chatMessage.deleteMany({});
      await db.alert.updateMany({ data: { incidentId: null } });
      await db.incident.deleteMany({});
      await db.alert.deleteMany({});
    }

    const feeds = buildDemoFeeds();
    const chunks = [
      feeds.siemJson,
      feeds.edrJson,
      feeds.sensorCsv,
      feeds.satelliteText,
      feeds.intelText,
    ];

    let seeded = 0;
    let failed = 0;
    for (const chunk of chunks) {
      let normalized;
      try {
        normalized = parseAndNormalize(chunk, "auto");
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error("[seed] chunk failed:", message);
        failed++;
        continue;
      }
      for (const item of normalized) {
        try {
          await db.alert.create({
            data: {
              alertId: item.alertId,
              source: item.source,
              sourceLabel: item.sourceLabel,
              timestamp: item.timestamp,
              user: item.user ?? null,
              device: item.device ?? null,
              ip: item.ip ?? null,
              event: item.event,
              description: item.description,
              rawSeverity: item.rawSeverity,
              rawFormat: item.rawFormat,
              metadata: JSON.stringify(item.metadata),
            },
          });
          seeded++;
        } catch {
          failed++;
        }
      }
    }

    const stats = await runCorrelation();

    return NextResponse.json({
      seeded,
      correlated: stats.alertsGrouped,
      incidents: stats.incidentsAfter,
      message: `Seeded ${seeded} alert(s) from 5 demo feeds (${failed} failed). Correlated into ${stats.incidentsAfter} incident(s).`,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Seed failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
