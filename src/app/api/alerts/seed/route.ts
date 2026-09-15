import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { parseAndNormalize } from "@/lib/normalizer";
import { runCorrelation } from "@/lib/correlator";
import { buildDemoFeeds } from "@/lib/seed-data";

export const dynamic = "force-dynamic";
export const maxDuration = 120;

/** Add the demo once; loading a demo never erases imported alerts or analyst work. */
export async function POST() {
  try {
    const existingCount = await db.alert.count();
    if (existingCount > 0) {
      const stats = await runCorrelation();
      return NextResponse.json({
        seeded: 0,
        correlated: stats.alertsGrouped,
        incidents: stats.incidentsAfter,
        message: `Dataset already contains ${existingCount} alerts. Existing records were retained.`,
      });
    }
    const feeds = buildDemoFeeds();
    const normalized = Object.values(feeds).flatMap((raw) => parseAndNormalize(raw));
    const seeded = await db.$transaction(async (tx) => {
      let count = 0;
      for (const item of normalized) {
        if (await tx.alert.findUnique({ where: { alertId: item.alertId } })) continue;
        await tx.alert.create({ data: { ...item, metadata: JSON.stringify(item.metadata) } });
        count++;
      }
      return count;
    });
    const stats = await runCorrelation();
    return NextResponse.json({ seeded, correlated: stats.alertsGrouped, incidents: stats.incidentsAfter, message: `Loaded ${seeded} alerts from five feed formats into ${stats.incidentsAfter} incidents.` });
  } catch (err) {
    return NextResponse.json({ error: err instanceof Error ? err.message : "Demo import failed" }, { status: 500 });
  }
}
