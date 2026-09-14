import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { runCorrelation } from "@/lib/correlator";
import { getDashboardSummary } from "@/lib/summary";

export const dynamic = "force-dynamic";
export const maxDuration = 120;

/** POST /api/incidents/correlate — rebuild all incidents from all alerts */
export async function POST() {
  try {
    const stats = await runCorrelation();
    const summary = await getDashboardSummary();
    return NextResponse.json({
      ...stats,
      summary,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Correlation failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
