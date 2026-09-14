import { NextResponse } from "next/server";
import { simulateOneAlert } from "@/lib/simulator";
import { getDashboardSummary } from "@/lib/summary";

export const dynamic = "force-dynamic";

/**
 * POST /api/alerts/simulate — live threat simulation tick (spec §15).
 * Generates ONE believable alert, inserts it through the real normalizer,
 * correlates it INCREMENTALLY (never wipes existing incidents / AI analysis),
 * and returns the outcome + a fresh dashboard summary.
 */
export async function POST() {
  try {
    const result = await simulateOneAlert();
    const summary = await getDashboardSummary();
    return NextResponse.json({ ...result, summary });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Simulation failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
