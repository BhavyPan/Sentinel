import { NextResponse } from "next/server";
import { getDashboardSummary } from "@/lib/summary";

export const dynamic = "force-dynamic";

/** GET /api/dashboard/summary — KPI counts, charts data, top incidents */
export async function GET() {
  try {
    const summary = await getDashboardSummary();
    return NextResponse.json(summary);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to build summary";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
