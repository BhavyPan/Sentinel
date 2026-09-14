import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { rankIncidents, toIncidentDTO } from "@/lib/summary";

export const dynamic = "force-dynamic";

/** GET /api/incidents — ranked incident list (severity, then score, then recency) */
export async function GET() {
  try {
    const rows = await db.incident.findMany({ include: { alerts: true } });
    const incidents = rankIncidents(rows.map(toIncidentDTO));
    return NextResponse.json({ incidents });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to list incidents";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
