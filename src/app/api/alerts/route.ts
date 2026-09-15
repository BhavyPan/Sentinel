import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { toAlertDTO } from "@/lib/summary";

export const dynamic = "force-dynamic";

/** GET /api/alerts — list normalized alerts with filters */
export async function GET(req: Request) {
  try {
    const { searchParams } = new URL(req.url);
    const source = searchParams.get("source") || undefined;
    const severity = searchParams.get("severity") || undefined;
    const correlated = searchParams.get("correlated");
    const ack = searchParams.get("ack"); // "ack" | "unack" | undefined
    const search = (searchParams.get("search") || "").trim().toLowerCase();
    const limitRaw = parseInt(searchParams.get("limit") || "200", 10);
    const limit = Math.max(1, Math.min(1000, Number.isFinite(limitRaw) ? limitRaw : 200));

    const offset = Math.max(0, Number.parseInt(searchParams.get("offset") || "0", 10) || 0);
    const rows = await db.alert.findMany({
      where: {
        ...(source ? { source } : {}),
        ...(severity ? { rawSeverity: severity } : {}),
        ...(correlated === "true" ? { incidentId: { not: null } } : {}),
        ...(correlated === "false" ? { incidentId: null } : {}),
        ...(ack === "ack" ? { acknowledged: true } : {}),
        ...(ack === "unack" ? { acknowledged: false } : {}),
      },
      orderBy: [{ timestamp: "desc" }, { id: "asc" }],
    });

    const filtered = search
      ? rows.filter((a) =>
          [a.alertId, a.description, a.user, a.device, a.ip, a.event, a.source]
            .filter(Boolean)
            .some((v) => String(v).toLowerCase().includes(search))
        )
      : rows;

    return NextResponse.json({ alerts: filtered.slice(offset, offset + limit).map(toAlertDTO), total: filtered.length, offset, limit, hasMore: offset + limit < filtered.length });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to list alerts";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
