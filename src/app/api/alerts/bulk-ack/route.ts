import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { toAlertDTO } from "@/lib/summary";
import type { BulkAckPayload } from "@/lib/types";

export const dynamic = "force-dynamic";

const MAX_IDS = 500;

/** POST /api/alerts/bulk-ack — acknowledge/clear a batch of alerts in one call */
export async function POST(req: Request) {
  try {
    const body = (await req.json()) as BulkAckPayload | null;
    if (
      !body ||
      !Array.isArray(body.ids) ||
      body.ids.length === 0 ||
      typeof body.acknowledged !== "boolean"
    ) {
      return NextResponse.json(
        { error: "Invalid request body — expected { ids: string[], acknowledged: boolean }" },
        { status: 400 }
      );
    }

    const ids = body.ids.map((id) => String(id).trim()).filter(Boolean).slice(0, MAX_IDS);
    if (ids.length === 0) {
      return NextResponse.json({ error: "No valid alert ids provided" }, { status: 400 });
    }

    // ids may be db cuids or business alertIds — resolve both
    const found = await db.alert.findMany({
      where: {
        OR: ids.flatMap((id) => [{ id }, { alertId: id }]),
      },
      select: { id: true, alertId: true },
    });

    if (found.length === 0) {
      return NextResponse.json(
        { error: "No matching alerts found for the supplied ids" },
        { status: 404 }
      );
    }

    const resolvedIds = found.map((a) => a.id);

    await db.alert.updateMany({
      where: { id: { in: resolvedIds } },
      data: {
        acknowledged: body.acknowledged,
        acknowledgedAt: body.acknowledged ? new Date() : null,
      },
    });

    const alerts = await db.alert.findMany({
      where: { id: { in: resolvedIds } },
      orderBy: { timestamp: "desc" },
    });

    const preview =
      alerts.length <= 3
        ? alerts.map((a) => a.alertId).join(", ")
        : `${alerts.slice(0, 3).map((a) => a.alertId).join(", ")} +${alerts.length - 3} more`;

    return NextResponse.json({
      updated: resolvedIds.length,
      requested: ids.length,
      alerts: alerts.map(toAlertDTO),
      message: body.acknowledged
        ? `${resolvedIds.length} alert${resolvedIds.length === 1 ? "" : "s"} acknowledged (${preview})`
        : `Acknowledgement cleared for ${resolvedIds.length} alert${resolvedIds.length === 1 ? "" : "s"}`,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Bulk acknowledgement failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
