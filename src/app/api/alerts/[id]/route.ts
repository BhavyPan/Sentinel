import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { toAlertDTO } from "@/lib/summary";
import type { AlertUpdatePayload } from "@/lib/types";

export const dynamic = "force-dynamic";

/** PATCH /api/alerts/[id] — triage acknowledgement (accepts db cuid or alertId) */
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const body = (await req.json()) as AlertUpdatePayload | null;
    if (!body || typeof body.acknowledged !== "boolean") {
      return NextResponse.json(
        { error: "Invalid request body — expected { acknowledged: boolean }" },
        { status: 400 }
      );
    }

    const existing = await db.alert.findFirst({
      where: { OR: [{ id }, { alertId: id }] },
      select: { id: true },
    });
    if (!existing) {
      return NextResponse.json({ error: `Alert ${id} not found` }, { status: 404 });
    }

    const alert = await db.alert.update({
      where: { id: existing.id },
      data: {
        acknowledged: body.acknowledged,
        acknowledgedAt: body.acknowledged ? new Date() : null,
      },
    });

    return NextResponse.json({
      alert: toAlertDTO(alert),
      message: body.acknowledged
        ? `Alert ${alert.alertId} acknowledged`
        : `Acknowledgement cleared for ${alert.alertId}`,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to update alert";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
