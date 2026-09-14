import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { parseAndNormalize, type RequestedFormat } from "@/lib/normalizer";
import { toAlertDTO } from "@/lib/summary";
import type { ImportPayload } from "@/lib/types";
import type { Alert } from "@prisma/client";

export const dynamic = "force-dynamic";

/** POST /api/alerts/import — normalize + insert a raw feed (no auto-correlation) */
export async function POST(req: Request) {
  try {
    const body = (await req.json()) as ImportPayload | null;
    const raw = typeof body?.raw === "string" ? body.raw : "";
    const format: RequestedFormat =
      body?.format === "json" || body?.format === "csv" || body?.format === "text"
        ? body.format
        : "auto";

    if (!raw.trim()) {
      return NextResponse.json({ error: "Missing 'raw' payload" }, { status: 400 });
    }

    let normalized;
    try {
      normalized = parseAndNormalize(raw, format);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to parse payload";
      return NextResponse.json(
        { error: `Normalization failed: ${message}`, imported: 0, failed: 0, alerts: [] },
        { status: 400 }
      );
    }

    const inserted: Alert[] = [];
    let failed = 0;
    for (const item of normalized) {
      try {
        const row = await db.alert.create({
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
        inserted.push(row);
      } catch {
        failed++; // duplicate alertId or constraint violation
      }
    }

    return NextResponse.json({
      imported: inserted.length,
      failed,
      alerts: inserted.map(toAlertDTO),
      message:
        inserted.length > 0
          ? `Imported ${inserted.length} alert(s)${failed ? `, skipped ${failed}` : ""}. Run correlation to group them.`
          : "No alerts imported.",
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Import failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
