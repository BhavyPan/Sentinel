import { Prisma } from "@prisma/client";
import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { normalizeBatch, type RequestedFormat } from "@/lib/normalizer";
import { toAlertDTO } from "@/lib/summary";
import type { ImportPayload } from "@/lib/types";
import type { Alert } from "@prisma/client";

export const dynamic = "force-dynamic";

/** POST /api/alerts/import — normalize + insert a raw feed (no auto-correlation) */
export async function POST(req: Request) {
  try {
    const body = (await req.json().catch(() => null)) as ImportPayload | null;
    const raw = typeof body?.raw === "string" ? body.raw : "";
    const format: RequestedFormat =
      body?.format === "json" || body?.format === "csv" || body?.format === "text"
        ? body.format
        : "auto";

    if (!raw.trim()) {
      return NextResponse.json({ error: "Missing 'raw' payload" }, { status: 400 });
    }

    if (Buffer.byteLength(raw, "utf8") > 2 * 1024 * 1024) return NextResponse.json({ error: "Import is limited to 2 MB" }, { status: 413 });
    if (body?.format && !["auto", "json", "csv", "text"].includes(body.format)) return NextResponse.json({ error: "Unsupported format" }, { status: 400 });
    let normalized;
    let errors: { row: number; message: string }[] = [];
    try {
      const batch = normalizeBatch(raw, format);
      normalized = batch.alerts;
      errors = batch.errors;
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to parse payload";
      return NextResponse.json(
        { error: `Normalization failed: ${message}`, imported: 0, failed: 0, alerts: [] },
        { status: 400 }
      );
    }

    const inserted: Alert[] = [];
    let failed = errors.length;
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
      } catch (err) {
        if (!(err instanceof Prisma.PrismaClientKnownRequestError) || err.code !== "P2002") throw err;
        errors.push({ row: 0, message: `Duplicate alert ID: ${item.alertId}` });
        failed++; // duplicate alertId or constraint violation
      }
    }

    return NextResponse.json({
      imported: inserted.length,
      failed,
      errors,
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
