import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { refreshIntel } from "@/lib/watchlist";
import { parseIocText } from "@/lib/watchlist-parse";

export const dynamic = "force-dynamic";

const MAX_LINES = 200;

/**
 * POST /api/watchlist/bulk — bulk import IOCs from pasted text.
 * Body: { text: string }
 * Each line: `type,value` or bare value (auto-detected). Comments (#, //)
 * and blank lines skipped. Duplicates (in paste or already in DB) reported.
 */
export async function POST(req: Request) {
  try {
    const body = (await req.json()) as { text?: unknown } | null;
    if (!body || typeof body.text !== "string" || !body.text.trim()) {
      return NextResponse.json(
        { error: "Provide `text` — a block of IOC lines to import" },
        { status: 400 }
      );
    }

    const { parsed, skipped } = parseIocText(body.text, MAX_LINES);
    if (parsed.length === 0) {
      return NextResponse.json(
        { error: "No valid indicators found in the paste", details: { duplicates: skipped } },
        { status: 400 }
      );
    }

    // dedupe against existing DB rows in one query
    const values = parsed.map((p) => p.value);
    const existing = await db.watchlistItem.findMany({
      where: { value: { in: values } },
      select: { value: true },
    });
    const existingSet = new Set(existing.map((e) => e.value));

    const toCreate = parsed.filter((p) => !existingSet.has(p.value));
    const duplicates: { line: number; reason: string }[] = [
      ...parsed
        .filter((p) => existingSet.has(p.value))
        .map((p) => ({ line: p.line, reason: `${p.value} already on watchlist` })),
      ...skipped,
    ];

    const created = await db.$transaction(
      toCreate.map((p) =>
        db.watchlistItem.create({
          data: { type: p.type, value: p.value, note: "bulk import" },
        })
      )
    );
    await refreshIntel();

    const typeCounts = toCreate.reduce<Record<string, number>>((acc, p) => {
      acc[p.type] = (acc[p.type] ?? 0) + 1;
      return acc;
    }, {});
    const parts = Object.entries(typeCounts)
      .sort((a, b) => b[1] - a[1])
      .map(([t, n]) => `${n} ${t}`);
    const message =
      `Imported ${created.length} indicator${created.length === 1 ? "" : "s"}` +
      (parts.length ? ` (${parts.join(", ")})` : "") +
      (duplicates.length ? ` · ${duplicates.length} skipped` : "");

    return NextResponse.json({
      added: created.length,
      duplicatesCount: duplicates.length,
      duplicates: duplicates.slice(0, 25),
      items: created.map((c) => ({
        id: c.id,
        type: c.type,
        value: c.value,
        note: c.note,
        createdAt: c.createdAt.toISOString(),
      })),
      message,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Bulk import failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
