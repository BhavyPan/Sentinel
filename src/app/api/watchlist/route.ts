import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { refreshIntel, listWatchlist, validateWatchlistEntry } from "@/lib/watchlist";

export const dynamic = "force-dynamic";

/** GET /api/watchlist — analyst-curated IOC list */
export async function GET() {
  try {
    const items = await listWatchlist();
    return NextResponse.json({ items });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to load watchlist";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

/** POST /api/watchlist — add an IOC (validated, deduped by unique value) */
export async function POST(req: Request) {
  try {
    const body = (await req.json()) as { type?: string; value?: string; note?: string } | null;
    if (!body || typeof body !== "object") {
      return NextResponse.json({ error: "Invalid request body" }, { status: 400 });
    }
    const check = validateWatchlistEntry(body.type ?? "", body.value ?? "");
    if ("error" in check) {
      return NextResponse.json({ error: check.error }, { status: 400 });
    }
    const existing = await db.watchlistItem.findUnique({ where: { value: check.value } });
    if (existing) {
      return NextResponse.json(
        { error: `${check.value} is already on the watchlist` },
        { status: 409 }
      );
    }
    const created = await db.watchlistItem.create({
      data: {
        type: check.type,
        value: check.value,
        note: String(body.note ?? "").slice(0, 200),
      },
    });
    await refreshIntel();
    return NextResponse.json({
      item: {
        id: created.id,
        type: created.type,
        value: created.value,
        note: created.note,
        createdAt: created.createdAt.toISOString(),
      },
      message: `${created.value} added to the watchlist — future correlations will treat it as malicious intel`,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to add watchlist item";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
