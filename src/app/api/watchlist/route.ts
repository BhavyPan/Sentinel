import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { refreshIntel, listWatchlist, validateWatchlistEntry } from "@/lib/watchlist";
import type { WatchlistHitStats } from "@/lib/types";

export const dynamic = "force-dynamic";

/** POST /api/watchlist — add a single IOC (validated, deduped by unique value) */
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
        hits: 0,
      },
      message: `${created.value} added to the watchlist — future correlations will treat it as malicious intel`,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to add watchlist item";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

export async function GET() {
  try {
    await refreshIntel(); // keep runtime intel in sync for consumers
    const items = await listWatchlist();

    const alerts = await db.alert.findMany({
      select: { ip: true, description: true, metadata: true },
    });
    const alertBlobs = alerts.map((a) => ({
      ip: a.ip,
      lower: `${a.metadata}\n${a.description}`.toLowerCase(),
    }));

    let totalHits = 0;
    let itemsWithHits = 0;
    const withHits = items.map((it) => {
      const needle = it.type === "ip" ? it.value : it.value.toLowerCase();
      let hits = 0;
      for (const a of alertBlobs) {
        if ((a.ip && a.ip === needle) || a.lower.includes(needle)) hits++;
      }
      totalHits += hits;
      if (hits > 0) itemsWithHits++;
      return { ...it, hits };
    });

    const stats: WatchlistHitStats = {
      itemCount: withHits.length,
      totalHits,
      itemsWithHits,
      lastAddedAt: withHits[0]?.createdAt ?? null,
    };
    return NextResponse.json({ items: withHits, stats });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to load watchlist";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
