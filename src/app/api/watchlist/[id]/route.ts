import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { refreshIntel } from "@/lib/watchlist";

export const dynamic = "force-dynamic";

/** DELETE /api/watchlist/[id] — remove an IOC by db id (or value) */
export async function DELETE(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const existing = await db.watchlistItem.findFirst({
      where: { OR: [{ id }, { value: id }] },
    });
    if (!existing) {
      return NextResponse.json({ error: `Watchlist item ${id} not found` }, { status: 404 });
    }
    await db.watchlistItem.delete({ where: { id: existing.id } });
    await refreshIntel();
    return NextResponse.json({ removed: existing.value, message: `${existing.value} removed from the watchlist` });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to remove watchlist item";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
