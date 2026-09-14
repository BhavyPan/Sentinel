/**
 * Analyst IOC watchlist (server-side).
 * Loads the DB watchlist and merges it into the runtime intel sets used by
 * the normalizer, correlator, scorer, simulator and graph — so analyst-added
 * IOCs instantly participate in scoring, correlation and flagging.
 */
import { db } from "@/lib/db";
import { setExtraIntel, type IntelMerge } from "./threat-intel";

const CACHE_MS = 5_000;
let lastLoad = 0;
let lastError: string | null = null;

export interface WatchlistItemDTO {
  id: string;
  type: "ip" | "domain" | "hash";
  value: string;
  note: string;
  createdAt: string;
}

function split(items: { type: string; value: string }[]): IntelMerge {
  const ips: string[] = [];
  const domains: string[] = [];
  const hashes: string[] = [];
  for (const it of items) {
    if (it.type === "ip") ips.push(it.value);
    else if (it.type === "domain") domains.push(it.value);
    else if (it.type === "hash") hashes.push(it.value);
  }
  return { ips, domains, hashes };
}

/**
 * Re-read the watchlist (5s cache) and refresh the runtime intel merge.
 * Safe to call at the top of any route that scores or flags IOCs.
 */
export async function refreshIntel(): Promise<void> {
  const now = Date.now();
  if (now - lastLoad < CACHE_MS) return;
  try {
    const rows = await db.watchlistItem.findMany({ select: { type: true, value: true } });
    setExtraIntel(split(rows));
    lastLoad = now;
    lastError = null;
  } catch (err) {
    // intel refresh failure must never break ingestion/correlation — keep stale sets
    lastError = err instanceof Error ? err.message : "watchlist load failed";
    lastLoad = now;
  }
}

export function intelError(): string | null {
  return lastError;
}

export async function listWatchlist(): Promise<WatchlistItemDTO[]> {
  const rows = await db.watchlistItem.findMany({ orderBy: { createdAt: "desc" } });
  return rows.map((r) => ({
    id: r.id,
    type: r.type as WatchlistItemDTO["type"],
    value: r.value,
    note: r.note,
    createdAt: r.createdAt.toISOString(),
  }));
}

export type WatchlistType = "ip" | "domain" | "hash";

/** Validate + normalize a watchlist entry. Returns an error string or null. */
export function validateWatchlistEntry(
  rawType: string,
  rawValue: string
): { type: WatchlistType; value: string } | { error: string } {
  const type = String(rawType).trim().toLowerCase();
  const value = String(rawValue).trim();
  if (!["ip", "domain", "hash"].includes(type)) {
    return { error: "type must be one of: ip, domain, hash" };
  }
  if (!value || value.length > 200) {
    return { error: "value is required (max 200 chars)" };
  }
  if (type === "ip") {
    const ipv4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
    if (!ipv4.test(value)) return { error: "value must be a valid IPv4 address" };
  }
  if (type === "domain") {
    const domain = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i;
    if (!domain.test(value)) return { error: "value must be a valid domain name" };
    return { type: "domain", value: value.toLowerCase() };
  }
  if (type === "hash") {
    if (!/^[a-f0-9]{8,64}$/i.test(value)) {
      return { error: "value must be a hex hash (8-64 chars)" };
    }
    return { type: "hash", value: value.toLowerCase() };
  }
  return { type: type as WatchlistType, value };
}
