"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { toast } from "sonner";
import {
  ArrowDownWideNarrow,
  Crosshair,
  Fingerprint,
  Globe,
  Loader2,
  Plus,
  ShieldBan,
  Trash2,
  TriangleAlert,
  Upload,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { apiGet, apiSend } from "@/lib/api-client";
import { timeAgo } from "@/lib/ui-helpers";
import { parseIocText } from "@/lib/watchlist-parse";
import type {
  WatchlistBulkResult,
  WatchlistItemDTO,
  WatchlistListResult,
  WatchlistResult,
} from "@/lib/types";
import { cn } from "@/lib/utils";

const TYPE_META: Record<string, { label: string; placeholder: string; icon: typeof Globe }> = {
  ip: { label: "IP address", placeholder: "e.g. 203.0.113.66", icon: Globe },
  domain: { label: "Domain", placeholder: "e.g. evil-cdn.example.com", icon: TriangleAlert },
  hash: { label: "File hash", placeholder: "e.g. e3b0c442…", icon: Fingerprint },
};

const SAMPLE_PASTE = `# one IOC per line — type auto-detected, or "type,value" rows
198.51.100.23
203.0.113.198
domain,c2.bad-actor.example.net
d41d8cd98f00b204e9800998ecf8427e`;

type WatchTypeFilter = "all" | "ip" | "domain" | "hash";
type WatchSort = "newest" | "hits" | "value";

const TYPE_FILTERS: { value: WatchTypeFilter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "ip", label: "IPs" },
  { value: "domain", label: "Domains" },
  { value: "hash", label: "Hashes" },
];

const SORT_OPTIONS: { value: WatchSort; label: string }[] = [
  { value: "newest", label: "Newest first" },
  { value: "hits", label: "Most hits" },
  { value: "value", label: "Value A–Z" },
];

/**
 * Analyst IOC Watchlist — add/remove custom malicious indicators.
 * Entries merge into the runtime intel feed: future correlations score them
 * as "known malicious IOC match" and the Threat Graph flags them red.
 * Each row shows how many stored alerts reference the IOC (hit counter).
 */
export function WatchlistCard() {
  const queryClient = useQueryClient();
  const [type, setType] = useState<"ip" | "domain" | "hash">("ip");
  const [value, setValue] = useState("");
  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkText, setBulkText] = useState("");
  const [typeFilter, setTypeFilter] = useState<WatchTypeFilter>("all");
  const [sort, setSort] = useState<WatchSort>("newest");

  const listQuery = useQuery({
    queryKey: ["watchlist"],
    queryFn: () => apiGet<WatchlistListResult>("/api/watchlist"),
    refetchInterval: 30_000, // hit counters refresh with new alerts
  });
  const items = listQuery.data?.items ?? [];
  const stats = listQuery.data?.stats;

  // client-side filter + sort (list is capped by the demo dataset scale)
  const visibleItems = useMemo(() => {
    const filtered = typeFilter === "all" ? items : items.filter((i) => i.type === typeFilter);
    const sorted = [...filtered];
    if (sort === "newest") {
      sorted.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    } else if (sort === "hits") {
      sorted.sort((a, b) => b.hits - a.hits || a.value.localeCompare(b.value));
    } else {
      sorted.sort((a, b) => a.value.localeCompare(b.value));
    }
    return sorted;
  }, [items, typeFilter, sort]);

  const typeCounts = useMemo(() => {
    const c: Record<WatchTypeFilter, number> = { all: items.length, ip: 0, domain: 0, hash: 0 };
    for (const i of items) c[i.type] += 1;
    return c;
  }, [items]);

  const invalidate = () =>
    void queryClient.invalidateQueries({ queryKey: ["watchlist"] });

  const addMutation = useMutation({
    mutationFn: (payload: { type: string; value: string }) =>
      apiSend<WatchlistResult>("/api/watchlist", "POST", payload),
    onSuccess: (d) => {
      invalidate();
      setValue("");
      toast.success("IOC added to watchlist", { description: d.message });
    },
    onError: (err: Error) => {
      toast.error("Could not add IOC", { description: err.message });
    },
  });

  const removeMutation = useMutation({
    mutationFn: (id: string) => apiSend<WatchlistResult>(`/api/watchlist/${id}`, "DELETE"),
    onSuccess: (d) => {
      invalidate();
      toast.success("IOC removed", { description: d.message });
    },
    onError: (err: Error) => {
      toast.error("Could not remove IOC", { description: err.message });
    },
  });

  const bulkMutation = useMutation({
    mutationFn: (text: string) =>
      apiSend<WatchlistBulkResult>("/api/watchlist/bulk", "POST", { text }),
    onSuccess: (d) => {
      invalidate();
      setBulkOpen(false);
      setBulkText("");
      const dupNote = d.duplicatesCount
        ? {
            description: `${d.duplicatesCount} skipped — ${d.duplicates
              .slice(0, 2)
              .map((x) => x.reason)
              .join("; ")}${d.duplicatesCount > 2 ? "…" : ""}`,
          }
        : undefined;
      toast.success(d.message, dupNote);
    },
    onError: (err: Error) => {
      toast.error("Bulk import failed", { description: err.message });
    },
  });

  const submit = () => {
    if (!value.trim()) {
      toast.error("Enter an indicator value first");
      return;
    }
    addMutation.mutate({ type, value: value.trim() });
  };

  // live preview of the bulk paste
  const bulkPreview = useMemo(() => parseIocText(bulkText), [bulkText]);
  const bulkValid = bulkPreview.parsed.length;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: 0.22 }}
    >
      <Card className="gap-3 rounded-xl">
        <CardHeader className="pb-1">
          <CardTitle className="flex flex-wrap items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            <span className="flex size-8 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10">
              <ShieldBan className="size-4 text-emerald-400" aria-hidden="true" />
            </span>
            IOC Watchlist
            {items.length > 0 && (
              <span className="rounded-full border border-red-500/40 bg-red-500/10 px-2 py-px font-mono text-[10px] font-bold text-red-300">
                {items.length}
              </span>
            )}
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="ml-auto min-h-8 gap-1.5 border-border px-2.5 text-[11px] text-muted-foreground hover:border-emerald-500/40 hover:text-emerald-300"
              onClick={() => setBulkOpen(true)}
              aria-label="Bulk import indicators from pasted text"
            >
              <Upload className="size-3.5" aria-hidden="true" />
              Bulk paste
            </Button>
          </CardTitle>
          <CardDescription className="text-xs">
            Your indicators join the intel feed — future correlations score them as known-malicious
            and the graph flags them red.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {/* coverage stat strip */}
          {stats && stats.itemCount > 0 && (
            <div className="flex items-center gap-2 rounded-lg border border-border/70 bg-muted/40 px-2.5 py-1.5" role="status" aria-label="Watchlist coverage">
              <Crosshair className="size-3.5 shrink-0 text-emerald-400/80" aria-hidden="true" />
              <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                coverage
              </span>
              <span className="flex flex-wrap items-center gap-1.5 font-mono text-[10px]">
                <span className="font-bold text-foreground/90">{stats.itemCount} indicators</span>
                <span aria-hidden="true" className="text-muted-foreground/50">·</span>
                <span
                  className={cn(
                    "inline-flex items-center gap-1 rounded-full border px-1.5 py-px font-bold",
                    stats.totalHits > 0
                      ? "border-red-500/40 bg-red-500/10 text-red-300"
                      : "border-border bg-background/60 text-muted-foreground"
                  )}
                >
                  {stats.totalHits} alert hit{stats.totalHits === 1 ? "" : "s"}
                </span>
                <span aria-hidden="true" className="text-muted-foreground/50">·</span>
                <span className="text-muted-foreground">
                  {stats.itemsWithHits}/{stats.itemCount} matched
                </span>
              </span>
            </div>
          )}

          {/* type filter chips + sort */}
          {items.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex flex-wrap items-center gap-1" role="group" aria-label="Filter by indicator type">
                {TYPE_FILTERS.map((f) => (
                  <button
                    key={f.value}
                    type="button"
                    onClick={() => setTypeFilter(f.value)}
                    aria-pressed={typeFilter === f.value}
                    className={cn(
                      "inline-flex min-h-7 items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider transition-colors",
                      typeFilter === f.value
                        ? "border-emerald-500/50 bg-emerald-500/15 text-emerald-300 shadow-[0_0_10px_oklch(0.72_0.149_163/15%)]"
                        : "border-border bg-muted/40 text-muted-foreground hover:border-emerald-500/30 hover:text-foreground"
                    )}
                  >
                    {f.label}
                    <span
                      className={cn(
                        "rounded px-1 text-[9px]",
                        typeFilter === f.value ? "bg-emerald-500/20 text-emerald-200" : "bg-background/60 text-muted-foreground"
                      )}
                    >
                      {typeCounts[f.value]}
                    </span>
                  </button>
                ))}
              </div>
              <div className="ml-auto flex items-center gap-1.5">
                <ArrowDownWideNarrow className="size-3 text-muted-foreground/60" aria-hidden="true" />
                <label htmlFor="watchlist-sort" className="sr-only">
                  Sort indicators
                </label>
                <Select value={sort} onValueChange={(v) => setSort(v as WatchSort)}>
                  <SelectTrigger
                    id="watchlist-sort"
                    className="h-7 w-[7.5rem] gap-1 border-border/70 bg-muted/40 px-2 text-[10px] uppercase tracking-wider text-muted-foreground"
                    aria-label="Sort indicators"
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SORT_OPTIONS.map((o) => (
                      <SelectItem key={o.value} value={o.value} className="text-xs">
                        {o.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}

          {/* add form */}
          <div className="flex flex-col gap-2 sm:flex-row">
            <div className="sm:w-32">
              <label htmlFor="watchlist-type" className="sr-only">
                Indicator type
              </label>
              <Select value={type} onValueChange={(v) => setType(v as typeof type)}>
                <SelectTrigger id="watchlist-type" className="min-h-10 w-full" aria-label="Indicator type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(TYPE_META).map(([k, m]) => (
                    <SelectItem key={k} value={k}>
                      {m.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-1 gap-2">
              <label htmlFor="watchlist-value" className="sr-only">
                Indicator value
              </label>
              <Input
                id="watchlist-value"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") submit();
                }}
                placeholder={TYPE_META[type].placeholder}
                className="min-h-10 flex-1 font-mono text-xs"
                autoComplete="off"
                spellCheck={false}
              />
              <Button
                type="button"
                size="sm"
                onClick={submit}
                disabled={addMutation.isPending}
                className="min-h-10 gap-1 border-emerald-500/50 bg-emerald-500/15 px-3 font-semibold text-emerald-300 hover:bg-emerald-500/25 hover:text-emerald-200"
                aria-label="Add indicator to watchlist"
              >
                {addMutation.isPending ? (
                  <Loader2 className="size-3.5 animate-spin" aria-hidden="true" />
                ) : (
                  <Plus className="size-3.5" aria-hidden="true" />
                )}
                Add
              </Button>
            </div>
          </div>

          {/* list */}
          {listQuery.isLoading ? (
            <div className="flex flex-col gap-1.5" aria-busy="true">
              <div className="h-8 rounded-lg bg-muted/50" />
              <div className="h-8 rounded-lg bg-muted/50" />
            </div>
          ) : items.length === 0 ? (
            <p className="rounded-lg border border-dashed border-border bg-background/40 px-3 py-3 text-center font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
              watchlist empty — add your first indicator above
            </p>
          ) : visibleItems.length === 0 ? (
            <div className="flex flex-col items-center gap-1.5 rounded-lg border border-dashed border-border bg-background/40 px-3 py-3">
              <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                no {typeFilter} indicators on the list
              </p>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="min-h-7 text-[11px] text-emerald-300 hover:text-emerald-200"
                onClick={() => setTypeFilter("all")}
              >
                Show all {items.length}
              </Button>
            </div>
          ) : (
            <ul
              className="soc-scroll -mx-1 flex max-h-40 flex-col gap-1 overflow-y-auto px-1"
              aria-label="Watchlist entries"
            >
              {visibleItems.map((it) => (
                <WatchlistRow
                  key={it.id}
                  item={it}
                  onRemove={() => removeMutation.mutate(it.id)}
                  removing={removeMutation.isPending && removeMutation.variables === it.id}
                />
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      {/* bulk import dialog */}
      <Dialog open={bulkOpen} onOpenChange={(o) => !o && setBulkOpen(false)}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              <Upload className="size-4 text-emerald-400" aria-hidden="true" />
              Bulk import indicators
            </DialogTitle>
            <DialogDescription className="text-xs">
              One IOC per line — type is auto-detected (IPv4 / hex hash / domain).{" "}
              <code className="rounded bg-muted px-1 font-mono text-[10px]">type,value</code> rows
              and <code className="rounded bg-muted px-1 font-mono text-[10px]">#</code> comments
              are supported. Max 200 lines.
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-2">
            <label htmlFor="bulk-ioc-text" className="sr-only">
              Indicator list
            </label>
            <textarea
              id="bulk-ioc-text"
              value={bulkText}
              onChange={(e) => setBulkText(e.target.value)}
              placeholder={SAMPLE_PASTE}
              rows={7}
              spellCheck={false}
              autoComplete="off"
              className="soc-scroll w-full resize-y rounded-lg border border-border bg-background/60 px-3 py-2 font-mono text-xs leading-relaxed text-foreground/90 placeholder:text-muted-foreground/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            />
            <div className="flex min-h-5 flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[10px]" aria-live="polite">
              {bulkText.trim() ? (
                <>
                  <span
                    className={cn(
                      "inline-flex items-center gap-1 rounded-full border px-1.5 py-px font-bold",
                      bulkValid > 0
                        ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                        : "border-red-500/40 bg-red-500/10 text-red-300"
                    )}
                  >
                    {bulkValid} valid
                  </span>
                  {bulkPreview.skipped.length > 0 && (
                    <span
                      className="text-muted-foreground"
                      title={bulkPreview.skipped.map((s) => `L${s.line}: ${s.reason}`).join("\n")}
                    >
                      {bulkPreview.skipped.length} skipped (hover for reasons)
                    </span>
                  )}
                </>
              ) : (
                <span className="text-muted-foreground">paste indicators to preview</span>
              )}
              <button
                type="button"
                className="ml-auto text-muted-foreground underline-offset-2 transition-colors hover:text-emerald-300 hover:underline"
                onClick={() => setBulkText(SAMPLE_PASTE)}
              >
                insert sample
              </button>
            </div>
            {bulkPreview.skipped.length > 0 && bulkText.trim() && (
              <ul className="soc-scroll max-h-16 overflow-y-auto rounded-lg border border-amber-500/30 bg-amber-500/5 px-2.5 py-1.5 font-mono text-[10px] text-amber-200/90" aria-label="Skipped lines">
                {bulkPreview.skipped.slice(0, 8).map((s, i) => (
                  <li key={`${s.line}-${i}`}>
                    L{s.line}: {s.reason}
                  </li>
                ))}
                {bulkPreview.skipped.length > 8 && (
                  <li className="text-muted-foreground">+{bulkPreview.skipped.length - 8} more…</li>
                )}
              </ul>
            )}
          </div>
          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="min-h-9 text-xs"
              onClick={() => setBulkOpen(false)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              size="sm"
              className="min-h-9 gap-1.5 border-emerald-500/50 bg-emerald-500/15 font-semibold text-emerald-300 hover:bg-emerald-500/25 hover:text-emerald-200"
              disabled={bulkValid === 0 || bulkMutation.isPending}
              onClick={() => bulkMutation.mutate(bulkText)}
            >
              {bulkMutation.isPending ? (
                <Loader2 className="size-3.5 animate-spin" aria-hidden="true" />
              ) : (
                <Upload className="size-3.5" aria-hidden="true" />
              )}
              Import {bulkValid > 0 ? bulkValid : ""}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </motion.div>
  );
}

function WatchlistRow({
  item,
  onRemove,
  removing,
}: {
  item: WatchlistItemDTO;
  onRemove: () => void;
  removing: boolean;
}) {
  const meta = TYPE_META[item.type] ?? TYPE_META.ip;
  const Icon = meta.icon;
  return (
    <li
      className={cn(
        "group flex min-h-9 items-center gap-2 rounded-lg border border-border/70 bg-muted/30 px-2.5 py-1.5 transition-colors hover:border-red-500/30 hover:bg-red-500/5",
        removing && "opacity-50"
      )}
    >
      <Icon className="size-3.5 shrink-0 text-red-400/80" aria-hidden="true" />
      <span className="truncate font-mono text-xs text-foreground/90" title={item.value}>
        {item.value}
      </span>
      <span className="shrink-0 rounded border border-border bg-background/60 px-1 py-px font-mono text-[9px] uppercase text-muted-foreground">
        {item.type}
      </span>
      {/* hit counter */}
      <span
        title={
          item.hits > 0
            ? `${item.hits} stored alert${item.hits === 1 ? "" : "s"} reference this indicator`
            : "No stored alerts reference this indicator yet"
        }
        className={cn(
          "ml-auto inline-flex shrink-0 items-center gap-1 rounded-full border px-1.5 py-px font-mono text-[9px] font-bold",
          item.hits > 0
            ? "border-red-500/40 bg-red-500/10 text-red-300"
            : "border-border bg-background/60 text-muted-foreground/70"
        )}
        aria-label={`${item.hits} alert hits`}
      >
        <Crosshair className="size-2.5" aria-hidden="true" />
        {item.hits}
      </span>
      <span className="hidden shrink-0 font-mono text-[10px] text-muted-foreground lg:inline">
        {timeAgo(item.createdAt)}
      </span>
      <Button
        type="button"
        variant="ghost"
        size="icon"
        className="size-7 shrink-0 text-muted-foreground transition-opacity hover:text-red-300 focus-visible:opacity-100 sm:opacity-0 sm:group-hover:opacity-100"
        onClick={onRemove}
        disabled={removing}
        aria-label={`Remove ${item.value} from watchlist`}
      >
        {removing ? (
          <Loader2 className="size-3.5 animate-spin" aria-hidden="true" />
        ) : (
          <Trash2 className="size-3.5" aria-hidden="true" />
        )}
      </Button>
    </li>
  );
}
