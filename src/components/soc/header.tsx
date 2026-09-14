"use client";

import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Search, ShieldCheck } from "lucide-react";
import { SeedButton } from "@/components/soc/seed-button";
import { SimToggle } from "@/components/soc/sim-toggle";
import { useCommandPalette } from "@/components/soc/command-palette";
import { apiGet } from "@/lib/api-client";
import type { DashboardSummary } from "@/lib/types";

/** Live clock — suppressHydrationWarning covers the server/client time skew. */
function LiveClock() {
  const [now, setNow] = useState(() => new Date());

  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <span
      className="font-mono text-sm tabular-nums text-foreground/90"
      aria-label="Current time"
      suppressHydrationWarning
    >
      {now.toLocaleTimeString("en-GB", { hour12: false })}
    </span>
  );
}

/** "Last alert Xm ago" ticker — grounded in summary.lastUpdated. */
function LastAlertTicker() {
  const lastUpdated = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: () => apiGet<DashboardSummary>("/api/dashboard/summary"),
    refetchInterval: 15_000,
    select: (d: DashboardSummary) => d.lastUpdated,
  }).data;

  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(t);
  }, []);

  if (!lastUpdated) return null;
  const mins = Math.max(0, Math.floor((now - new Date(lastUpdated).getTime()) / 60_000));
  const label = mins < 1 ? "now" : mins < 60 ? `${mins}m ago` : `${Math.floor(mins / 60)}h ago`;
  return (
    <span
      className="hidden font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground lg:inline"
      aria-label={`Last alert received ${label}`}
    >
      last alert <span className="font-semibold text-emerald-300/90">{label}</span>
    </span>
  );
}

/** ⌘K quick-jump trigger — opens the global command palette. */
function PaletteTrigger() {
  const setOpen = useCommandPalette((s) => s.setOpen);
  return (
    <button
      type="button"
      onClick={() => setOpen(true)}
      aria-label="Open command palette (Command K)"
      title="Quick jump — ⌘K / Ctrl+K"
      className="inline-flex min-h-9 items-center gap-2 rounded-full border border-white/12 bg-card/70 px-3 text-[11px] text-muted-foreground transition-colors hover:border-emerald-500/40 hover:text-emerald-300"
    >
      <Search className="size-3.5" aria-hidden="true" />
      <span className="hidden md:inline">Quick jump…</span>
      <kbd className="hidden rounded border border-border bg-muted/60 px-1 font-mono text-[10px] md:inline">
        ⌘K
      </kbd>
    </button>
  );
}

/** Sticky SOC header: brand + tagline, live clock, SYSTEM ONLINE badge, sim + seed actions. */
export function SocHeader() {
  return (
    <header className="sticky top-0 z-40 border-b border-white/8 bg-background/80 backdrop-blur-md">
      <div className="soc-scanline mx-auto flex h-16 w-full max-w-[1600px] items-center justify-between gap-3 px-4 sm:px-6">
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-emerald-500/40 bg-emerald-500/10 shadow-[0_0_14px_-4px] shadow-emerald-500/50">
            <ShieldCheck className="size-5 text-emerald-400" aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <div className="flex items-baseline gap-2">
              <h1 className="truncate text-base font-bold tracking-tight sm:text-lg">SentinelAI</h1>
              <span className="hidden font-mono text-[10px] uppercase tracking-[0.25em] text-emerald-400/80 md:inline">
                D2 · SOC
              </span>
            </div>
            <p className="hidden truncate text-xs text-muted-foreground sm:block">
              From thousands of alerts to one clear decision.
            </p>
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-2 sm:gap-4">
          <PaletteTrigger />
          <LastAlertTicker />
          <span className="hidden sm:inline"><LiveClock /></span>
          <SimToggle />
          <span
            className="inline-flex items-center gap-2 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-emerald-300"
            role="status"
            aria-label="System status: online"
          >
            <span className="relative flex size-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" aria-hidden="true" />
              <span className="relative inline-flex size-2 rounded-full bg-emerald-500" aria-hidden="true" />
            </span>
            <span className="hidden sm:inline">System Online</span>
            <span className="sm:hidden">Live</span>
          </span>
          <SeedButton size="sm" label="Load Demo" className="hidden md:inline-flex" />
        </div>
      </div>
    </header>
  );
}
