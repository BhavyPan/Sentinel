"use client";

import { useEffect, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { SeedButton } from "@/components/soc/seed-button";

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

/** Sticky SOC header: brand + tagline, live clock, SYSTEM ONLINE badge, seed action. */
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
              <h1 className="truncate text-lg font-bold tracking-tight">SentinelAI</h1>
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
          <LiveClock />
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
