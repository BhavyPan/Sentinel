"use client";

/** Sticky footer: attribution + demo disclaimer, respects iOS safe area. */
export function SocFooter() {
  return (
    <footer className="mt-auto border-t border-white/8 bg-card/40">
      <div className="mx-auto flex w-full max-w-[1600px] flex-col items-center justify-between gap-2 px-4 py-4 pb-[calc(1rem+env(safe-area-inset-bottom))] text-xs text-muted-foreground sm:flex-row sm:px-6">
        <p className="flex items-center gap-2">
          <span className="font-semibold text-foreground/80">SentinelAI</span>
          <span aria-hidden="true" className="text-emerald-500/60">·</span>
          D2 Threat Intelligence &amp; Alert Prioritisation
        </p>
        <p className="text-center sm:text-right">
          <span
            className="mr-2 hidden items-center gap-1 font-mono text-[10px] md:inline-flex"
            aria-label="Keyboard shortcut: press 1 to 5 to switch views"
          >
            {["1", "2", "3", "4", "5"].map((k) => (
              <kbd
                key={k}
                className="inline-flex size-4.5 items-center justify-center rounded border border-white/15 bg-white/5 font-mono text-[10px] text-foreground/70"
              >
                {k}
              </kbd>
            ))}
            <span className="ml-1 uppercase tracking-wider">switch views</span>
            <span className="mx-1.5" aria-hidden="true">·</span>
            <kbd className="inline-flex h-4.5 items-center rounded border border-white/15 bg-white/5 px-1 font-mono text-[10px] text-foreground/70">
              ⌘K
            </kbd>
            <span className="ml-1 uppercase tracking-wider">quick jump</span>
            <span className="mx-1.5" aria-hidden="true">·</span>
          </span>
          Simulated demo data · Not for operational use
          <span className="mx-1.5" aria-hidden="true">·</span>
          MITRE ATT&amp;CK® is a registered trademark of MITRE
        </p>
      </div>
    </footer>
  );
}
