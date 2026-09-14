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
          Simulated demo data · Not for operational use
          <span className="mx-1.5" aria-hidden="true">·</span>
          MITRE ATT&amp;CK® is a registered trademark of MITRE
        </p>
      </div>
    </footer>
  );
}
