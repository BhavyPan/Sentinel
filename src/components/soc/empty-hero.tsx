"use client";

import { motion } from "framer-motion";
import { ShieldAlert, Workflow } from "lucide-react";
import { DEMO_FEED_LABELS } from "@/lib/seed-data";
import { SeedButton } from "@/components/soc/seed-button";

/**
 * Full-screen empty state shown before any data has been ingested.
 * Explains the pipeline and offers the one-click demo dataset.
 */
export function EmptyHero() {
  return (
    <motion.section
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45, ease: "easeOut" }}
      className="mx-auto flex w-full max-w-3xl flex-col items-center px-4 py-14 text-center sm:py-20"
      aria-labelledby="empty-hero-title"
    >
      <div className="relative mb-6">
        <div className="absolute inset-0 -z-10 rounded-full bg-emerald-500/15 blur-2xl" aria-hidden="true" />
        <div className="flex size-20 items-center justify-center rounded-2xl border border-emerald-500/30 bg-emerald-500/10">
          <ShieldAlert className="size-10 text-emerald-400" aria-hidden="true" />
        </div>
      </div>

      <h2 id="empty-hero-title" className="text-2xl font-bold tracking-tight sm:text-3xl">
        No threat data yet
      </h2>
      <p className="mt-3 max-w-xl text-sm leading-relaxed text-muted-foreground sm:text-base">
        SentinelAI turns raw multi-source alert streams into correlated, scored
        incidents with MITRE ATT&amp;CK mapping and AI-written BLUF briefings.
        Load the simulated demo dataset to watch the full pipeline:
        <span className="text-foreground/90"> ingest → normalize → correlate → score → analyze</span>.
      </p>

      <SeedButton size="lg" className="mt-7 min-h-11 px-6" />

      <div className="mt-10 w-full">
        <div className="mb-3 flex items-center justify-center gap-2 text-xs uppercase tracking-[0.2em] text-muted-foreground">
          <Workflow className="size-3.5" aria-hidden="true" />
          Included demo feeds
        </div>
        <ul className="flex flex-wrap items-center justify-center gap-2">
          {DEMO_FEED_LABELS.map((feed) => (
            <li
              key={feed.key}
              className="inline-flex items-center gap-2 rounded-lg border border-border bg-card/70 px-3 py-2 text-left"
            >
              <span className="font-medium text-foreground/90">{feed.label}</span>
              <span className="font-mono text-[10px] uppercase tracking-wider text-emerald-400/80">
                {feed.format}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </motion.section>
  );
}
