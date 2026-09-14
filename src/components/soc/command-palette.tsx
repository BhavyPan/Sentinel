"use client";

import { useEffect } from "react";
import { create } from "zustand";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Bot,
  Crosshair,
  DatabaseZap,
  LayoutDashboard,
  MessageCircleQuestion,
  Network,
  Radio,
  ShieldQuestion,
  Sparkles,
  Waypoints,
  type LucideIcon,
} from "lucide-react";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ui/command";
import { apiGet, apiSend } from "@/lib/api-client";
import { unwrapList } from "@/lib/ui-helpers";
import type { CorrelateResult, IncidentDTO, SeedResult } from "@/lib/types";
import { useSocStore, type SocTab } from "@/store/soc-store";
import { cn } from "@/lib/utils";

// ============================================================
// ⌘K Command Palette — global quick navigation & actions
// ============================================================

interface PaletteState {
  open: boolean;
  setOpen: (open: boolean) => void;
}

/** Module-level palette state so the header button and the shortcut share it. */
export const useCommandPalette = create<PaletteState>((set) => ({
  open: false,
  setOpen: (open) => set({ open }),
}));

const TAB_TARGETS: { tab: SocTab; label: string; icon: LucideIcon; shortcut: string }[] = [
  { tab: "command", label: "Command Center", icon: LayoutDashboard, shortcut: "1" },
  { tab: "feed", label: "Threat Feed", icon: Radio, shortcut: "2" },
  { tab: "graph", label: "Threat Graph", icon: Waypoints, shortcut: "3" },
  { tab: "analysis", label: "Incident Analysis", icon: Crosshair, shortcut: "4" },
  { tab: "copilot", label: "AI Copilot", icon: Bot, shortcut: "5" },
];

const COPILOT_PROMPTS = [
  "What is the highest-risk threat?",
  "Why is INC-1001 critical?",
  "What should we investigate first?",
  "Summarize all false positives.",
];

/** Severity → dot color class (mirrors badges.tsx ramp). */
function severityDot(severity: string): string {
  switch (severity) {
    case "Critical":
      return "bg-red-500";
    case "High":
      return "bg-amber-500";
    case "Medium":
      return "bg-yellow-400";
    case "Low":
      return "bg-emerald-500";
    default:
      return "bg-slate-500";
  }
}

/**
 * Global ⌘K / Ctrl+K palette:
 *  - Go to any SOC view (1-5)
 *  - Jump straight to an incident investigation (live, severity-ranked)
 *  - One-click Copilot questions
 *  - Pipeline actions (load demo dataset, run correlation)
 */
export function CommandPalette() {
  const open = useCommandPalette((s) => s.open);
  const setOpen = useCommandPalette((s) => s.setOpen);
  const setActiveTab = useSocStore((s) => s.setActiveTab);
  const openIncident = useSocStore((s) => s.openIncident);
  const askQuestion = useSocStore((s) => s.askQuestion);
  const queryClient = useQueryClient();

  // Global shortcut — registers once, opens/closes regardless of focus target.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen(!useCommandPalette.getState().open);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setOpen]);

  const incidentsQuery = useQuery({
    queryKey: ["incidents"],
    queryFn: () => apiGet<unknown>("/api/incidents"),
    enabled: open, // only fetch while the palette is open
    select: (d: unknown) => unwrapList<IncidentDTO>(d, "incidents"),
  });
  const incidents = [...(incidentsQuery.data ?? [])].sort(
    (a, b) => b.threatScore - a.threatScore
  );

  const runCorrelate = async () => {
    try {
      const d = await apiSend<CorrelateResult>("/api/incidents/correlate", "POST");
      void queryClient.invalidateQueries();
      toast.success("Correlation complete", {
        description: `${d.alertsGrouped} alerts grouped → ${d.incidentsAfter} incidents.`,
      });
    } catch (err) {
      toast.error("Correlation failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    }
  };

  const runSeed = async () => {
    try {
      const d = await apiSend<SeedResult>("/api/alerts/seed", "POST");
      void queryClient.invalidateQueries();
      toast.success("Demo dataset loaded", {
        description: d.message || `Seeded ${d.seeded} alerts → ${d.incidents} incidents correlated.`,
      });
      setActiveTab("command");
    } catch (err) {
      toast.error("Seeding failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    }
  };

  const close = () => setOpen(false);

  return (
    <CommandDialog
      open={open}
      onOpenChange={setOpen}
      className="border-white/10 shadow-[0_0_60px_-12px] shadow-emerald-500/25"
      aria-label="Command palette"
    >
      <div className="flex items-center gap-2 border-b border-border/70 px-3 pt-3">
        <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
          quick jump
        </span>
        <kbd className="ml-auto rounded border border-border bg-muted/60 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
          Esc
        </kbd>
      </div>
      <CommandInput placeholder="Search views, incidents (INC-…) and actions…" />

      <CommandList className="soc-scroll max-h-[min(60vh,480px)]">
        <CommandEmpty className="py-8 text-center font-mono text-xs text-muted-foreground">
          No matching views, incidents or actions.
        </CommandEmpty>

        <CommandGroup heading="Go to view">
          {TAB_TARGETS.map(({ tab, label, icon: Icon, shortcut }) => (
            <CommandItem
              key={tab}
              value={`view ${label}`}
              keywords={[tab, "go", "view", "navigate"]}
              onSelect={() => {
                setActiveTab(tab);
                close();
              }}
            >
              <Icon className="size-4 text-emerald-400" aria-hidden="true" />
              <span>{label}</span>
              <CommandShortcut>{shortcut}</CommandShortcut>
            </CommandItem>
          ))}
        </CommandGroup>

        {incidents.length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading={`Open investigation — ${incidents.length} incidents`}>
              {incidents.map((inc) => (
                <CommandItem
                  key={inc.id}
                  value={`${inc.incidentId} ${inc.title} ${inc.severity} ${inc.status}`}
                  keywords={["incident", "investigation", "open"]}
                  onSelect={() => {
                    openIncident(inc.id);
                    close();
                  }}
                >
                  <span
                    className={cn("size-2 shrink-0 rounded-full", severityDot(inc.severity))}
                    aria-hidden="true"
                  />
                  <span className="font-mono text-xs text-emerald-300/90">{inc.incidentId}</span>
                  <span className="truncate">{inc.title}</span>
                  <span className="ml-auto shrink-0 font-mono text-[10px] tabular-nums text-muted-foreground">
                    {inc.threatScore}
                  </span>
                </CommandItem>
              ))}
            </CommandGroup>
          </>
        )}

        <CommandSeparator />
        <CommandGroup heading="Ask the copilot">
          {COPILOT_PROMPTS.map((q) => (
            <CommandItem
              key={q}
              value={`ask ${q}`}
              keywords={["copilot", "question", "ai"]}
              onSelect={() => {
                askQuestion(q);
                close();
              }}
            >
              <MessageCircleQuestion className="size-4 text-emerald-400" aria-hidden="true" />
              <span className="truncate">{q}</span>
            </CommandItem>
          ))}
        </CommandGroup>

        <CommandSeparator />
        <CommandGroup heading="Actions">
          <CommandItem
            value="load demo dataset seed"
            keywords={["seed", "data", "ingest", "reset"]}
            onSelect={() => {
              close();
              void runSeed();
            }}
          >
            <DatabaseZap className="size-4 text-emerald-400" aria-hidden="true" />
            <span>Load Demo Dataset</span>
            <CommandShortcut>
              <Sparkles className="size-3" aria-hidden="true" />
            </CommandShortcut>
          </CommandItem>
          <CommandItem
            value="run correlation pipeline"
            keywords={["correlate", "group", "cluster", "pipeline"]}
            onSelect={() => {
              close();
              void runCorrelate();
            }}
          >
            <Network className="size-4 text-emerald-400" aria-hidden="true" />
            <span>Run Correlation Pipeline</span>
          </CommandItem>
          <CommandItem
            value="open copilot ask anything"
            keywords={["copilot", "chat", "custom"]}
            onSelect={() => {
              setActiveTab("copilot");
              close();
            }}
          >
            <ShieldQuestion className="size-4 text-emerald-400" aria-hidden="true" />
            <span>Open Copilot (free-form)</span>
          </CommandItem>
        </CommandGroup>
      </CommandList>

      <div className="flex items-center justify-between border-t border-border/70 px-3 py-2 font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground">
        <span>↑↓ navigate · ↵ select</span>
        <span>⌘K palette</span>
      </div>
    </CommandDialog>
  );
}
