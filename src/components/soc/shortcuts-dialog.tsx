"use client";

import { Keyboard } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useSocStore } from "@/store/soc-store";

interface ShortcutDef {
  keys: string[];
  action: string;
  group: "Navigation" | "Global" | "Tables & graph";
}

const SHORTCUTS: ShortcutDef[] = [
  { keys: ["1"], action: "Go to Command Center", group: "Navigation" },
  { keys: ["2"], action: "Go to Threat Feed", group: "Navigation" },
  { keys: ["3"], action: "Go to Threat Graph", group: "Navigation" },
  { keys: ["4"], action: "Go to Incident Analysis", group: "Navigation" },
  { keys: ["5"], action: "Go to AI Copilot", group: "Navigation" },
  { keys: ["⌘", "K"], action: "Open command palette (quick jump, actions)", group: "Global" },
  { keys: ["?"], action: "Toggle this shortcuts help", group: "Global" },
  { keys: ["Esc"], action: "Close palette / dialog / graph selection", group: "Global" },
  { keys: ["Enter"], action: "Open the focused incident row", group: "Tables & graph" },
  { keys: ["Space"], action: "Open the focused incident row / graph node", group: "Tables & graph" },
  { keys: ["Esc"], action: "Clear selected graph edge or node highlight", group: "Tables & graph" },
];

const GROUPS: ShortcutDef["group"][] = ["Navigation", "Global", "Tables & graph"];

/** Keyboard shortcuts help dialog — open with "?" or the footer [?] hint. */
export function ShortcutsDialog() {
  const open = useSocStore((s) => s.shortcutsOpen);
  const setOpen = useSocStore((s) => s.setShortcutsOpen);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-base">
            <span className="flex size-8 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10">
              <Keyboard className="size-4 text-emerald-400" aria-hidden="true" />
            </span>
            Keyboard shortcuts
          </DialogTitle>
          <DialogDescription className="text-xs">
            Shortcuts are ignored while typing in inputs, notes and searches.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          {GROUPS.map((group) => (
            <div key={group}>
              <p className="mb-1.5 font-mono text-[9px] uppercase tracking-widest text-muted-foreground/60">
                {group}
              </p>
              <ul className="flex flex-col gap-1" aria-label={`${group} shortcuts`}>
                {SHORTCUTS.filter((s) => s.group === group).map((s, i) => (
                  <li
                    key={`${s.action}-${i}`}
                    className="flex min-h-8 items-center justify-between gap-3 rounded-lg border border-border/60 bg-muted/25 px-2.5 py-1"
                  >
                    <span className="text-xs text-foreground/85">{s.action}</span>
                    <span className="flex shrink-0 items-center gap-1">
                      {s.keys.map((k) => (
                        <kbd
                          key={k}
                          className="inline-flex h-5 min-w-5 items-center justify-center rounded border border-white/15 bg-white/5 px-1 font-mono text-[10px] font-semibold text-foreground/80"
                        >
                          {k}
                        </kbd>
                      ))}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  );
}
