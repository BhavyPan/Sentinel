"use client";

import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Activity, Loader2 } from "lucide-react";
import { apiSend } from "@/lib/api-client";
import type { DashboardSummary } from "@/lib/types";
import { cn } from "@/lib/utils";

interface SimulateResponse {
  action: "attached" | "new-incident" | "ungrouped";
  alert: {
    alertId: string;
    sourceLabel: string;
    event: string;
    description: string;
    rawSeverity: string;
  };
  note: string;
  incident: { incidentId: string; severity: string; threatScore: number } | null;
  summary: DashboardSummary;
}

const TICK_MS = 9_000;

/**
 * Live threat simulation toggle (spec §15). When ON, a 9s interval asks the
 * backend for one new simulated alert (real normalizer + incremental
 * correlator) and refreshes every SOC view.
 */
export function SimToggle() {
  const [on, setOn] = useState(false);
  const [pending, setPending] = useState(false);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);
  const inFlight = useRef(false);
  const queryClient = useQueryClient();

  const tick = async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setPending(true);
    try {
      const d = await apiSend<SimulateResponse>("/api/alerts/simulate", "POST");
      void queryClient.invalidateQueries({ queryKey: ["dashboard-summary"] });
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["incident"] });

      const sev = d.alert.rawSeverity.toUpperCase();
      const headline = `${d.alert.sourceLabel} · ${d.alert.description}`;
      if (d.action === "new-incident" && d.incident) {
        toast.success(`New ${d.incident.severity} incident ${d.incident.incidentId}`, {
          description: headline,
        });
      } else if (d.action === "attached" && d.incident) {
        toast(`Alert correlated → ${d.incident.incidentId}`, { description: headline });
      } else if (["CRITICAL", "HIGH"].includes(sev)) {
        toast.warning(`High-signal alert ingested`, { description: headline });
      } else {
        toast("Alert ingested", { description: headline });
      }
    } catch (err) {
      toast.error("Simulation tick failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    } finally {
      inFlight.current = false;
      setPending(false);
    }
  };

  useEffect(() => {
    if (on) {
      void tick();
      timer.current = setInterval(() => void tick(), TICK_MS);
    }
    return () => {
      if (timer.current) clearInterval(timer.current);
      timer.current = null;
    };
  }, [on]);

  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label="Toggle live threat simulation"
      onClick={() => setOn((v) => !v)}
      className={cn(
        "inline-flex min-h-9 items-center gap-2 rounded-full border px-3 text-[10px] font-semibold uppercase tracking-[0.16em] transition-all",
        on
          ? "border-red-500/50 bg-red-500/15 text-red-300 shadow-[0_0_16px_-4px] shadow-red-500/60"
          : "border-white/12 bg-card/70 text-muted-foreground hover:border-emerald-500/40 hover:text-emerald-300"
      )}
    >
      {pending && on ? (
        <Loader2 className="size-3.5 animate-spin" aria-hidden="true" />
      ) : (
        <span className="relative flex size-2">
          {on && (
            <span
              className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-60"
              aria-hidden="true"
            />
          )}
          <span
            className={cn("relative inline-flex size-2 rounded-full", on ? "bg-red-500" : "bg-slate-500")}
            aria-hidden="true"
          />
        </span>
      )}
      <Activity className="size-3.5" aria-hidden="true" />
      <span className="hidden sm:inline">{on ? "Simulating" : "Simulate"}</span>
      <span className="hidden font-mono sm:inline">SIM</span>
    </button>
  );
}
