"use client";

import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { DatabaseZap, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { apiSend } from "@/lib/api-client";
import type { SeedResult } from "@/lib/types";
import { useSocStore } from "@/store/soc-store";
import { cn } from "@/lib/utils";

const STATUS_LINES = [
  "Ingesting SIEM batch…",
  "Parsing CSV sensor export…",
  "Correlating alerts…",
  "Scoring threats…",
];

/**
 * "Load Demo Dataset" — POSTs /api/alerts/seed with a rotating status readout,
 * then invalidates all queries and jumps to the Command Center.
 */
export function SeedButton({
  size = "default",
  className,
  label = "Load Demo Dataset",
}: {
  size?: "default" | "sm" | "lg";
  className?: string;
  label?: string;
}) {
  const [lineIndex, setLineIndex] = useState(0);
  const queryClient = useQueryClient();
  const setActiveTab = useSocStore((s) => s.setActiveTab);

  const mutation = useMutation({
    mutationFn: () => apiSend<SeedResult>("/api/alerts/seed", "POST"),
    onSuccess: (data) => {
      queryClient.invalidateQueries();
      toast.success("Demo dataset loaded", {
        description: data.message || `Seeded ${data.seeded} alerts → ${data.incidents} incidents correlated.`,
      });
      setActiveTab("command");
    },
    onError: (err: Error) => {
      toast.error("Seeding failed", {
        description: err.message || "The ingestion pipeline returned an error.",
      });
    },
  });

  const pending = mutation.isPending;

  useEffect(() => {
    if (!pending) return;
    const t = setInterval(
      () => setLineIndex((i) => (i + 1) % STATUS_LINES.length),
      1400
    );
    return () => clearInterval(t);
  }, [pending]);

  return (
    <Button
      type="button"
      size={size}
      disabled={pending}
      onClick={() => {
        setLineIndex(0);
        mutation.mutate();
      }}
      aria-label={pending ? "Loading demo dataset" : label}
      className={cn(
        "group relative overflow-hidden border-emerald-500/50 bg-emerald-500/15 font-semibold text-emerald-300 shadow-[0_0_18px_-6px] shadow-emerald-500/40 hover:bg-emerald-500/25 hover:text-emerald-200",
        className
      )}
    >
      {pending ? (
        <>
          <Loader2 className="size-4 animate-spin" aria-hidden="true" />
          <span className="font-mono text-xs sm:text-sm">{STATUS_LINES[lineIndex]}</span>
        </>
      ) : (
        <>
          <DatabaseZap className="size-4 transition-transform group-hover:scale-110" aria-hidden="true" />
          {label}
        </>
      )}
    </Button>
  );
}
