"use client";

import { createElement } from "react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { sourceIcon, severityStyle, rawSeverityLabel } from "@/lib/ui-helpers";
import { ArrowRight, Link2, Unlink } from "lucide-react";
import type { Classification, IncidentStatus, Severity } from "@/lib/types";

/** Incident severity badge (Critical / High / Medium / Low / False Positive) */
export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity | string;
  className?: string;
}) {
  const s = severityStyle(severity);
  return (
    <Badge
      variant="outline"
      className={cn(s.bg, s.border, s.text, "font-semibold tracking-wide", className)}
    >
      <span className={cn("size-1.5 rounded-full", s.dot)} aria-hidden="true" />
      {s.label}
    </Badge>
  );
}

/** Raw source-system severity (low/medium/high/critical/info) for the feed */
export function RawSeverityBadge({
  raw,
  className,
}: {
  raw: string;
  className?: string;
}) {
  const key = rawSeverityLabel(raw);
  const s = severityStyle(key);
  return (
    <Badge
      variant="outline"
      className={cn(s.bg, s.border, s.text, "uppercase font-mono text-[10px] tracking-widest", className)}
    >
      {raw || "info"}
    </Badge>
  );
}

/** Classification chip: Genuine Threat / False Positive / Under Review */
export function ClassificationBadge({
  classification,
  className,
}: {
  classification: Classification;
  className?: string;
}) {
  const map: Record<Classification, string> = {
    "Genuine Threat": "border-red-500/40 bg-red-500/10 text-red-300",
    "False Positive": "border-slate-500/40 bg-slate-500/10 text-slate-300",
    "Under Review": "border-amber-500/40 bg-amber-500/10 text-amber-300",
  };
  const icons: Record<Classification, string> = {
    "Genuine Threat": "◆",
    "False Positive": "○",
    "Under Review": "◔",
  };
  return (
    <Badge
      variant="outline"
      className={cn(map[classification], "font-medium", className)}
      aria-label={`Classification: ${classification}`}
    >
      <span aria-hidden="true" className="mr-0.5 text-[9px]">{icons[classification]}</span>
      {classification}
    </Badge>
  );
}

/** Workflow status chip: Open=red / Investigating=amber / Contained=emerald / Resolved=slate */
export function StatusBadge({
  status,
  className,
}: {
  status: IncidentStatus;
  className?: string;
}) {
  const map: Record<IncidentStatus, string> = {
    Open: "border-red-500/40 bg-red-500/10 text-red-300",
    Investigating: "border-amber-500/40 bg-amber-500/10 text-amber-300",
    Contained: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
    Resolved: "border-slate-500/40 bg-slate-500/10 text-slate-300",
  };
  const dots: Record<IncidentStatus, string> = {
    Open: "bg-red-500",
    Investigating: "bg-amber-500",
    Contained: "bg-emerald-500",
    Resolved: "bg-slate-500",
  };
  return (
    <Badge
      variant="outline"
      className={cn(map[status], "font-medium", className)}
      aria-label={`Status: ${status}`}
    >
      <span className={cn("size-1.5 rounded-full", dots[status])} aria-hidden="true" />
      {status}
    </Badge>
  );
}

/** Source chip: icon + display label */
export function SourceChip({
  source,
  sourceLabel,
  className,
}: {
  source: string;
  sourceLabel?: string;
  className?: string;
}) {
  const icon = sourceIcon(source);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border border-border bg-muted/60 px-2 py-0.5 text-xs text-foreground/90 whitespace-nowrap",
        className
      )}
    >
      {createElement(icon, {
        className: "size-3.5 text-emerald-400/90",
        "aria-hidden": true,
      })}
      {sourceLabel ?? source}
    </span>
  );
}

/** Code-style event name chip */
export function EventChip({ event, className }: { event: string; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex max-w-full items-center rounded-md border border-emerald-500/20 bg-emerald-500/5 px-1.5 py-0.5 font-mono text-[11px] text-emerald-300/90 truncate",
        className
      )}
      title={event}
    >
      {event}
    </span>
  );
}

/** Feed status: "Correlated → INC-XXXX" emerald chip (click → Analysis tab) or "Unassigned" slate */
export function CorrelationChip({
  incidentId,
  onClick,
  className,
}: {
  incidentId: string | null;
  /** display id like INC-1001; pass undefined for Unassigned */
  onClick?: () => void;
  className?: string;
}) {
  if (incidentId) {
    return (
      <button
        type="button"
        onClick={onClick}
        className={cn(
          "inline-flex min-h-11 items-center gap-1 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 font-mono text-[11px] font-semibold text-emerald-300 transition-colors hover:bg-emerald-500/20 focus-visible:ring-2 focus-visible:ring-ring md:min-h-0",
          className
        )}
        aria-label={`Open correlated incident ${incidentId}`}
      >
        <Link2 className="size-3" aria-hidden="true" />
        {incidentId}
        <ArrowRight className="size-3" aria-hidden="true" />
      </button>
    );
  }
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border border-slate-600/40 bg-slate-500/10 px-2 py-0.5 font-mono text-[11px] text-slate-400",
        className
      )}
    >
      <Unlink className="size-3" aria-hidden="true" />
      Unassigned
    </span>
  );
}
