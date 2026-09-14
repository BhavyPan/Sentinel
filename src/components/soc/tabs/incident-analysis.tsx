"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { motion } from "framer-motion";
import {
  CheckCircle2,
  Copy,
  Crosshair,
  Download,
  FileDown,
  FileText,
  Loader2,
  NotebookPen,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  ThumbsDown,
  ThumbsUp,
  X,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  ClassificationBadge,
  EventChip,
  SeverityBadge,
  SourceChip,
  StatusBadge,
} from "@/components/soc/badges";
import { ScoreGauge } from "@/components/soc/threat-score";
import { ErrorState } from "@/components/soc/error-state";
import { apiGet, apiSend } from "@/lib/api-client";
import type {
  Classification,
  IncidentDetailDTO,
  IncidentDTO,
  IncidentStatus,
  IncidentUpdatePayload,
} from "@/lib/types";
import {
  formatDateTime,
  rawSeverityLabel,
  scoreTextClass,
  severityStyle,
  timeAgo,
  unwrapList,
} from "@/lib/ui-helpers";
import { useSocStore } from "@/store/soc-store";
import { cn } from "@/lib/utils";

const ANALYZE_LINES = [
  "Consulting threat analyst model…",
  "Cross-referencing MITRE ATT&CK…",
  "Drafting BLUF summary…",
  "Validating evidence chain…",
];

const STATUSES: IncidentStatus[] = ["Open", "Investigating", "Contained", "Resolved"];

// ------------------------------------------------------------------
// Left pane — ranked incident list
// ----------------------------------------------------------------------

function IncidentList({
  incidents,
  selectedId,
  onSelect,
}: {
  incidents: IncidentDTO[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <nav
      aria-label="Incident list"
      className="soc-scroll flex gap-2 overflow-x-auto pb-1 lg:max-h-[calc(100vh-15rem)] lg:w-80 lg:shrink-0 lg:flex-col lg:overflow-y-auto lg:pb-0"
    >
      {incidents.map((inc) => {
        const sev = severityStyle(inc.severity);
        const selected = inc.id === selectedId;
        return (
          <button
            key={inc.id}
            type="button"
            onClick={() => onSelect(inc.id)}
            aria-current={selected ? "true" : undefined}
            className={cn(
              "group flex min-h-16 w-64 shrink-0 items-center gap-3 rounded-xl border p-3 text-left transition-colors lg:w-full",
              selected
                ? "border-emerald-500/50 bg-emerald-500/10"
                : "border-border bg-card/60 hover:border-emerald-500/30 hover:bg-card"
            )}
          >
            <span className="relative flex size-2.5 shrink-0" aria-hidden="true">
              {inc.severity === "Critical" && (
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-60" />
              )}
              <span className={cn("relative inline-flex size-2.5 rounded-full", sev.dot)} />
            </span>
            <span className="min-w-0 flex-1">
              <span className="flex items-center gap-2">
                <span className="font-mono text-xs font-semibold text-emerald-300/90">{inc.incidentId}</span>
                <span className={cn("ml-auto font-mono text-xs font-bold tabular-nums", scoreTextClass(inc.threatScore))}>
                  {inc.threatScore}
                </span>
              </span>
              <span className="mt-0.5 block truncate text-xs text-foreground/85" title={inc.title}>
                {inc.title}
              </span>
            </span>
          </button>
        );
      })}
    </nav>
  );
}

function IncidentListSkeleton() {
  return (
    <div className="flex w-full flex-col gap-2 lg:w-80 lg:shrink-0" aria-busy="true">
      {Array.from({ length: 5 }).map((_, i) => (
        <Skeleton key={i} className="h-16 rounded-xl" />
      ))}
    </div>
  );
}

// ------------------------------------------------------------------
// Score panel
// ----------------------------------------------------------------------

function ScorePanel({ incident }: { incident: IncidentDetailDTO }) {
  return (
    <Card className="rounded-xl">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          <Target className="size-4 text-emerald-400" aria-hidden="true" />
          Threat Score
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col items-center gap-5 sm:flex-row sm:items-start">
        <ScoreGauge score={incident.threatScore} />
        <div className="min-w-0 flex-1 space-y-4">
          <div>
            <div className="mb-1 flex items-center justify-between text-xs">
              <span className="uppercase tracking-wider text-muted-foreground">Confidence</span>
              <span className="font-mono font-semibold tabular-nums text-foreground/90">
                {incident.confidence}%
              </span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-white/8">
              <motion.div
                className="h-full rounded-full bg-emerald-400"
                initial={{ width: 0 }}
                animate={{ width: `${incident.confidence}%` }}
                transition={{ duration: 0.8, ease: "easeOut" }}
              />
            </div>
          </div>
          <div>
            <p className="mb-2 text-xs uppercase tracking-wider text-muted-foreground">
              Risk signals
            </p>
            {incident.riskSignals.length === 0 ? (
              <p className="text-xs text-muted-foreground">No deterministic risk signals recorded.</p>
            ) : (
              <ul className="flex flex-wrap gap-1.5">
                {incident.riskSignals.map((rs, i) => (
                  <li
                    key={`${rs.signal}-${i}`}
                    className={cn(
                      "inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs",
                      rs.points >= 15
                        ? "border-red-500/30 bg-red-500/10 text-red-300"
                        : rs.points >= 8
                          ? "border-amber-500/30 bg-amber-500/10 text-amber-300"
                          : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                    )}
                  >
                    <span className="font-mono font-bold tabular-nums">+{rs.points}</span>
                    {rs.signal}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ------------------------------------------------------------------
// Attack timeline
// ----------------------------------------------------------------------

function AttackTimeline({ incident }: { incident: IncidentDetailDTO }) {
  const alerts = incident.alerts ?? [];
  return (
    <Card className="rounded-xl">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          <Radar className="size-4 text-emerald-400" aria-hidden="true" />
          Attack Timeline
        </CardTitle>
        <CardDescription className="text-xs">
          {alerts.length} correlated alert{alerts.length === 1 ? "" : "s"}, chronological
        </CardDescription>
      </CardHeader>
      <CardContent>
        {alerts.length === 0 ? (
          <p className="py-4 text-sm text-muted-foreground">No correlated alerts on record.</p>
        ) : (
          <ol className="soc-scroll relative max-h-96 space-y-5 overflow-y-auto border-l border-white/10 ml-3 pl-6 pr-2">
            {alerts.map((a) => {
              const sev = severityStyle(rawSeverityLabel(a.rawSeverity));
              return (
                <li key={a.id} className="relative">
                  <span
                    className={cn(
                      "absolute -left-[29px] top-1.5 size-2.5 rounded-full ring-4 ring-background",
                      sev.dot
                    )}
                    aria-hidden="true"
                  />
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <span className="font-mono text-xs text-muted-foreground" title={formatDateTime(a.timestamp)}>
                      {formatDateTime(a.timestamp)}
                      <span className="ml-2 text-[10px] text-muted-foreground/70">{timeAgo(a.timestamp)}</span>
                    </span>
                    <SourceChip source={a.source} sourceLabel={a.sourceLabel} />
                    <EventChip event={a.event} />
                  </div>
                  <p className="mt-1.5 text-sm leading-relaxed text-foreground/90">{a.description}</p>
                  <p className="mt-1 flex flex-wrap gap-x-3 font-mono text-[11px] text-muted-foreground">
                    {a.user && <span>user: {a.user}</span>}
                    {a.device && <span>device: {a.device}</span>}
                    {a.ip && <span>ip: {a.ip}</span>}
                    <span className="text-emerald-400/70">id: {a.alertId}</span>
                  </p>
                </li>
              );
            })}
          </ol>
        )}
      </CardContent>
    </Card>
  );
}

// ------------------------------------------------------------------
// MITRE mapping
// ----------------------------------------------------------------------

function MitrePanel({ incident }: { incident: IncidentDetailDTO }) {
  const techniques = incident.mitre ?? [];
  return (
    <Card className="rounded-xl">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          <Crosshair className="size-4 text-emerald-400" aria-hidden="true" />
          MITRE ATT&amp;CK Mapping
        </CardTitle>
      </CardHeader>
      <CardContent>
        {techniques.length === 0 ? (
          <p className="flex items-center gap-2 text-xs text-muted-foreground">
            <Sparkles className="size-3.5 text-amber-400" aria-hidden="true" />
            No techniques mapped yet — run AI analysis.
          </p>
        ) : (
          <ul className="flex flex-wrap gap-2">
            {techniques.map((t) => (
              <li
                key={t.id}
                title={`${t.id} — ${t.name} (${t.tactic})`}
                className="rounded-lg border border-border bg-muted/50 px-2.5 py-1.5"
              >
                <span className="block font-mono text-xs font-semibold text-emerald-300/90">
                  {t.id} · {t.name}
                </span>
                <span className="block text-[10px] uppercase tracking-wider text-muted-foreground">
                  {t.tactic}
                </span>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

// ------------------------------------------------------------------
// BLUF report
// ----------------------------------------------------------------------

/** Build the full plain-text incident report for download/export. */
function buildReportText(incident: IncidentDetailDTO): string {
  const rule = "-".repeat(72);
  const lines: string[] = [];
  lines.push("=".repeat(72));
  lines.push(`SENTINELAI INCIDENT REPORT — ${incident.incidentId}`);
  lines.push("=".repeat(72));
  lines.push(`Title          : ${incident.title}`);
  lines.push(`Severity       : ${incident.severity}`);
  lines.push(`Classification : ${incident.classification}`);
  lines.push(`Threat Score   : ${incident.threatScore}/100`);
  lines.push(`Confidence     : ${incident.confidence}%`);
  lines.push(`Status         : ${incident.status}`);
  lines.push(`Related Alerts : ${incident.alertCount} (${incident.sources.join(", ")})`);
  lines.push(`Generated      : ${new Date().toISOString()}`);
  lines.push("");
  lines.push(rule);
  lines.push("MITRE ATT&CK MAPPING");
  lines.push(rule);
  if (incident.mitre.length === 0) lines.push("(none mapped)");
  for (const t of incident.mitre) lines.push(`  ${t.id}  ${t.name} [${t.tactic}]`);
  lines.push("");
  lines.push(rule);
  lines.push("RISK SIGNALS");
  lines.push(rule);
  if (incident.riskSignals.length === 0) lines.push("(none)");
  for (const r of incident.riskSignals) lines.push(`  +${r.points}  ${r.signal}`);
  lines.push("");
  lines.push(rule);
  lines.push("BLUF — BOTTOM LINE UP FRONT");
  lines.push(rule);
  lines.push(incident.bluf ?? "");
  if (incident.explanation) {
    lines.push("");
    lines.push(rule);
    lines.push("ANALYST EXPLANATION");
    lines.push(rule);
    lines.push(incident.explanation);
  }
  if (incident.recommendedActions.length > 0) {
    lines.push("");
    lines.push(rule);
    lines.push("RECOMMENDED ACTIONS");
    lines.push(rule);
    incident.recommendedActions.forEach((a, i) => lines.push(`  ${i + 1}. ${a}`));
  }
  if (incident.evidence.length > 0) {
    lines.push("");
    lines.push(rule);
    lines.push("KEY EVIDENCE");
    lines.push(rule);
    for (const e of incident.evidence) lines.push(`  - ${e}`);
  }
  lines.push("");
  lines.push(rule);
  lines.push("RELATED ALERT TIMELINE");
  lines.push(rule);
  for (const a of incident.alerts) {
    lines.push(`  ${a.timestamp}  [${a.sourceLabel}]  ${a.event}  (${a.alertId})`);
    lines.push(`    ${a.description}`);
  }
  lines.push("");
  lines.push("SentinelAI — simulated demo data, not for operational use.");
  return lines.join("\n");
}

function BlufReport({ incident }: { incident: IncidentDetailDTO }) {
  const [copied, setCopied] = useState(false);
  const [pdfBusy, setPdfBusy] = useState(false);
  if (!incident.bluf) return null;

  const copyBluf = async () => {
    try {
      await navigator.clipboard.writeText(incident.bluf ?? "");
      setCopied(true);
      toast.success("BLUF summary copied to clipboard");
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error("Clipboard unavailable in this browser");
    }
  };

  const downloadReport = () => {
    const blob = new Blob([buildReportText(incident)], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `SentinelAI-report-${incident.incidentId}.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast.success(`Full report downloaded (${incident.incidentId})`);
  };

  const downloadPdf = async () => {
    if (pdfBusy) return;
    setPdfBusy(true);
    toast.info(`Building PDF report for ${incident.incidentId}…`);
    try {
      // dynamic import keeps jsPDF out of the initial bundle
      const { downloadIncidentPdf } = await import("@/lib/report-pdf");
      await downloadIncidentPdf(incident);
      toast.success(`PDF report downloaded (${incident.incidentId})`);
    } catch (err) {
      toast.error("PDF export failed", {
        description: err instanceof Error ? err.message : "Unknown error",
      });
    } finally {
      setPdfBusy(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      <Card className="overflow-hidden rounded-xl border-emerald-500/25 p-0">
        <div className="flex flex-wrap items-center gap-2 border-b border-emerald-500/25 bg-emerald-500/10 px-4 py-2.5">
          <FileText className="size-4 text-emerald-400" aria-hidden="true" />
          <span className="font-mono text-xs font-bold uppercase tracking-[0.2em] text-emerald-300">
            BLUF — Bottom Line Up Front
          </span>
          {incident.analyzed ? (
            <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-emerald-300">
              <Sparkles className="size-3" aria-hidden="true" /> AI Analyst Report
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-amber-300">
              <ShieldAlert className="size-3" aria-hidden="true" /> Deterministic Baseline
            </span>
          )}
          <span className="ml-auto flex items-center gap-1.5">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => void copyBluf()}
              className="min-h-8 gap-1.5 border-emerald-500/40 bg-transparent px-2.5 font-mono text-[11px] font-semibold text-emerald-300 hover:bg-emerald-500/15 hover:text-emerald-200"
              aria-label="Copy BLUF summary to clipboard"
            >
              {copied ? <CheckCircle2 className="size-3.5" aria-hidden="true" /> : <Copy className="size-3.5" aria-hidden="true" />}
              {copied ? "Copied" : "Copy BLUF"}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={downloadReport}
              className="min-h-8 gap-1.5 border-emerald-500/40 bg-transparent px-2.5 font-mono text-[11px] font-semibold text-emerald-300 hover:bg-emerald-500/15 hover:text-emerald-200"
              aria-label="Download full incident report as text file"
            >
              <Download className="size-3.5" aria-hidden="true" />
              Report .txt
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => void downloadPdf()}
              disabled={pdfBusy}
              className="min-h-8 gap-1.5 border-emerald-500/40 bg-transparent px-2.5 font-mono text-[11px] font-semibold text-emerald-300 hover:bg-emerald-500/15 hover:text-emerald-200"
              aria-label="Download full incident report as PDF"
            >
              {pdfBusy ? (
                <Loader2 className="size-3.5 animate-spin" aria-hidden="true" />
              ) : (
                <FileDown className="size-3.5" aria-hidden="true" />
              )}
              {pdfBusy ? "Building…" : "Report .pdf"}
            </Button>
          </span>
        </div>
        <CardContent className="space-y-5 p-4 sm:p-6">
          <p className="whitespace-pre-wrap font-mono text-sm leading-relaxed text-foreground/90">
            {incident.bluf}
          </p>

          {incident.recommendedActions.length > 0 && (
            <div>
              <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Recommended Actions
              </p>
              <ol className="space-y-2">
                {incident.recommendedActions.map((action, i) => (
                  <li key={i} className="flex items-start gap-2.5 text-sm">
                    <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded border border-emerald-500/40 bg-emerald-500/10 font-mono text-[10px] font-bold text-emerald-300">
                      {i + 1}
                    </span>
                    <span className="leading-relaxed text-foreground/90">{action}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}

          {incident.evidence.length > 0 && (
            <div>
              <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Evidence
              </p>
              <ul className="space-y-1.5">
                {incident.evidence.map((ev, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs leading-relaxed text-muted-foreground">
                    <Crosshair className="mt-0.5 size-3 shrink-0 text-emerald-500/70" aria-hidden="true" />
                    <span>{ev}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ------------------------------------------------------------------
// Detail pane
// ----------------------------------------------------------------------

function DetailPane({ incidentId }: { incidentId: string }) {
  const queryClient = useQueryClient();

  const detailQuery = useQuery({
    queryKey: ["incident", incidentId],
    queryFn: async () => {
      const d = await apiGet<{ incident: IncidentDetailDTO }>(`/api/incidents/${incidentId}`);
      return d.incident;
    },
    enabled: Boolean(incidentId),
  });

  const [analyzeLine, setAnalyzeLine] = useState(0);
  const [noteText, setNoteText] = useState("");
  const analyzeMutation = useMutation({
    mutationFn: () => apiSend(`/api/incidents/${incidentId}/analyze`, "POST"),
    onSuccess: (data: unknown) => {
      let msg = "AI analysis complete — BLUF report ready.";
      if (data && typeof data === "object" && "message" in data) {
        const m = (data as { message: unknown }).message;
        if (typeof m === "string") msg = m;
      }
      toast.success("Analysis complete", { description: msg });
      queryClient.invalidateQueries({ queryKey: ["incident", incidentId] });
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard-summary"] });
    },
    onError: (err: Error) => {
      toast.error("AI analysis failed", { description: err.message });
    },
  });

  useEffect(() => {
    if (!analyzeMutation.isPending) return;
    const t = setInterval(
      () => setAnalyzeLine((i) => (i + 1) % ANALYZE_LINES.length),
      2500
    );
    return () => clearInterval(t);
  }, [analyzeMutation.isPending]);

  const updateMutation = useMutation({
    mutationFn: (payload: IncidentUpdatePayload) =>
      apiSend<unknown>(`/api/incidents/${incidentId}`, "PATCH", payload),
    onSuccess: (_data, variables) => {
      const what = variables.status
        ? `Status set to ${variables.status}`
        : variables.classification
          ? `Classification set to ${variables.classification}`
          : variables.analystNote
            ? "Analyst note saved"
            : "Incident updated";
      toast.success(what, { description: "Analyst feedback recorded." });
      queryClient.invalidateQueries({ queryKey: ["incident", incidentId] });
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard-summary"] });
      if (variables.analystNote) setNoteText("");
    },
    onError: (err: Error) => {
      toast.error("Update failed", { description: err.message });
    },
  });

  if (detailQuery.isLoading) {
    return (
      <div className="flex flex-col gap-4 sm:gap-6" aria-busy="true" aria-label="Loading incident detail">
        <Skeleton className="h-36 rounded-xl" />
        <Skeleton className="h-52 rounded-xl" />
        <Skeleton className="h-64 rounded-xl" />
      </div>
    );
  }
  if (detailQuery.isError) {
    return (
      <ErrorState
        message={detailQuery.error instanceof Error ? detailQuery.error.message : undefined}
        onRetry={() => detailQuery.refetch()}
      />
    );
  }
  const incident = detailQuery.data;
  if (!incident) return null;

  return (
    <div className="flex min-w-0 flex-col gap-4 sm:gap-6">
      {/* Header */}
      <motion.div
        key={incident.id}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35 }}
      >
        <Card className="rounded-xl p-4 sm:p-6">
          <div className="flex flex-col gap-4">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={incident.severity} />
              <ClassificationBadge classification={incident.classification} />
              <StatusBadge status={incident.status} />
              <span className="ml-auto font-mono text-sm font-bold text-emerald-300/90">
                {incident.incidentId}
              </span>
            </div>
            <div>
              <h2 className="text-lg font-bold leading-snug tracking-tight sm:text-xl">
                {incident.title}
              </h2>
              <p className="mt-1 text-xs text-muted-foreground">
                {incident.alertCount} related alert{incident.alertCount === 1 ? "" : "s"}
                {" · "}
                {incident.sources.join(", ") || "single source"}
                {" · "}
                created {timeAgo(incident.createdAt)}
              </p>
            </div>

            {/* Actions */}
            <div className="flex flex-wrap items-center gap-2 border-t border-border/70 pt-4">
              <Button
                type="button"
                onClick={() => {
                  setAnalyzeLine(0);
                  analyzeMutation.mutate();
                }}
                disabled={analyzeMutation.isPending}
                className="min-h-11 gap-2 border-emerald-500/50 bg-emerald-500/15 font-semibold text-emerald-300 hover:bg-emerald-500/25 hover:text-emerald-200"
                aria-label="Run AI analysis on this incident"
              >
                {analyzeMutation.isPending ? (
                  <Loader2 className="size-4 animate-spin" aria-hidden="true" />
                ) : (
                  <Sparkles className="size-4" aria-hidden="true" />
                )}
                {analyzeMutation.isPending ? (
                  <span className="font-mono text-xs">{ANALYZE_LINES[analyzeLine]}</span>
                ) : (
                  "Run AI Analysis"
                )}
              </Button>

              <div className="flex items-center gap-2">
                <label htmlFor="workflow-status" className="sr-only">Incident status</label>
                <Select
                  value={incident.status}
                  onValueChange={(v) =>
                    updateMutation.mutate({ status: v as IncidentStatus })
                  }
                  disabled={updateMutation.isPending}
                >
                  <SelectTrigger id="workflow-status" className="min-h-11 w-40" aria-label="Set incident status">
                    <SelectValue placeholder="Status" />
                  </SelectTrigger>
                  <SelectContent>
                    {STATUSES.map((s) => (
                      <SelectItem key={s} value={s}>
                        {s}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="ml-auto flex items-center gap-1.5">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="min-h-11 gap-1.5 border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10 hover:text-emerald-200"
                  disabled={updateMutation.isPending}
                  onClick={() =>
                    updateMutation.mutate({ classification: "Genuine Threat" as Classification })
                  }
                  aria-label="Confirm this incident as a genuine threat"
                >
                  <ThumbsUp className="size-3.5" aria-hidden="true" />
                  Confirm Threat
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="min-h-11 gap-1.5 border-slate-500/40 text-slate-300 hover:bg-slate-500/10 hover:text-slate-200"
                  disabled={updateMutation.isPending}
                  onClick={() =>
                    updateMutation.mutate({ classification: "False Positive" as Classification })
                  }
                  aria-label="Mark this incident as a false positive"
                >
                  <ThumbsDown className="size-3.5" aria-hidden="true" />
                  Mark False Positive
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-11 shrink-0 text-muted-foreground"
                  aria-label="Dismiss feedback (no-op in demo)"
                  title="Dismiss — no-op in this demo"
                >
                  <X className="size-4" aria-hidden="true" />
                </Button>
              </div>
            </div>

            {/* Analyst note */}
            <div className="flex flex-col gap-2 border-t border-border/70 pt-4">
              <label
                htmlFor="analyst-note"
                className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground"
              >
                <NotebookPen className="size-3.5 text-emerald-400" aria-hidden="true" />
                Analyst Working Notes
              </label>
              <div className="flex flex-col gap-2 sm:flex-row">
                <textarea
                  id="analyst-note"
                  value={noteText}
                  onChange={(e) => setNoteText(e.target.value)}
                  rows={2}
                  maxLength={600}
                  placeholder="Record triage decisions, containment steps, escalation path… (appended to the incident record)"
                  className="soc-scroll min-h-11 flex-1 resize-y rounded-lg border border-input bg-background/60 px-3 py-2 text-xs text-foreground placeholder:text-muted-foreground/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  aria-label="Add an analyst note to this incident"
                />
                <div className="flex items-start gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="min-h-11 gap-1.5 border-emerald-500/40 px-3 text-emerald-300 hover:bg-emerald-500/10 hover:text-emerald-200"
                    disabled={updateMutation.isPending || noteText.trim().length === 0}
                    onClick={() => updateMutation.mutate({ analystNote: noteText.trim() })}
                    aria-label="Save analyst note"
                  >
                    {updateMutation.isPending ? (
                      <Loader2 className="size-3.5 animate-spin" aria-hidden="true" />
                    ) : (
                      <CheckCircle2 className="size-3.5" aria-hidden="true" />
                    )}
                    Save Note
                  </Button>
                  {noteText.length > 0 && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="min-h-11 px-2 text-muted-foreground"
                      onClick={() => setNoteText("")}
                      aria-label="Clear note draft"
                    >
                      Clear
                    </Button>
                  )}
                </div>
              </div>
              <p className="font-mono text-[10px] text-muted-foreground/70">
                {noteText.length}/600 characters · notes are timestamped and appended to the case file
              </p>
            </div>
          </div>
        </Card>
      </motion.div>

      {/* Unanalyzed ribbon */}
      {!incident.analyzed && (
        <div
          role="status"
          className="flex items-center gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-xs text-amber-300"
        >
          <Sparkles className="size-4 shrink-0" aria-hidden="true" />
          Deterministic scoring only — run AI Analysis for the full LLM investigation report.
        </div>
      )}

      <ScorePanel incident={incident} />

      <div className="grid grid-cols-1 gap-4 sm:gap-6 xl:grid-cols-2">
        <AttackTimeline incident={incident} />
        <div className="flex flex-col gap-4 sm:gap-6">
          <MitrePanel incident={incident} />
          {incident.explanation && (
            <Card className="rounded-xl">
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                  <ShieldCheck className="size-4 text-emerald-400" aria-hidden="true" />
                  Analyst Explanation
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="whitespace-pre-wrap text-sm leading-relaxed text-foreground/85">
                  {incident.explanation}
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      <BlufReport incident={incident} />
    </div>
  );
}

// ------------------------------------------------------------------
// Tab root
// ----------------------------------------------------------------------

export function IncidentAnalysis() {
  const selectedId = useSocStore((s) => s.selectedIncidentId);
  const selectIncident = useSocStore((s) => s.selectIncident);

  const listQuery = useQuery({
    queryKey: ["incidents"],
    queryFn: () => apiGet<unknown>("/api/incidents"),
    select: (d: unknown) => unwrapList<IncidentDTO>(d, "incidents"),
  });

  const incidents = listQuery.data ?? [];
  const activeId =
    selectedId && incidents.some((i) => i.id === selectedId)
      ? selectedId
      : (incidents[0]?.id ?? null);

  if (listQuery.isLoading) {
    return (
      <div className="flex flex-col gap-6 lg:flex-row" aria-busy="true">
        <IncidentListSkeleton />
        <div className="hidden min-w-0 flex-1 flex-col gap-4 lg:flex">
          <Skeleton className="h-36 rounded-xl" />
          <Skeleton className="h-52 rounded-xl" />
        </div>
      </div>
    );
  }
  if (listQuery.isError) {
    return (
      <ErrorState
        message={listQuery.error instanceof Error ? listQuery.error.message : undefined}
        onRetry={() => listQuery.refetch()}
      />
    );
  }
  if (incidents.length === 0 || !activeId) {
    return (
      <div className="flex flex-col items-center gap-3 rounded-xl border border-border bg-card/50 py-16 text-center">
        <CheckCircle2 className="size-8 text-emerald-400/70" aria-hidden="true" />
        <p className="text-sm font-medium">No incidents yet</p>
        <p className="max-w-sm text-xs leading-relaxed text-muted-foreground">
          Once alerts are ingested, SentinelAI correlates them into incidents and ranks
          them here. Load the demo dataset or import a raw feed to get started.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:gap-6">
      <IncidentList
        incidents={incidents}
        selectedId={activeId}
        onSelect={selectIncident}
      />
      <div className="min-w-0 flex-1">
        <DetailPane incidentId={activeId} />
      </div>
    </div>
  );
}
