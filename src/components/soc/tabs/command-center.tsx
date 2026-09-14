"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  Bot,
  CircleAlert,
  FileDown,
  FileText,
  Inbox,
  Send,
  ShieldAlert,
  Siren,
  Sparkles,
  TriangleAlert,
  CircleOff,
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  SeverityBadge,
  StatusBadge,
} from "@/components/soc/badges";
import { ThreatScoreBar } from "@/components/soc/threat-score";
import { EmptyHero } from "@/components/soc/empty-hero";
import { ErrorState } from "@/components/soc/error-state";
import { apiGet } from "@/lib/api-client";
import type { DashboardSummary, IncidentDTO } from "@/lib/types";
import {
  formatCount,
  severityStyle,
} from "@/lib/ui-helpers";
import { useSocStore } from "@/store/soc-store";
import { cn } from "@/lib/utils";

// ------------------------------------------------------------------
// helpers
// ------------------------------------------------------------------

function priorityOf(severity: string): { label: string; chip: string } {
  switch (severity) {
    case "Critical":
      return { label: "P1", chip: "border-red-500/40 bg-red-500/10 text-red-300" };
    case "High":
      return { label: "P2", chip: "border-amber-500/40 bg-amber-500/10 text-amber-300" };
    case "Medium":
      return { label: "P3", chip: "border-yellow-400/40 bg-yellow-400/10 text-yellow-300" };
    case "Low":
      return { label: "P4", chip: "border-emerald-400/40 bg-emerald-400/10 text-emerald-300" };
    default:
      return { label: "FP", chip: "border-slate-500/40 bg-slate-500/10 text-slate-300" };
  }
}

const fadeUp = {
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0 },
};

// ------------------------------------------------------------------
// KPI row
// ------------------------------------------------------------------

type KpiTone = {
  border: string;
  icon: string;
  value: string;
};

const KPI_TONES: Record<string, KpiTone> = {
  emerald: { border: "border-l-emerald-400", icon: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400", value: "text-foreground" },
  red: { border: "border-l-red-500", icon: "border-red-500/30 bg-red-500/10 text-red-400", value: "text-red-300" },
  amber: { border: "border-l-amber-500", icon: "border-amber-500/30 bg-amber-500/10 text-amber-400", value: "text-amber-300" },
  yellow: { border: "border-l-yellow-400", icon: "border-yellow-400/30 bg-yellow-400/10 text-yellow-300", value: "text-yellow-300" },
  slate: { border: "border-l-slate-500", icon: "border-slate-500/30 bg-slate-500/10 text-slate-400", value: "text-slate-300" },
};

function KpiCard({
  icon: Icon,
  label,
  value,
  sub,
  tone,
  delay,
}: {
  icon: typeof Inbox;
  label: string;
  value: number;
  sub?: string;
  tone: keyof typeof KPI_TONES;
  delay: number;
}) {
  const t = KPI_TONES[tone];
  return (
    <motion.div {...fadeUp} transition={{ duration: 0.35, delay }}>
      <Card className={cn("border-l-2 p-4 transition-colors hover:border-emerald-500/30 hover:bg-card/80", t.border)}>
        {/* header row: label + icon; value/sub get the full card width below (no truncation) */}
        <div className="flex items-start justify-between gap-2">
          <p className="whitespace-nowrap text-[10px] font-medium uppercase tracking-[0.08em] text-muted-foreground sm:text-[11px]">{label}</p>
          <span className={cn("flex size-9 shrink-0 items-center justify-center rounded-lg border", t.icon)}>
            <Icon className="size-4.5" aria-hidden="true" />
          </span>
        </div>
        <p className={cn("mt-0.5 font-mono text-3xl font-bold tabular-nums", t.value)}>
          {formatCount(value)}
        </p>
        {sub && <p className="mt-0.5 truncate text-[11px] text-muted-foreground" title={sub}>{sub}</p>}
      </Card>
    </motion.div>
  );
}

function KpiRow({ data }: { data: DashboardSummary }) {
  const c = data.counts;
  // alert-level counts (by raw severity roll-up) — sub-labels describe the card's own metric
  const sevCount = (name: string) =>
    data.alertsBySeverity.find((s) => s.severity === name)?.count ?? 0;
  return (
    <section aria-label="Key metrics" className="grid grid-cols-2 gap-3 sm:gap-4 md:grid-cols-3 xl:grid-cols-6">
      <KpiCard icon={Inbox} label="Total Alerts" value={data.totalAlerts} sub={`${data.correlatedAlerts} correlated`} tone="emerald" delay={0} />
      <KpiCard icon={Siren} label="Active Incidents" value={data.totalIncidents} sub={`${c.open} open`} tone="red" delay={0.05} />
      <KpiCard icon={ShieldAlert} label="Critical" value={c.critical} sub={`${sevCount("Critical")} critical alert${sevCount("Critical") === 1 ? "" : "s"}`} tone="red" delay={0.1} />
      <KpiCard icon={TriangleAlert} label="High" value={c.high} sub={`${sevCount("High")} high alert${sevCount("High") === 1 ? "" : "s"}`} tone="amber" delay={0.15} />
      <KpiCard icon={CircleAlert} label="Medium" value={c.medium} sub={`${sevCount("Medium")} medium alert${sevCount("Medium") === 1 ? "" : "s"}`} tone="yellow" delay={0.2} />
      <KpiCard icon={CircleOff} label="False Positives" value={c.falsePositive} sub={`${sevCount("False Positive")} FP alert${sevCount("False Positive") === 1 ? "" : "s"}`} tone="slate" delay={0.25} />
    </section>
  );
}

// ------------------------------------------------------------------
// Charts row
// ----------------------------------------------------------------------

const TOOLTIP_STYLE = {
  backgroundColor: "var(--popover)",
  border: "1px solid var(--border)",
  borderRadius: "10px",
  fontSize: "12px",
  color: "var(--popover-foreground)",
} as const;

function SeverityDonut({ data }: { data: DashboardSummary }) {
  const severityOrder = ["Critical", "High", "Medium", "Low", "False Positive"];
  const rows = severityOrder
    .map((sev) => ({
      severity: sev,
      count: data.alertsBySeverity.find((s) => s.severity === sev)?.count ?? 0,
    }))
    .filter((r) => r.count > 0);
  const hasData = rows.length > 0;

  return (
      <Card className="gap-3 rounded-xl">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          Alerts by Severity
        </CardTitle>
      </CardHeader>
      <CardContent>
        {hasData ? (
          <div className="relative h-56">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={rows}
                  dataKey="count"
                  nameKey="severity"
                  innerRadius="62%"
                  outerRadius="88%"
                  paddingAngle={3}
                  strokeWidth={0}
                >
                  {rows.map((row) => (
                    <Cell key={row.severity} fill={severityStyle(row.severity).hex} />
                  ))}
                </Pie>
                <Tooltip contentStyle={TOOLTIP_STYLE} itemStyle={{ color: "var(--popover-foreground)" }} />
              </PieChart>
            </ResponsiveContainer>
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
              <span className="font-mono text-3xl font-bold tabular-nums">{formatCount(data.totalAlerts)}</span>
              <span className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground">alerts</span>
            </div>
          </div>
        ) : (
          <div className="flex h-56 items-center justify-center text-sm text-muted-foreground">
            No alerts yet
          </div>
        )}
        <ul className="mt-3 flex flex-wrap justify-center gap-x-4 gap-y-1.5">
          {severityOrder.map((sev) => {
            const count = data.alertsBySeverity.find((s) => s.severity === sev)?.count ?? 0;
            const s = severityStyle(sev);
            return (
              <li key={sev} className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <span className={cn("size-2 rounded-full", s.dot)} aria-hidden="true" />
                {sev === "False Positive" ? "False Pos." : sev}
                <span className="font-mono tabular-nums text-foreground/80">{count}</span>
              </li>
            );
          })}
        </ul>
      </CardContent>
    </Card>
  );
}

function HourlyArea({ data }: { data: DashboardSummary }) {
  const rows = data.alertsByHour ?? [];
  return (
    <Card className="gap-3 rounded-xl">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          Alerts by Hour
        </CardTitle>
        <CardDescription className="text-xs">Ingestion volume across the last 12 hours</CardDescription>
      </CardHeader>
      <CardContent>
        {rows.length > 0 ? (
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
                <defs>
                  <linearGradient id="hourFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#34d399" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#34d399" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="oklch(1 0 0 / 6%)" vertical={false} />
                <XAxis
                  dataKey="hour"
                  tick={{ fill: "oklch(0.68 0.012 240)", fontSize: 10 }}
                  tickLine={false}
                  axisLine={{ stroke: "oklch(1 0 0 / 10%)" }}
                  minTickGap={22}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fill: "oklch(0.68 0.012 240)", fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip contentStyle={TOOLTIP_STYLE} itemStyle={{ color: "var(--popover-foreground)" }} />
                <Area
                  type="monotone"
                  dataKey="count"
                  name="Alerts"
                  stroke="#34d399"
                  strokeWidth={2}
                  fill="url(#hourFill)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="flex h-56 items-center justify-center text-sm text-muted-foreground">
            No hourly data yet
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function SourceBars({ data }: { data: DashboardSummary }) {
  const rows = [...(data.alertsBySource ?? [])].sort((a, b) => b.count - a.count);
  const max = rows.reduce((m, r) => Math.max(m, r.count), 1);
  return (
    <Card className="gap-3 rounded-xl">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          Alerts by Source
        </CardTitle>
        <CardDescription className="text-xs">Sensor coverage across the estate</CardDescription>
      </CardHeader>
      <CardContent>
        {rows.length > 0 ? (
          <ul className="flex flex-col gap-3">
            {rows.slice(0, 7).map((r) => (
              <li key={r.source} className="flex items-center gap-3">
                <span className="w-24 shrink-0 truncate text-xs text-foreground/85" title={r.sourceLabel}>
                  {r.sourceLabel}
                </span>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-white/8">
                  <motion.div
                    className="h-full rounded-full bg-emerald-400/80"
                    initial={{ width: 0 }}
                    animate={{ width: `${Math.max(6, (r.count / max) * 100)}%` }}
                    transition={{ duration: 0.7, ease: "easeOut" }}
                  />
                </div>
                <span className="w-8 shrink-0 text-right font-mono text-xs tabular-nums text-muted-foreground">
                  {r.count}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="py-8 text-center text-sm text-muted-foreground">No source data yet</p>
        )}
      </CardContent>
    </Card>
  );
}

function ChartsRow({ data }: { data: DashboardSummary }) {
  return (
    <section aria-label="Charts" className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3 sm:gap-6">
      <motion.div {...fadeUp} transition={{ duration: 0.4, delay: 0.1 }} className="min-w-0">
        <SeverityDonut data={data} />
      </motion.div>
      <motion.div {...fadeUp} transition={{ duration: 0.4, delay: 0.15 }} className="min-w-0">
        <HourlyArea data={data} />
      </motion.div>
      <motion.div {...fadeUp} transition={{ duration: 0.4, delay: 0.2 }} className="min-w-0 md:col-span-2 xl:col-span-1">
        <SourceBars data={data} />
      </motion.div>
    </section>
  );
}

// ------------------------------------------------------------------
// Ranked incident table
// ----------------------------------------------------------------------

function IncidentTable({ incidents }: { incidents: IncidentDTO[] }) {
  const openIncident = useSocStore((s) => s.openIncident);
  const [exporting, setExporting] = useState(false);
  const [exportingPdf, setExportingPdf] = useState(false);

  const fetchAllIncidents = async (): Promise<IncidentDTO[]> => {
    const all = await apiGet<unknown>("/api/incidents");
    return Array.isArray(all)
      ? (all as IncidentDTO[])
      : ((all as { incidents?: IncidentDTO[] }).incidents ?? []);
  };

  const exportBriefing = async () => {
    setExportingPdf(true);
    try {
      const list = await fetchAllIncidents();
      if (list.length === 0) {
        toast.info("Nothing to brief — no incidents yet.");
        return;
      }
      const summary = await apiGet<DashboardSummary>("/api/dashboard/summary");
      const { downloadBriefingPackPdf } = await import("@/lib/report-pdf");
      await downloadBriefingPackPdf(list, {
        totalAlerts: summary.totalAlerts,
        unacknowledgedAlerts: summary.counts.unacknowledgedAlerts,
      });
      toast.success(`Briefing pack exported — ${list.length} incidents`);
    } catch (err) {
      toast.error("Briefing export failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    } finally {
      setExportingPdf(false);
    }
  };

  const exportCsv = async () => {
    setExporting(true);
    try {
      const list = await fetchAllIncidents();
      if (list.length === 0) {
        toast.info("Nothing to export — no incidents yet.");
        return;
      }
      const esc = (v: unknown) => {
        const s = String(v ?? "");
        return /["\n,]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
      };
      const header = [
        "incident_id", "title", "severity", "classification", "threat_score",
        "confidence_pct", "status", "alert_count", "sources", "ai_analyzed",
        "created_at", "updated_at",
      ].join(",");
      const rows = list.map((i) =>
        [
          i.incidentId, i.title, i.severity, i.classification, i.threatScore,
          i.confidence, i.status, i.alertCount, i.sources.join("; "), i.analyzed ? "yes" : "no",
          i.createdAt, i.updatedAt,
        ].map(esc).join(",")
      );
      const blob = new Blob([[header, ...rows].join("\n")], { type: "text/csv;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `SentinelAI-incidents-${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast.success(`Exported ${list.length} incidents to CSV`);
    } catch (err) {
      toast.error("CSV export failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    } finally {
      setExporting(false);
    }
  };

  return (
    <motion.section {...fadeUp} transition={{ duration: 0.4, delay: 0.25 }} aria-label="Priority incidents">
      <Card className="gap-0 rounded-xl p-0">
        <CardHeader className="border-b border-border/70 py-4">
          <div className="flex items-center justify-between gap-2">
            <div>
              <CardTitle className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                <Siren className="size-4 text-red-400" aria-hidden="true" />
                Priority Incidents
              </CardTitle>
              <CardDescription className="mt-1 text-xs">
                Ranked by threat score — click a row to open the investigation view
              </CardDescription>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="min-h-9 gap-1.5 border-border text-xs text-muted-foreground hover:border-emerald-500/40 hover:text-emerald-300"
                onClick={() => void exportBriefing()}
                disabled={exportingPdf}
                aria-label="Export situation briefing pack as PDF"
              >
                <FileText className={exportingPdf ? "size-3.5 animate-pulse" : "size-3.5"} aria-hidden="true" />
                Briefing .pdf
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="min-h-9 gap-1.5 border-border text-xs text-muted-foreground hover:border-emerald-500/40 hover:text-emerald-300"
                onClick={() => void exportCsv()}
                disabled={exporting}
                aria-label="Export all incidents as CSV"
              >
                <FileDown className={exporting ? "size-3.5 animate-pulse" : "size-3.5"} aria-hidden="true" />
                Export CSV
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {incidents.length === 0 ? (
            <p className="py-10 text-center text-sm text-muted-foreground">
              No incidents correlated yet — alerts will be grouped automatically.
            </p>
          ) : (
            <div className="soc-scroll max-h-[520px] overflow-auto">
              <Table>
                <TableHeader className="sticky top-0 z-10 bg-card/95 backdrop-blur">
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="w-14 pl-4 text-[11px] uppercase tracking-wider">Prio</TableHead>
                    <TableHead className="text-[11px] uppercase tracking-wider">Incident</TableHead>
                    <TableHead className="min-w-44 text-[11px] uppercase tracking-wider">Title</TableHead>
                    <TableHead className="text-[11px] uppercase tracking-wider">Severity</TableHead>
                    <TableHead className="min-w-32 text-[11px] uppercase tracking-wider">Threat Score</TableHead>
                    <TableHead className="text-right text-[11px] uppercase tracking-wider">Conf.</TableHead>
                    <TableHead className="text-right text-[11px] uppercase tracking-wider">Alerts</TableHead>
                    <TableHead className="pr-4 text-[11px] uppercase tracking-wider">Status</TableHead>
                    <TableHead className="w-10 pr-3 text-[11px] uppercase tracking-wider">AI</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {incidents.map((inc) => {
                    const prio = priorityOf(inc.severity);
                    return (
                      <TableRow
                        key={inc.id}
                        tabIndex={0}
                        onClick={() => openIncident(inc.id)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            openIncident(inc.id);
                          }
                        }}
                        className={cn(
                          "min-h-11 cursor-pointer border-white/5 transition-colors hover:bg-emerald-500/5 focus-visible:bg-emerald-500/10 focus-visible:outline-none",
                          inc.severity === "Critical" && "bg-red-500/[0.045] hover:bg-red-500/10"
                        )}
                        aria-label={`Open incident ${inc.incidentId}: ${inc.title}`}
                      >
                        <TableCell className="pl-4">
                          <span className="flex items-center gap-1.5">
                            {inc.severity === "Critical" && (
                              <span className="relative flex size-1.5 shrink-0" aria-hidden="true">
                                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-70" />
                                <span className="relative inline-flex size-1.5 rounded-full bg-red-500" />
                              </span>
                            )}
                            <span className={cn("inline-flex size-7 items-center justify-center rounded-md border font-mono text-[11px] font-bold", prio.chip)}>
                              {prio.label}
                            </span>
                          </span>
                        </TableCell>
                        <TableCell className="font-mono text-xs font-semibold text-emerald-300/90">
                          {inc.incidentId}
                        </TableCell>
                        <TableCell className="max-w-72">
                          <span className="block truncate text-sm" title={inc.title}>
                            {inc.title}
                          </span>
                        </TableCell>
                        <TableCell>
                          <SeverityBadge severity={inc.severity} />
                        </TableCell>
                        <TableCell>
                          <ThreatScoreBar score={inc.threatScore} />
                        </TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums text-muted-foreground">
                          {inc.confidence}%
                        </TableCell>
                        <TableCell className="pr-4 text-right font-mono text-xs tabular-nums">
                          {inc.alertCount}
                        </TableCell>
                        <TableCell className="pr-4">
                          <StatusBadge status={inc.status} />
                        </TableCell>
                        <TableCell className="pr-3">
                          {inc.analyzed ? (
                            <Sparkles className="size-4 text-emerald-400" aria-label="AI analysis complete" />
                          ) : (
                            <span className="block text-center text-muted-foreground/40" aria-label="Not analyzed">—</span>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.section>
  );
}

// ------------------------------------------------------------------
// AI Copilot mini panel (xl+)
// ----------------------------------------------------------------------

function CopilotMiniPanel() {
  const askQuestion = useSocStore((s) => s.askQuestion);
  const top = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: () => apiGet<DashboardSummary>("/api/dashboard/summary"),
    refetchInterval: 15_000,
    select: (d: DashboardSummary) => d.topIncidents[0],
  }).data;

  const questions = [
    "What is the highest-risk threat right now?",
    top ? `Why is ${top.incidentId} critical?` : "Why is the top incident critical?",
    "What should we investigate first?",
  ];

  return (
    <motion.aside
      {...fadeUp}
      transition={{ duration: 0.4, delay: 0.3 }}
      className="hidden w-80 shrink-0 xl:block"
      aria-label="AI Copilot quick actions"
    >
      <Card className="sticky top-24 rounded-xl border-emerald-500/20">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm font-semibold">
            <span className="flex size-8 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10">
              <Bot className="size-4 text-emerald-400" aria-hidden="true" />
            </span>
            AI Copilot
          </CardTitle>
          <CardDescription className="text-xs">
            Ask about the current threat landscape — answers are grounded in live incident data.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {questions.map((q) => (
            <button
              key={q}
              type="button"
              onClick={() => askQuestion(q)}
              className="group flex min-h-11 items-center justify-between gap-2 rounded-lg border border-border bg-muted/40 px-3 py-2 text-left text-xs leading-snug text-foreground/85 transition-colors hover:border-emerald-500/40 hover:bg-emerald-500/5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              aria-label={`Ask copilot: ${q}`}
            >
              <span>{q}</span>
              <Send className="size-3.5 shrink-0 text-muted-foreground transition-colors group-hover:text-emerald-400" aria-hidden="true" />
            </button>
          ))}
        </CardContent>
      </Card>
    </motion.aside>
  );
}

// ------------------------------------------------------------------
// Skeletons
// ----------------------------------------------------------------------

function CommandCenterSkeleton() {
  return (
    <div className="flex flex-col gap-4 sm:gap-6" aria-busy="true" aria-label="Loading dashboard">
      <div className="grid grid-cols-2 gap-3 sm:gap-4 md:grid-cols-3 xl:grid-cols-6">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-24 rounded-xl" />
        ))}
      </div>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3 sm:gap-6">
        <Skeleton className="h-72 rounded-xl" />
        <Skeleton className="h-72 rounded-xl" />
        <Skeleton className="h-72 rounded-xl" />
      </div>
      <Skeleton className="h-96 rounded-xl" />
    </div>
  );
}

// ------------------------------------------------------------------
// Tab root
// ----------------------------------------------------------------------

export function CommandCenter() {
  const query = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: () => apiGet<DashboardSummary>("/api/dashboard/summary"),
    refetchInterval: 15_000,
  });

  if (query.isLoading) return <CommandCenterSkeleton />;
  if (query.isError) {
    return (
      <ErrorState
        message={query.error instanceof Error ? query.error.message : undefined}
        onRetry={() => query.refetch()}
      />
    );
  }
  if (!query.data || query.data.totalAlerts === 0) {
    return <EmptyHero />;
  }

  return (
    <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:gap-6">
      <div className="flex min-w-0 flex-1 flex-col gap-4 sm:gap-6">
        <KpiRow data={query.data} />
        <ChartsRow data={query.data} />
        <IncidentTable incidents={query.data.topIncidents} />
      </div>
      <CopilotMiniPanel />
    </div>
  );
}
