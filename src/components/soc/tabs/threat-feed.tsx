"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { motion } from "framer-motion";
import {
  Download,
  FileUp,
  Paperclip,
  RotateCw,
  Search,
  Upload,
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  CorrelationChip,
  EventChip,
  RawSeverityBadge,
  SourceChip,
} from "@/components/soc/badges";
import { ErrorState } from "@/components/soc/error-state";
import { SeedButton } from "@/components/soc/seed-button";
import { apiGet, apiSend } from "@/lib/api-client";
import { DEMO_FEED_LABELS } from "@/lib/seed-data";
import type {
  AlertDTO,
  DashboardSummary,
  ImportPayload,
  ImportResult,
  IncidentDTO,
} from "@/lib/types";
import { formatDateTime, timeAgo, unwrapList } from "@/lib/ui-helpers";
import { cn } from "@/lib/utils";
import { useSocStore } from "@/store/soc-store";

type CorrelatedFilter = "all" | "correlated";

interface FeedFilters {
  search: string;
  source: string;
  severity: string;
  correlated: CorrelatedFilter;
}

const DEFAULT_FILTERS: FeedFilters = {
  search: "",
  source: "all",
  severity: "all",
  correlated: "all",
};

function buildAlertsUrl(filters: FeedFilters): string {
  const params = new URLSearchParams();
  if (filters.search.trim()) params.set("search", filters.search.trim());
  if (filters.source !== "all") params.set("source", filters.source);
  if (filters.severity !== "all") params.set("severity", filters.severity);
  if (filters.correlated === "correlated") params.set("correlated", "true");
  const qs = params.toString();
  return qs ? `/api/alerts?${qs}` : "/api/alerts";
}

// ------------------------------------------------------------------
// Import panel
// ----------------------------------------------------------------------

const MAX_IMPORT_BYTES = 2 * 1024 * 1024; // 2 MB guard rail

function guessFormatFromName(name: string): NonNullable<ImportPayload["format"]> | null {
  const ext = name.toLowerCase().split(".").pop() ?? "";
  if (ext === "json") return "json";
  if (ext === "csv" || ext === "tsv") return "csv";
  if (ext === "txt" || ext === "log" || ext === "text") return "text";
  return null;
}

function ImportPanel() {
  const [raw, setRaw] = useState("");
  const [format, setFormat] = useState<NonNullable<ImportPayload["format"]>>("auto");
  const [fileName, setFileName] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (payload: ImportPayload) =>
      apiSend<ImportResult>("/api/alerts/import", "POST", payload),
    onSuccess: (data) => {
      queryClient.invalidateQueries();
      toast.success(`Imported ${data.imported} alerts · ${data.failed} failed`, {
        description: data.message || undefined,
      });
      setRaw("");
      setFileName(null);
      if (fileInputRef.current) fileInputRef.current.value = "";
    },
    onError: (err: Error) => {
      toast.error("Import failed", { description: err.message });
    },
  });

  const importPayload = (text: string, fmt: NonNullable<ImportPayload["format"]>) =>
    mutation.mutate({ raw: text, format: fmt });

  const loadFile = async (file: File) => {
    if (file.size > MAX_IMPORT_BYTES) {
      toast.error("File too large", { description: `${file.name} exceeds the 2 MB import limit.` });
      return;
    }
    try {
      const text = await file.text();
      setRaw(text);
      setFileName(file.name);
      const guessed = guessFormatFromName(file.name);
      if (guessed) setFormat(guessed);
      toast.success(`Loaded ${file.name}`, {
        description: `${(file.size / 1024).toFixed(1)} KB${guessed ? ` · format set to ${guessed.toUpperCase()}` : " · auto-detect will be used"}`,
      });
    } catch {
      toast.error("Could not read file", { description: file.name });
    }
  };

  const clearFile = () => {
    setRaw("");
    setFileName(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  return (
    <Card className="rounded-xl border-dashed">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          <Upload className="size-4 text-emerald-400" aria-hidden="true" />
          Import Raw Feed
        </CardTitle>
        <CardDescription className="text-xs">
          Upload a file (CSV, JSON or text log), drag &amp; drop it below, or paste a raw feed. The
          normalizer auto-detects the schema and ingests each record.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {/* hidden file input + picker row */}
        <input
          ref={fileInputRef}
          type="file"
          accept=".csv,.tsv,.json,.txt,.log,text/csv,application/json,text/plain"
          className="sr-only"
          aria-label="Choose a feed file to import"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void loadFile(f);
          }}
        />
        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="min-h-9 gap-2 border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10 hover:text-emerald-200"
            onClick={() => fileInputRef.current?.click()}
            aria-label="Choose feed file"
          >
            <FileUp className="size-3.5" aria-hidden="true" />
            Choose file
          </Button>
          {fileName && (
            <span className="inline-flex max-w-full items-center gap-1.5 rounded-lg border border-border bg-muted/50 px-2.5 py-1.5 font-mono text-[11px] text-foreground/85">
              <Paperclip className="size-3 shrink-0 text-emerald-400" aria-hidden="true" />
              <span className="max-w-48 truncate">{fileName}</span>
              <button
                type="button"
                onClick={clearFile}
                className="ml-0.5 rounded p-0.5 text-muted-foreground transition-colors hover:bg-white/10 hover:text-foreground"
                aria-label={`Remove file ${fileName}`}
              >
                <X className="size-3" aria-hidden="true" />
              </button>
            </span>
          )}
          <div className="ml-auto">
            <Label htmlFor="import-format" className="sr-only">
              Feed format
            </Label>
            <Select
              value={format}
              onValueChange={(v) => setFormat(v as NonNullable<ImportPayload["format"]>)}
            >
              <SelectTrigger id="import-format" className="w-full sm:w-44" aria-label="Import format">
                <SelectValue placeholder="Format" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="auto">Auto-detect</SelectItem>
                <SelectItem value="json">JSON</SelectItem>
                <SelectItem value="csv">CSV</SelectItem>
                <SelectItem value="text">Plain text</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragOver(false);
            const f = e.dataTransfer.files?.[0];
            if (f) void loadFile(f);
          }}
          className={cn(
            "relative rounded-lg border border-dashed transition-colors",
            dragOver ? "border-emerald-400 bg-emerald-500/10" : "border-transparent"
          )}
        >
          {dragOver && (
            <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center rounded-lg bg-background/70 font-mono text-xs font-semibold uppercase tracking-widest text-emerald-300">
              Drop file to load
            </div>
          )}
          <Label htmlFor="import-raw" className="sr-only">
            Raw feed content
          </Label>
          <textarea
            id="import-raw"
            value={raw}
            onChange={(e) => {
              setRaw(e.target.value);
              setFileName(null);
            }}
            rows={5}
            placeholder={`{"alert_id":"A9999","source":"siem","timestamp":"...","user":"jdoe",...}\nalert_id,source,timestamp,user,device,ip,event,description,severity\n[SATCOM-7] 2025-01-01T00:00Z SEV:info GROUND-STATION-2 :: ...`}
            className="soc-scroll w-full resize-y rounded-lg border border-input bg-background/60 px-3 py-2 font-mono text-xs text-foreground placeholder:text-muted-foreground/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            aria-label="Raw feed content to import"
          />
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="max-w-md text-[11px] leading-relaxed text-muted-foreground">
            Supported demo feed types:{" "}
            {DEMO_FEED_LABELS.map((f) => f.label).join(" · ")}. Correlation re-runs
            automatically after import.
          </p>
          <Button
            type="button"
            size="sm"
            disabled={mutation.isPending || raw.trim().length === 0}
            onClick={() => importPayload(raw, format)}
            className="min-h-9 gap-2 border-emerald-500/40 bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25 hover:text-emerald-200"
            aria-label="Import pasted feed"
          >
            {mutation.isPending ? (
              <RotateCw className="size-3.5 animate-spin" aria-hidden="true" />
            ) : (
              <Download className="size-3.5" aria-hidden="true" />
            )}
            {mutation.isPending ? "Importing…" : "Import Feed"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ------------------------------------------------------------------
// Feed table
// ----------------------------------------------------------------------

function AlertRow({
  alert,
  incidentIdMap,
}: {
  alert: AlertDTO;
  incidentIdMap: Map<string, string>;
}) {
  const openIncident = useSocStore((s) => s.openIncident);
  const displayIncidentId = alert.incidentId
    ? incidentIdMap.get(alert.incidentId) ?? "View incident"
    : null;

  return (
    <TableRow className="border-white/5 hover:bg-emerald-500/5">
      <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground" title={formatDateTime(alert.timestamp)}>
        <span className="block text-foreground/80">{timeAgo(alert.timestamp)}</span>
        <span className="block text-[10px] text-muted-foreground/70">{formatDateTime(alert.timestamp)}</span>
      </TableCell>
      <TableCell className="whitespace-nowrap font-mono text-xs font-semibold text-foreground/85">
        {alert.alertId}
      </TableCell>
      <TableCell>
        <SourceChip source={alert.source} sourceLabel={alert.sourceLabel} />
      </TableCell>
      <TableCell className="font-mono text-[11px] leading-4 text-muted-foreground">
        {alert.user && <span className="block truncate" title={`user: ${alert.user}`}>u: {alert.user}</span>}
        {alert.device && <span className="block truncate" title={`device: ${alert.device}`}>d: {alert.device}</span>}
        {alert.ip && <span className="block truncate" title={`ip: ${alert.ip}`}>ip: {alert.ip}</span>}
        {!alert.user && !alert.device && !alert.ip && <span className="text-muted-foreground/50">—</span>}
      </TableCell>
      <TableCell>
        <EventChip event={alert.event} />
      </TableCell>
      <TableCell className="max-w-64">
        <span className="block truncate text-xs text-foreground/85" title={alert.description}>
          {alert.description}
        </span>
      </TableCell>
      <TableCell>
        <RawSeverityBadge raw={alert.rawSeverity} />
      </TableCell>
      <TableCell>
        <CorrelationChip
          incidentId={displayIncidentId}
          onClick={
            alert.incidentId ? () => openIncident(alert.incidentId as string) : undefined
          }
        />
      </TableCell>
    </TableRow>
  );
}

function FeedSkeleton() {
  return (
    <div className="flex flex-col gap-2 p-4" aria-busy="true" aria-label="Loading threat feed">
      {Array.from({ length: 8 }).map((_, i) => (
        <Skeleton key={i} className="h-11 rounded-lg" />
      ))}
    </div>
  );
}

// ------------------------------------------------------------------
// Tab root
// ----------------------------------------------------------------------

export function ThreatFeed() {
  const [filters, setFilters] = useState<FeedFilters>(DEFAULT_FILTERS);
  const [searchInput, setSearchInput] = useState("");
  const [showImport, setShowImport] = useState(false);

  // debounce search input into the applied filter
  useEffect(() => {
    const t = setTimeout(() => setFilters((f) => ({ ...f, search: searchInput })), 300);
    return () => clearTimeout(t);
  }, [searchInput]);

  const alertsQuery = useQuery({
    queryKey: ["alerts", filters],
    queryFn: () => apiGet<unknown>(buildAlertsUrl(filters)),
    select: (d: unknown) => unwrapList<AlertDTO>(d, "alerts"),
  });

  // summary is shared with Command Center (same key) — used for source options
  const summaryQuery = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: () => apiGet<DashboardSummary>("/api/dashboard/summary"),
    refetchInterval: 15_000,
  });

  const incidentsQuery = useQuery({
    queryKey: ["incidents"],
    queryFn: () => apiGet<unknown>("/api/incidents"),
    select: (d: unknown) => unwrapList<IncidentDTO>(d, "incidents"),
  });

  const incidentIdMap = useMemo(() => {
    const m = new Map<string, string>();
    for (const inc of incidentsQuery.data ?? []) m.set(inc.id, inc.incidentId);
    return m;
  }, [incidentsQuery.data]);

  const alerts = alertsQuery.data ?? [];

  return (
    <div className="flex flex-col gap-4 sm:gap-6">
      {/* Toolbar */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35 }}
      >
        <Card className="rounded-xl p-4">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
            <div className="relative min-w-0 flex-1">
              <Search
                className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
                aria-hidden="true"
              />
              <Input
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                placeholder="Search alerts — user, IP, event, description…"
                className="min-h-11 pl-9"
                aria-label="Search alerts"
              />
            </div>

            <div className="flex flex-wrap items-center gap-2.5">
              <Label htmlFor="filter-source" className="sr-only">Filter by source</Label>
              <Select
                value={filters.source}
                onValueChange={(v) => setFilters((f) => ({ ...f, source: v }))}
              >
                <SelectTrigger id="filter-source" className="min-h-11 w-full sm:w-40" aria-label="Filter by source">
                  <SelectValue placeholder="Source" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All sources</SelectItem>
                  {(summaryQuery.data?.alertsBySource ?? []).map((s) => (
                    <SelectItem key={s.source} value={s.source}>
                      {s.sourceLabel} ({s.count})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Label htmlFor="filter-severity" className="sr-only">Filter by severity</Label>
              <Select
                value={filters.severity}
                onValueChange={(v) => setFilters((f) => ({ ...f, severity: v }))}
              >
                <SelectTrigger id="filter-severity" className="min-h-11 w-full sm:w-36" aria-label="Filter by severity">
                  <SelectValue placeholder="Severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All severities</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="info">Info</SelectItem>
                </SelectContent>
              </Select>

              <div className="flex min-h-11 items-center gap-2 rounded-lg border border-input bg-background/40 px-3">
                <Switch
                  id="correlated-only"
                  checked={filters.correlated === "correlated"}
                  onCheckedChange={(checked) =>
                    setFilters((f) => ({
                      ...f,
                      correlated: checked ? "correlated" : "all",
                    }))
                  }
                  aria-label="Show correlated alerts only"
                />
                <Label htmlFor="correlated-only" className="cursor-pointer text-xs text-muted-foreground">
                  Correlated only
                </Label>
              </div>

              <Button
                variant="outline"
                size="icon"
                className="size-11 shrink-0"
                onClick={() => alertsQuery.refetch()}
                disabled={alertsQuery.isFetching}
                aria-label="Refresh feed"
              >
                <RotateCw className={alertsQuery.isFetching ? "size-4 animate-spin" : "size-4"} />
              </Button>

              <SeedButton size="sm" className="min-h-11" />
            </div>
          </div>

          <div className="mt-3 flex items-center justify-between border-t border-border/60 pt-3 text-xs text-muted-foreground">
            <span aria-live="polite">
              {alertsQuery.isLoading
                ? "Loading feed…"
                : `${alerts.length} alert${alerts.length === 1 ? "" : "s"} in view`}
              {summaryQuery.data?.lastUpdated
                ? ` · newest ${timeAgo(summaryQuery.data.lastUpdated)}`
                : ""}
            </span>
            <button
              type="button"
              onClick={() => setShowImport((v) => !v)}
              className="inline-flex min-h-9 items-center gap-1.5 rounded-md px-2 font-medium text-emerald-400 transition-colors hover:text-emerald-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              aria-expanded={showImport}
              aria-controls="import-panel"
            >
              <Upload className="size-3.5" aria-hidden="true" />
              {showImport ? "Hide import panel" : "Import raw feed"}
            </button>
          </div>
        </Card>
      </motion.div>

      {/* Import panel (collapsible) */}
      {showImport && (
        <motion.div
          id="import-panel"
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: "auto" }}
          transition={{ duration: 0.3 }}
          className="overflow-hidden"
        >
          <ImportPanel />
        </motion.div>
      )}

      {/* Feed table */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, delay: 0.08 }}
      >
        <Card className="rounded-xl p-0">
          {alertsQuery.isLoading ? (
            <FeedSkeleton />
          ) : alertsQuery.isError ? (
            <div className="p-4">
              <ErrorState
                message={alertsQuery.error instanceof Error ? alertsQuery.error.message : undefined}
                onRetry={() => alertsQuery.refetch()}
              />
            </div>
          ) : alerts.length === 0 ? (
            <div className="flex flex-col items-center gap-2 py-14 text-center">
              <Search className="size-6 text-muted-foreground/60" aria-hidden="true" />
              <p className="text-sm font-medium">No alerts match your filters</p>
              <p className="max-w-sm text-xs text-muted-foreground">
                Try clearing the search box, widening the severity filter, or load the
                demo dataset to populate the feed.
              </p>
              <Button
                variant="outline"
                size="sm"
                className="mt-1 min-h-9"
                onClick={() => {
                  setSearchInput("");
                  setFilters(DEFAULT_FILTERS);
                }}
              >
                Clear filters
              </Button>
            </div>
          ) : (
            <div className="soc-scroll max-h-[620px] overflow-auto">
              <Table>
                <TableHeader className="sticky top-0 z-10 bg-card/95 backdrop-blur">
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="pl-4 text-[11px] uppercase tracking-wider">Time</TableHead>
                    <TableHead className="text-[11px] uppercase tracking-wider">Alert ID</TableHead>
                    <TableHead className="text-[11px] uppercase tracking-wider">Source</TableHead>
                    <TableHead className="text-[11px] uppercase tracking-wider">Entity</TableHead>
                    <TableHead className="text-[11px] uppercase tracking-wider">Event</TableHead>
                    <TableHead className="text-[11px] uppercase tracking-wider">Description</TableHead>
                    <TableHead className="text-[11px] uppercase tracking-wider">Raw Sev.</TableHead>
                    <TableHead className="pr-4 text-[11px] uppercase tracking-wider">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {alerts.map((a) => (
                    <AlertRow key={a.id} alert={a} incidentIdMap={incidentIdMap} />
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </Card>
      </motion.div>
    </div>
  );
}
