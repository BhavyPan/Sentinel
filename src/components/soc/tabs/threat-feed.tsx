"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { motion } from "framer-motion";
import {
  Bookmark,
  BookmarkPlus,
  Check,
  CheckCheck,
  Download,
  FileUp,
  ListChecks,
  Paperclip,
  RotateCw,
  Search,
  Trash2,
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
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
import { AlertDrawer } from "@/components/soc/alert-drawer";
import { ErrorState } from "@/components/soc/error-state";
import { SeedButton } from "@/components/soc/seed-button";
import { apiGet, apiSend } from "@/lib/api-client";
import { DEMO_FEED_LABELS } from "@/lib/seed-data";
import type {
  AlertDTO,
  AlertUpdateResult,
  BulkAckPayload,
  BulkAckResult,
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
  hideAck: boolean;
}

const DEFAULT_FILTERS: FeedFilters = {
  search: "",
  source: "all",
  severity: "all",
  correlated: "all",
  hideAck: false,
};

function buildAlertsUrl(filters: FeedFilters): string {
  const params = new URLSearchParams();
  if (filters.search.trim()) params.set("search", filters.search.trim());
  if (filters.source !== "all") params.set("source", filters.source);
  if (filters.severity !== "all") params.set("severity", filters.severity);
  if (filters.correlated === "correlated") params.set("correlated", "true");
  if (filters.hideAck) params.set("ack", "unack");
  const qs = params.toString();
  return qs ? `/api/alerts?${qs}` : "/api/alerts";
}

// ------------------------------------------------------------------
// Saved filter presets (localStorage)
// ----------------------------------------------------------------------

interface FeedPreset {
  id: string;
  name: string;
  filters: FeedFilters;
}

const PRESETS_KEY = "sentinelai.feedPresets";

function loadPresets(): FeedPreset[] {
  if (typeof window === "undefined") return []; // SSR guard
  try {
    const raw = localStorage.getItem(PRESETS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (p): p is FeedPreset =>
        typeof p === "object" && p !== null &&
        typeof (p as FeedPreset).id === "string" &&
        typeof (p as FeedPreset).name === "string" &&
        typeof (p as FeedPreset).filters === "object"
    );
  } catch {
    return [];
  }
}

function savePresets(presets: FeedPreset[]) {
  try {
    localStorage.setItem(PRESETS_KEY, JSON.stringify(presets));
  } catch {
    // storage full/blocked — presets just won't persist
  }
}

function filtersMatch(a: FeedFilters, b: FeedFilters): boolean {
  return (
    a.search === b.search &&
    a.source === b.source &&
    a.severity === b.severity &&
    a.correlated === b.correlated &&
    a.hideAck === b.hideAck
  );
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

/** Alerts newer than this get a pulsing "NEW" chip. */
const FRESH_MS = 120_000;

function AlertRow({
  alert,
  incidentIdMap,
  ackPending,
  onToggleAck,
  selected,
  onToggleSelect,
  onOpen,
}: {
  alert: AlertDTO;
  incidentIdMap: Map<string, string>;
  ackPending: boolean;
  onToggleAck: (alert: AlertDTO) => void;
  selected: boolean;
  onToggleSelect: (alert: AlertDTO) => void;
  onOpen: (alert: AlertDTO) => void;
}) {
  const openIncident = useSocStore((s) => s.openIncident);
  const displayIncidentId = alert.incidentId
    ? incidentIdMap.get(alert.incidentId) ?? "View incident"
    : null;
  const fresh = Date.now() - new Date(alert.timestamp).getTime() < FRESH_MS;

  return (
    <TableRow
      onClick={() => onOpen(alert)}
      className={cn(
        "cursor-pointer border-white/5 transition-opacity hover:bg-emerald-500/5",
        alert.acknowledged && "bg-muted/20 opacity-55 hover:opacity-80",
        selected && "bg-emerald-500/10 opacity-100"
      )}
      aria-selected={selected}
    >
      <TableCell
        className="pl-4 pr-1"
        onClick={(e) => e.stopPropagation()}
      >
        <Checkbox
          checked={selected}
          onCheckedChange={() => onToggleSelect(alert)}
          aria-label={`Select alert ${alert.alertId}`}
          className="size-4 border-muted-foreground/50 data-[state=checked]:border-emerald-500 data-[state=checked]:bg-emerald-500/80 data-[state=checked]:text-background"
        />
      </TableCell>
      <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground" title={formatDateTime(alert.timestamp)}>
        <span className="block text-foreground/80">{timeAgo(alert.timestamp)}</span>
        <span className="block text-[10px] text-muted-foreground/70">{formatDateTime(alert.timestamp)}</span>
      </TableCell>
      <TableCell className="whitespace-nowrap font-mono text-xs font-semibold text-foreground/85">
        <span className="flex items-center gap-1.5">
          {alert.alertId}
          {fresh && !alert.acknowledged && (
            <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/50 bg-emerald-500/15 px-1.5 py-px font-mono text-[9px] font-bold tracking-wider text-emerald-300">
              <span className="relative flex size-1.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-70" aria-hidden="true" />
                <span className="relative inline-flex size-1.5 rounded-full bg-emerald-400" aria-hidden="true" />
              </span>
              NEW
            </span>
          )}
          {alert.acknowledged && (
            <span className="rounded border border-emerald-500/40 bg-emerald-500/10 px-1 py-px font-mono text-[9px] font-bold tracking-wider text-emerald-400/90">
              ACK
            </span>
          )}
        </span>
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
        <span
          onClick={(e) => e.stopPropagation()}
          className="inline-flex"
        >
          <CorrelationChip
            incidentId={displayIncidentId}
            onClick={
              alert.incidentId ? () => openIncident(alert.incidentId as string) : undefined
            }
          />
        </span>
      </TableCell>
      <TableCell className="pr-3" onClick={(e) => e.stopPropagation()}>
        <button
          type="button"
          onClick={() => onToggleAck(alert)}
          disabled={ackPending}
          aria-pressed={alert.acknowledged}
          aria-label={
            alert.acknowledged
              ? `Clear acknowledgement for alert ${alert.alertId}`
              : `Acknowledge alert ${alert.alertId}`
          }
          title={
            alert.acknowledged
              ? `Acknowledged — click to clear`
              : `Mark ${alert.alertId} as reviewed`
          }
          className={cn(
            "inline-flex size-8 items-center justify-center rounded-lg border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
            alert.acknowledged
              ? "border-emerald-500/50 bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25"
              : "border-border bg-transparent text-muted-foreground hover:border-emerald-500/40 hover:bg-emerald-500/10 hover:text-emerald-300"
          )}
        >
          {ackPending ? (
            <RotateCw className="size-3.5 animate-spin" aria-hidden="true" />
          ) : alert.acknowledged ? (
            <CheckCheck className="size-4" aria-hidden="true" />
          ) : (
            <Check className="size-4" aria-hidden="true" />
          )}
        </button>
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
  const [presets, setPresets] = useState<FeedPreset[]>(() => loadPresets());
  const [presetDialogOpen, setPresetDialogOpen] = useState(false);
  const [presetName, setPresetName] = useState("");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [drawerAlertId, setDrawerAlertId] = useState<string | null>(null);
  const queryClient = useQueryClient();

  // track whether current filters match a saved preset (for the active chip)
  const activePreset = useMemo(
    () => presets.find((p) => filtersMatch(p.filters, filters)) ?? null,
    [presets, filters]
  );

  const applyPreset = (preset: FeedPreset) => {
    setFilters({ ...preset.filters });
    setSearchInput(preset.filters.search);
    toast.success(`Preset applied — ${preset.name}`);
  };

  const savePreset = () => {
    const name = presetName.trim();
    if (!name) return;
    // overwrite an existing preset with the same name
    const next: FeedPreset[] = [
      ...presets.filter((p) => p.name.toLowerCase() !== name.toLowerCase()),
      { id: `p-${Date.now().toString(36)}`, name, filters: { ...filters } },
    ];
    setPresets(next);
    savePresets(next);
    setPresetDialogOpen(false);
    setPresetName("");
    toast.success(`Preset "${name}" saved`, {
      description: "Stored locally in this browser.",
    });
  };

  const deletePreset = (preset: FeedPreset) => {
    const next = presets.filter((p) => p.id !== preset.id);
    setPresets(next);
    savePresets(next);
    toast.success(`Preset "${preset.name}" deleted`);
  };

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

  // ack triage toggle
  const ackMutation = useMutation({
    mutationFn: (alert: AlertDTO) =>
      apiSend<AlertUpdateResult>(`/api/alerts/${alert.id}`, "PATCH", {
        acknowledged: !alert.acknowledged,
      }),
    onSuccess: (data) => {
      queryClient.invalidateQueries();
      toast.success(data.message);
    },
    onError: (err: Error) => {
      toast.error("Could not update alert", { description: err.message });
    },
  });
  const pendingAckId = ackMutation.variables?.id;

  // bulk triage: acknowledge / clear a set of alerts in one call
  const bulkAckMutation = useMutation({
    mutationFn: (payload: BulkAckPayload) =>
      apiSend<BulkAckResult>("/api/alerts/bulk-ack", "POST", payload),
    onSuccess: (data) => {
      queryClient.invalidateQueries();
      toast.success(data.message, { description: "Bulk triage applied." });
      setSelectedIds(new Set());
    },
    onError: (err: Error) => {
      toast.error("Bulk acknowledge failed", { description: err.message });
    },
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

  // ---- selection helpers -------------------------------------------------
  const toggleSelect = (alert: AlertDTO) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(alert.id)) next.delete(alert.id);
      else next.add(alert.id);
      return next;
    });
  };

  const allVisibleSelected = alerts.length > 0 && alerts.every((a) => selectedIds.has(a.id));
  const someVisibleSelected = alerts.some((a) => selectedIds.has(a.id));

  const toggleSelectAll = () => {
    setSelectedIds((prev) => {
      if (allVisibleSelected) {
        const next = new Set(prev);
        for (const a of alerts) next.delete(a.id);
        return next;
      }
      return new Set([...prev, ...alerts.map((a) => a.id)]);
    });
  };

  const selectedAlerts = useMemo(
    () => alerts.filter((a) => selectedIds.has(a.id)),
    [alerts, selectedIds]
  );
  const bulkAllAcked = selectedAlerts.length > 0 && selectedAlerts.every((a) => a.acknowledged);

  const runBulkAck = () => {
    if (selectedIds.size === 0) return;
    bulkAckMutation.mutate({ ids: [...selectedIds], acknowledged: !bulkAllAcked });
  };

  // ---- alert drawer ------------------------------------------------------
  const drawerAlert = useMemo(
    () => (drawerAlertId ? alerts.find((a) => a.id === drawerAlertId) ?? null : null),
    [alerts, drawerAlertId]
  );
  const drawerIncidentLabel = drawerAlert?.incidentId
    ? incidentIdMap.get(drawerAlert.incidentId) ?? null
    : null;


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

              <div className="flex min-h-11 items-center gap-2 rounded-lg border border-input bg-background/40 px-3">
                <Switch
                  id="hide-acknowledged"
                  checked={filters.hideAck}
                  onCheckedChange={(checked) =>
                    setFilters((f) => ({ ...f, hideAck: checked }))
                  }
                  aria-label="Hide acknowledged alerts"
                />
                <Label htmlFor="hide-acknowledged" className="cursor-pointer text-xs text-muted-foreground">
                  Hide acked
                </Label>
              </div>

              {/* saved filter presets */}
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="outline"
                    size="icon"
                    className={cn(
                      "size-11 shrink-0",
                      activePreset && "border-emerald-500/50 bg-emerald-500/10 text-emerald-300"
                    )}
                    aria-label="Saved filter presets"
                  >
                    <Bookmark className="size-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-64">
                  <DropdownMenuLabel className="flex items-center justify-between">
                    Filter presets
                    {activePreset && (
                      <span className="rounded border border-emerald-500/40 bg-emerald-500/10 px-1.5 py-px font-mono text-[9px] font-bold uppercase tracking-wider text-emerald-300">
                        {activePreset.name}
                      </span>
                    )}
                  </DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    onSelect={(e) => {
                      e.preventDefault();
                      setPresetName("");
                      setPresetDialogOpen(true);
                    }}
                    className="gap-2 text-emerald-300 focus:text-emerald-200"
                  >
                    <BookmarkPlus className="size-4" aria-hidden="true" />
                    Save current filters…
                  </DropdownMenuItem>
                  {presets.length > 0 && <DropdownMenuSeparator />}
                  {presets.map((p) => (
                    <DropdownMenuItem
                      key={p.id}
                      onSelect={() => applyPreset(p)}
                      className="group gap-2"
                    >
                      <Bookmark className={cn("size-3.5 shrink-0", activePreset?.id === p.id ? "text-emerald-400" : "text-muted-foreground")} aria-hidden="true" />
                      <span className="min-w-0 flex-1 truncate">{p.name}</span>
                      <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
                        {[p.filters.source !== "all" && "src", p.filters.severity !== "all" && "sev", p.filters.correlated === "correlated" && "corr", p.filters.hideAck && "unacked", p.filters.search && "\"search\""].filter(Boolean).join(" · ") || "all"}
                      </span>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          deletePreset(p);
                        }}
                        aria-label={`Delete preset ${p.name}`}
                        className="shrink-0 rounded p-1 text-muted-foreground/60 opacity-0 transition-all hover:bg-red-500/15 hover:text-red-300 focus-visible:opacity-100 group-hover:opacity-100"
                      >
                        <Trash2 className="size-3.5" aria-hidden="true" />
                      </button>
                    </DropdownMenuItem>
                  ))}
                  {presets.length === 0 && (
                    <p className="px-2 py-1.5 text-[11px] leading-relaxed text-muted-foreground">
                      No presets yet — configure the filters above, then save them for one-click recall.
                    </p>
                  )}
                </DropdownMenuContent>
              </DropdownMenu>

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

          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-border/60 pt-3 text-xs text-muted-foreground">
            <span aria-live="polite" className="flex flex-wrap items-center gap-2">
              {alertsQuery.isLoading
                ? "Loading feed…"
                : `${alerts.length} alert${alerts.length === 1 ? "" : "s"} in view`}
              {summaryQuery.data?.lastUpdated
                ? ` · newest ${timeAgo(summaryQuery.data.lastUpdated)}`
                : ""}
              {typeof summaryQuery.data?.counts.unacknowledgedAlerts === "number" &&
                summaryQuery.data.counts.unacknowledgedAlerts > 0 && (
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-amber-300">
                    <Check className="size-3" aria-hidden="true" />
                    {summaryQuery.data.counts.unacknowledgedAlerts} awaiting triage
                  </span>
                )}
              {activePreset && (
                <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-emerald-300">
                  <Bookmark className="size-3" aria-hidden="true" />
                  {activePreset.name}
                </span>
              )}
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
          {/* bulk triage toolbar (appears when rows are selected) */}
          {selectedIds.size > 0 && (
            <motion.div
              initial={{ opacity: 0, y: -6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.2 }}
              role="toolbar"
              aria-label="Bulk triage actions"
              className="flex flex-wrap items-center gap-2 border-b border-emerald-500/25 bg-emerald-500/[0.07] px-4 py-2.5"
            >
              <ListChecks className="size-4 text-emerald-300" aria-hidden="true" />
              <span className="font-mono text-xs font-semibold text-emerald-300">
                {selectedIds.size} selected
              </span>
              <span className="hidden text-[11px] text-muted-foreground sm:inline">
                {bulkAllAcked ? "all acknowledged — clear them?" : "mark as reviewed / triaged"}
              </span>
              <div className="ml-auto flex items-center gap-2">
                <Button
                  type="button"
                  size="sm"
                  className={cn(
                    "min-h-9 gap-1.5 border",
                    bulkAllAcked
                      ? "border-slate-500/40 bg-slate-500/10 text-slate-300 hover:bg-slate-500/20"
                      : "border-emerald-500/40 bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25 hover:text-emerald-200"
                  )}
                  disabled={bulkAckMutation.isPending}
                  onClick={runBulkAck}
                >
                  {bulkAckMutation.isPending ? (
                    <RotateCw className="size-3.5 animate-spin" aria-hidden="true" />
                  ) : (
                    <CheckCheck className="size-3.5" aria-hidden="true" />
                  )}
                  {bulkAllAcked ? "Clear acknowledgement" : "Acknowledge selected"}
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="min-h-9 gap-1.5 px-2 text-muted-foreground"
                  onClick={() => setSelectedIds(new Set())}
                  disabled={bulkAckMutation.isPending}
                >
                  <X className="size-3.5" aria-hidden="true" />
                  Clear
                </Button>
              </div>
            </motion.div>
          )}
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
                    <TableHead className="pl-4 pr-1">
                      <Checkbox
                        checked={
                          allVisibleSelected
                            ? true
                            : someVisibleSelected
                              ? "indeterminate"
                              : false
                        }
                        onCheckedChange={toggleSelectAll}
                        aria-label="Select all visible alerts"
                        className="size-4 border-muted-foreground/50 data-[state=checked]:border-emerald-500 data-[state=checked]:bg-emerald-500/80 data-[state=checked]:text-background"
                      />
                    </TableHead>
                    <TableHead className="text-[11px] uppercase tracking-wider">Time</TableHead>
                    <TableHead className="text-[11px] uppercase tracking-wider">Alert ID</TableHead>
                    <TableHead className="text-[11px] uppercase tracking-wider">Source</TableHead>
                    <TableHead className="text-[11px] uppercase tracking-wider">Entity</TableHead>
                    <TableHead className="text-[11px] uppercase tracking-wider">Event</TableHead>
                    <TableHead className="text-[11px] uppercase tracking-wider">Description</TableHead>
                    <TableHead className="text-[11px] uppercase tracking-wider">Raw Sev.</TableHead>
                    <TableHead className="text-[11px] uppercase tracking-wider">Status</TableHead>
                    <TableHead className="pr-3 text-right text-[11px] uppercase tracking-wider" aria-label="Acknowledge">Ack</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {alerts.map((a) => (
                    <AlertRow
                      key={a.id}
                      alert={a}
                      incidentIdMap={incidentIdMap}
                      ackPending={pendingAckId === a.id}
                      onToggleAck={(alert) => ackMutation.mutate(alert)}
                      selected={selectedIds.has(a.id)}
                      onToggleSelect={toggleSelect}
                      onOpen={(alert) => setDrawerAlertId(alert.id)}
                    />
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </Card>
      </motion.div>

      {/* Save-preset dialog */}
      <Dialog open={presetDialogOpen} onOpenChange={setPresetDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <BookmarkPlus className="size-4 text-emerald-400" aria-hidden="true" />
              Save filter preset
            </DialogTitle>
            <DialogDescription>
              Stores the current search, source, severity, correlation and triage filters in this
              browser for one-click recall.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            <Label htmlFor="preset-name">Preset name</Label>
            <Input
              id="preset-name"
              value={presetName}
              onChange={(e) => setPresetName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  savePreset();
                }
              }}
              placeholder="e.g. Critical auth alerts"
              maxLength={40}
              autoFocus
            />
            <p className="font-mono text-[11px] text-muted-foreground">
              {[filters.source !== "all" && `source: ${filters.source}`, filters.severity !== "all" && `severity: ${filters.severity}`, filters.correlated === "correlated" && "correlated only", filters.hideAck && "hide acknowledged", filters.search.trim() && `search: "${filters.search.trim()}"`]
                .filter(Boolean)
                .join(" · ") || "no filters (show everything)"}
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPresetDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={savePreset}
              disabled={!presetName.trim()}
              className="gap-2 border-emerald-500/40 bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25 hover:text-emerald-200"
            >
              <BookmarkPlus className="size-4" aria-hidden="true" />
              Save preset
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Alert detail drawer (row click) */}
      <AlertDrawer
        alert={drawerAlert}
        incidentLabel={drawerIncidentLabel}
        onClose={() => setDrawerAlertId(null)}
      />
    </div>
  );
}
