"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Check,
  CheckCheck,
  Copy,
  Crosshair,
  Fingerprint,
  Globe,
  Link2,
  Loader2,
  LocateFixed,
  MonitorSmartphone,
  Plus,
  TriangleAlert,
  Unlink,
  User,
} from "lucide-react";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { EventChip, RawSeverityBadge, SourceChip } from "@/components/soc/badges";
import { apiGet, apiSend } from "@/lib/api-client";
import { extractIocs, type BulkIocType } from "@/lib/watchlist-parse";
import type { AlertDTO, AlertUpdateResult, WatchlistListResult } from "@/lib/types";
import { formatDateTime, timeAgo } from "@/lib/ui-helpers";
import { useSocStore } from "@/store/soc-store";
import { cn } from "@/lib/utils";

/** One key/value row in the entity grid — with a "locate in graph" action. */
function EntityRow({
  icon: Icon,
  label,
  value,
  entityType,
  onLocate,
}: {
  icon: typeof User;
  label: string;
  value: string | null;
  entityType?: "user" | "device" | "ip";
  onLocate?: () => void;
}) {
  return (
    <div className="flex items-start gap-2.5 rounded-lg border border-border/70 bg-background/40 px-3 py-2">
      <Icon
        className={cn(
          "mt-0.5 size-3.5 shrink-0",
          value ? "text-emerald-400/90" : "text-muted-foreground/40"
        )}
        aria-hidden="true"
      />
      <div className="min-w-0 flex-1">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          {label}
        </p>
        {value ? (
          <p className="truncate font-mono text-xs text-foreground/90" title={value}>
            {value}
          </p>
        ) : (
          <p className="font-mono text-xs text-muted-foreground/50">not present</p>
        )}
      </div>
      {value && entityType && onLocate && (
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="size-7 shrink-0 text-muted-foreground transition-colors hover:border-sky-500/40 hover:text-sky-300"
          onClick={onLocate}
          aria-label={`Locate ${entityType} ${value} in the Threat Graph`}
          title="Locate in Threat Graph — highlights every incident this entity appears in"
        >
          <LocateFixed className="size-3.5" aria-hidden="true" />
        </Button>
      )}
    </div>
  );
}

/** Icon + label per IOC type (mirrors the watchlist card TYPE_META). */
const IOC_META: Record<BulkIocType, { label: string; icon: typeof Globe }> = {
  ip: { label: "IP", icon: Globe },
  domain: { label: "Domain", icon: TriangleAlert },
  hash: { label: "Hash", icon: Fingerprint },
};

/** One quick-add IOC chip: value + on-list state + add-to-watchlist action. */
function IocChip({
  ioc,
  onList,
  onAdd,
  adding,
}: {
  ioc: { type: BulkIocType; value: string };
  onList: boolean;
  onAdd: () => void;
  adding: boolean;
}) {
  const meta = IOC_META[ioc.type];
  const Icon = meta.icon;
  return (
    <li
      className={cn(
        "flex min-h-8 items-center gap-1.5 rounded-lg border px-2 py-1 transition-colors",
        onList
          ? "border-emerald-500/30 bg-emerald-500/10"
          : "border-border bg-muted/40 hover:border-red-500/40 hover:bg-red-500/5"
      )}
    >
      <Icon
        className={cn("size-3 shrink-0", onList ? "text-emerald-400" : "text-red-400/80")}
        aria-hidden="true"
      />
      <span className="truncate font-mono text-[11px] text-foreground/90" title={`${meta.label} · ${ioc.value}`}>
        {ioc.value}
      </span>
      <span className="hidden shrink-0 rounded border border-border bg-background/60 px-1 font-mono text-[8px] uppercase tracking-wider text-muted-foreground sm:inline">
        {ioc.type}
      </span>
      {onList ? (
        <span
          className="ml-auto inline-flex shrink-0 items-center gap-0.5 pl-1 font-mono text-[9px] font-bold uppercase tracking-wider text-emerald-400/90"
          title="Already on your watchlist"
        >
          <Check className="size-3" aria-hidden="true" />
          listed
        </span>
      ) : (
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="ml-auto size-6 shrink-0 text-muted-foreground hover:text-emerald-300"
          disabled={adding}
          onClick={onAdd}
          aria-label={`Add ${ioc.value} to watchlist`}
          title="Add to watchlist — future alerts referencing it score as known-malicious"
        >
          {adding ? (
            <Loader2 className="size-3 animate-spin" aria-hidden="true" />
          ) : (
            <Plus className="size-3.5" aria-hidden="true" />
          )}
        </Button>
      )}
    </li>
  );
}

/**
 * AlertDetailDrawer — right-side sheet with the full normalized alert:
 * entities, description, extracted IOCs, correlation status, triage state and
 * raw metadata JSON.
 */
export function AlertDrawer({
  alert,
  incidentLabel,
  onClose,
}: {
  alert: AlertDTO | null;
  /** display id (INC-XXXX) of the correlated incident, resolved by the feed */
  incidentLabel: string | null;
  onClose: () => void;
}) {
  const openIncident = useSocStore((s) => s.openIncident);
  const focusEntityInGraph = useSocStore((s) => s.focusEntityInGraph);
  const queryClient = useQueryClient();
  const [copied, setCopied] = useState(false);

  // watchlist cache is shared with the Command Center card — lets chips show
  // an "already listed" state without an extra fetch in most cases
  const watchlistQuery = useQuery({
    queryKey: ["watchlist"],
    queryFn: () => apiGet<WatchlistListResult>("/api/watchlist"),
    enabled: alert !== null,
    staleTime: 15_000,
  });

  // candidate IOCs from the entity ip + description + metadata values
  const iocs = useMemo(() => {
    if (!alert) return [];
    const metaText = Object.entries(alert.metadata ?? {})
      .filter(([, v]) => v !== null && v !== undefined)
      .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
      .join("\n");
    return extractIocs([alert.ip ?? "", alert.description ?? "", metaText].join("\n"));
  }, [alert]);

  const listedValues = useMemo(() => {
    const items = watchlistQuery.data?.items ?? [];
    return new Set(items.map((i) => `${i.type}:${i.value.toLowerCase()}`));
  }, [watchlistQuery.data]);

  const addIocMutation = useMutation({
    mutationFn: (payload: { type: BulkIocType; value: string }) =>
      apiSend<{ message: string; duplicate?: boolean }>("/api/watchlist", "POST", payload),
    onSuccess: (d) => {
      void queryClient.invalidateQueries({ queryKey: ["watchlist"] });
      toast.success("IOC added to watchlist", {
        description: d.message,
      });
    },
    onError: (err: Error) => {
      toast.error("Could not add IOC", { description: err.message });
    },
  });

  const ackMutation = useMutation({
    mutationFn: (a: AlertDTO) =>
      apiSend<AlertUpdateResult>(`/api/alerts/${a.id}`, "PATCH", {
        acknowledged: !a.acknowledged,
      }),
    onSuccess: (data) => {
      queryClient.invalidateQueries();
      toast.success(data.message);
    },
    onError: (err: Error) => {
      toast.error("Could not update alert", { description: err.message });
    },
  });

  const copyJson = async () => {
    if (!alert) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(alert, null, 2));
      setCopied(true);
      toast.success("Alert JSON copied to clipboard");
      setTimeout(() => setCopied(false), 1600);
    } catch {
      toast.error("Clipboard unavailable in this browser");
    }
  };

  const metaEntries = alert
    ? Object.entries(alert.metadata ?? {}).filter(([, v]) => v !== null && v !== undefined)
    : [];

  return (
    <Sheet open={alert !== null} onOpenChange={(o) => !o && onClose()}>
      <SheetContent
        side="right"
        className="flex w-full flex-col gap-0 border-l border-border/80 bg-card p-0 sm:max-w-md"
      >
        {alert && (
          <>
            <SheetHeader className="border-b border-border/70 pb-4 pr-10">
              <div className="flex flex-wrap items-center gap-2">
                <SheetTitle className="font-mono text-base font-bold tracking-tight">
                  {alert.alertId}
                </SheetTitle>
                <RawSeverityBadge raw={alert.rawSeverity} />
                {alert.acknowledged && (
                  <span className="inline-flex items-center gap-1 rounded border border-emerald-500/40 bg-emerald-500/10 px-1.5 py-px font-mono text-[9px] font-bold tracking-wider text-emerald-400/90">
                    <CheckCheck className="size-3" aria-hidden="true" />
                    ACKNOWLEDGED
                  </span>
                )}
              </div>
              <SheetDescription className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
                <span>{timeAgo(alert.timestamp)}</span>
                <span aria-hidden="true">·</span>
                <span className="font-mono text-[11px]">
                  {formatDateTime(alert.timestamp)}
                </span>
                <span aria-hidden="true">·</span>
                <span className="uppercase">ingested as {alert.rawFormat}</span>
              </SheetDescription>
            </SheetHeader>

            <div className="soc-scroll flex-1 overflow-y-auto px-4 py-4">
              <div className="flex flex-col gap-5">
                {/* source + event */}
                <div className="flex flex-wrap items-center gap-2">
                  <SourceChip source={alert.source} sourceLabel={alert.sourceLabel} />
                  <EventChip event={alert.event} />
                </div>

                {/* entities */}
                <section aria-label="Entities" className="grid grid-cols-1 gap-2">
                  <EntityRow
                    icon={User}
                    label="User"
                    value={alert.user}
                    entityType="user"
                    onLocate={() => focusEntityInGraph("user", alert.user as string)}
                  />
                  <EntityRow
                    icon={MonitorSmartphone}
                    label="Device"
                    value={alert.device}
                    entityType="device"
                    onLocate={() => focusEntityInGraph("device", alert.device as string)}
                  />
                  <EntityRow
                    icon={Globe}
                    label="IP address"
                    value={alert.ip}
                    entityType="ip"
                    onLocate={() => focusEntityInGraph("ip", alert.ip as string)}
                  />
                </section>

                {/* description */}
                <section aria-label="Description">
                  <h4 className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                    <Fingerprint className="size-3.5 text-emerald-400" aria-hidden="true" />
                    Description
                  </h4>
                  <p className="mt-1.5 rounded-lg border border-border/70 bg-background/40 px-3 py-2.5 text-sm leading-relaxed text-foreground/85">
                    {alert.description || "—"}
                  </p>
                </section>

                {/* extracted indicators of compromise */}
                {iocs.length > 0 && (
                  <section aria-label="Indicators of compromise">
                    <div className="flex items-center justify-between gap-2">
                      <h4 className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                        <Crosshair className="size-3.5 text-red-400" aria-hidden="true" />
                        Indicators of Compromise
                        <span className="rounded-full border border-red-500/40 bg-red-500/10 px-1.5 font-mono text-[9px] font-bold text-red-300">
                          {iocs.length}
                        </span>
                      </h4>
                      <span className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground/60">
                        tap + to watch
                      </span>
                    </div>
                    <ul className="mt-1.5 grid grid-cols-1 gap-1.5" aria-label="Extracted indicators">
                      {iocs.map((ioc) => (
                        <IocChip
                          key={`${ioc.type}:${ioc.value}`}
                          ioc={ioc}
                          onList={listedValues.has(`${ioc.type}:${ioc.value.toLowerCase()}`)}
                          adding={
                            addIocMutation.isPending &&
                            addIocMutation.variables?.value === ioc.value
                          }
                          onAdd={() => addIocMutation.mutate(ioc)}
                        />
                      ))}
                    </ul>
                    <p className="mt-1 text-[10px] leading-relaxed text-muted-foreground/70">
                      Auto-extracted from this alert — watched indicators raise scores on future
                      correlations and turn red in the Threat Graph.
                    </p>
                  </section>
                )}

                {/* correlation status */}
                <section aria-label="Correlation status">
                  <h4 className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                    Correlation
                  </h4>
                  {alert.incidentId ? (
                    <div className="mt-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2.5">
                      <div className="flex items-center gap-2">
                        <Link2 className="size-3.5 text-emerald-300" aria-hidden="true" />
                        <span className="font-mono text-xs font-semibold text-emerald-300">
                          {incidentLabel ?? "Correlated incident"}
                        </span>
                      </div>
                      <p className="mt-1 text-[11px] leading-relaxed text-emerald-200/70">
                        This alert was correlated into an active incident.
                      </p>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        className="mt-2 min-h-8 gap-1.5 border-emerald-500/40 px-2.5 text-emerald-300 hover:bg-emerald-500/15 hover:text-emerald-200"
                        onClick={() => {
                          onClose();
                          openIncident(alert.incidentId as string);
                        }}
                      >
                        Open in Incident Analysis
                      </Button>
                    </div>
                  ) : (
                    <div className="mt-1.5 flex items-center gap-2 rounded-lg border border-slate-600/40 bg-slate-500/10 px-3 py-2.5">
                      <Unlink className="size-3.5 shrink-0 text-slate-400" aria-hidden="true" />
                      <p className="text-[11px] leading-relaxed text-slate-300/90">
                        Uncorrelated — no incident yet. It will attach automatically when a
                        matching pattern is observed or correlation re-runs.
                      </p>
                    </div>
                  )}
                </section>

                {/* raw metadata */}
                <section aria-label="Raw metadata">
                  <div className="flex items-center justify-between gap-2">
                    <h4 className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                      Raw metadata
                    </h4>
                    {metaEntries.length === 0 && (
                      <span className="font-mono text-[10px] text-muted-foreground/60">
                        no extra fields
                      </span>
                    )}
                  </div>
                  {metaEntries.length > 0 && (
                    <pre className="soc-scroll mt-1.5 max-h-44 overflow-auto rounded-lg border border-border/70 bg-background/60 p-3 font-mono text-[11px] leading-relaxed text-foreground/80">
                      {JSON.stringify(Object.fromEntries(metaEntries), null, 2)}
                    </pre>
                  )}
                </section>
                <Separator className="opacity-50" />
                <p className="text-[11px] leading-relaxed text-muted-foreground">
                  Normalized record — source feed was auto-detected as{" "}
                  <span className="font-mono uppercase text-foreground/70">{alert.rawFormat}</span>{" "}
                  and mapped to the unified schema on ingest.
                </p>
              </div>
            </div>

            <SheetFooter className="flex-row items-center gap-2 border-t border-border/70 pb-[max(1rem,env(safe-area-inset-bottom))]">
              <Button
                type="button"
                className={cn(
                  "min-h-10 flex-1 gap-2",
                  alert.acknowledged
                    ? "border-slate-500/40 bg-slate-500/10 text-slate-300 hover:bg-slate-500/20"
                    : "border-emerald-500/40 bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25 hover:text-emerald-200"
                )}
                disabled={ackMutation.isPending}
                onClick={() => ackMutation.mutate(alert)}
              >
                {ackMutation.isPending ? (
                  <Loader2 className="size-4 animate-spin" aria-hidden="true" />
                ) : alert.acknowledged ? (
                  <Check className="size-4" aria-hidden="true" />
                ) : (
                  <CheckCheck className="size-4" aria-hidden="true" />
                )}
                {alert.acknowledged ? "Clear acknowledgement" : "Acknowledge alert"}
              </Button>
              <Button
                type="button"
                variant="outline"
                className="min-h-10 gap-1.5 px-3"
                onClick={() => void copyJson()}
                aria-label="Copy alert JSON"
              >
                <Copy className={copied ? "size-3.5 text-emerald-400" : "size-3.5"} aria-hidden="true" />
                {copied ? "Copied" : "JSON"}
              </Button>
            </SheetFooter>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
