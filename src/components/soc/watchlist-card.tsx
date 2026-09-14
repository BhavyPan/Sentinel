"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { toast } from "sonner";
import {
  Fingerprint,
  Globe,
  Loader2,
  Plus,
  ShieldBan,
  Trash2,
  TriangleAlert,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { apiGet, apiSend } from "@/lib/api-client";
import { timeAgo } from "@/lib/ui-helpers";
import type { WatchlistItemDTO, WatchlistListResult, WatchlistResult } from "@/lib/types";
import { cn } from "@/lib/utils";

const TYPE_META: Record<string, { label: string; placeholder: string; icon: typeof Globe }> = {
  ip: { label: "IP address", placeholder: "e.g. 203.0.113.66", icon: Globe },
  domain: { label: "Domain", placeholder: "e.g. evil-cdn.example.com", icon: TriangleAlert },
  hash: { label: "File hash", placeholder: "e.g. e3b0c442…", icon: Fingerprint },
};

/**
 * Analyst IOC Watchlist — add/remove custom malicious indicators.
 * Entries merge into the runtime intel feed: future correlations score them
 * as "known malicious IOC match" and the Threat Graph flags them red.
 */
export function WatchlistCard() {
  const queryClient = useQueryClient();
  const [type, setType] = useState<"ip" | "domain" | "hash">("ip");
  const [value, setValue] = useState("");

  const listQuery = useQuery({
    queryKey: ["watchlist"],
    queryFn: () => apiGet<WatchlistListResult>("/api/watchlist"),
  });
  const items = listQuery.data?.items ?? [];

  const addMutation = useMutation({
    mutationFn: (payload: { type: string; value: string }) =>
      apiSend<WatchlistResult>("/api/watchlist", "POST", payload),
    onSuccess: (d) => {
      void queryClient.invalidateQueries({ queryKey: ["watchlist"] });
      setValue("");
      toast.success("IOC added to watchlist", { description: d.message });
    },
    onError: (err: Error) => {
      toast.error("Could not add IOC", { description: err.message });
    },
  });

  const removeMutation = useMutation({
    mutationFn: (id: string) => apiSend<WatchlistResult>(`/api/watchlist/${id}`, "DELETE"),
    onSuccess: (d) => {
      void queryClient.invalidateQueries({ queryKey: ["watchlist"] });
      toast.success("IOC removed", { description: d.message });
    },
    onError: (err: Error) => {
      toast.error("Could not remove IOC", { description: err.message });
    },
  });

  const submit = () => {
    if (!value.trim()) {
      toast.error("Enter an indicator value first");
      return;
    }
    addMutation.mutate({ type, value: value.trim() });
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: 0.22 }}
    >
      <Card className="gap-3 rounded-xl">
        <CardHeader className="pb-1">
          <CardTitle className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            <span className="flex size-8 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10">
              <ShieldBan className="size-4 text-emerald-400" aria-hidden="true" />
            </span>
            IOC Watchlist
            {items.length > 0 && (
              <span className="rounded-full border border-red-500/40 bg-red-500/10 px-2 py-px font-mono text-[10px] font-bold text-red-300">
                {items.length}
              </span>
            )}
          </CardTitle>
          <CardDescription className="text-xs">
            Your indicators join the intel feed — future correlations score them as known-malicious
            and the graph flags them red.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {/* add form */}
          <div className="flex flex-col gap-2 sm:flex-row">
            <div className="sm:w-32">
              <label htmlFor="watchlist-type" className="sr-only">
                Indicator type
              </label>
              <Select value={type} onValueChange={(v) => setType(v as typeof type)}>
                <SelectTrigger id="watchlist-type" className="min-h-10 w-full" aria-label="Indicator type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(TYPE_META).map(([k, m]) => (
                    <SelectItem key={k} value={k}>
                      {m.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-1 gap-2">
              <label htmlFor="watchlist-value" className="sr-only">
                Indicator value
              </label>
              <Input
                id="watchlist-value"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") submit();
                }}
                placeholder={TYPE_META[type].placeholder}
                className="min-h-10 flex-1 font-mono text-xs"
                autoComplete="off"
                spellCheck={false}
              />
              <Button
                type="button"
                size="sm"
                onClick={submit}
                disabled={addMutation.isPending}
                className="min-h-10 gap-1 border-emerald-500/50 bg-emerald-500/15 px-3 font-semibold text-emerald-300 hover:bg-emerald-500/25 hover:text-emerald-200"
                aria-label="Add indicator to watchlist"
              >
                {addMutation.isPending ? (
                  <Loader2 className="size-3.5 animate-spin" aria-hidden="true" />
                ) : (
                  <Plus className="size-3.5" aria-hidden="true" />
                )}
                Add
              </Button>
            </div>
          </div>

          {/* list */}
          {listQuery.isLoading ? (
            <div className="flex flex-col gap-1.5" aria-busy="true">
              <div className="h-8 rounded-lg bg-muted/50" />
              <div className="h-8 rounded-lg bg-muted/50" />
            </div>
          ) : items.length === 0 ? (
            <p className="rounded-lg border border-dashed border-border bg-background/40 px-3 py-3 text-center font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
              watchlist empty — add your first indicator above
            </p>
          ) : (
            <ul
              className="soc-scroll -mx-1 flex max-h-40 flex-col gap-1 overflow-y-auto px-1"
              aria-label="Watchlist entries"
            >
              {items.map((it) => (
                <WatchlistRow
                  key={it.id}
                  item={it}
                  onRemove={() => removeMutation.mutate(it.id)}
                  removing={removeMutation.isPending && removeMutation.variables === it.id}
                />
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}

function WatchlistRow({
  item,
  onRemove,
  removing,
}: {
  item: WatchlistItemDTO;
  onRemove: () => void;
  removing: boolean;
}) {
  const meta = TYPE_META[item.type] ?? TYPE_META.ip;
  const Icon = meta.icon;
  return (
    <li
      className={cn(
        "group flex min-h-9 items-center gap-2 rounded-lg border border-border/70 bg-muted/30 px-2.5 py-1.5 transition-colors hover:border-red-500/30 hover:bg-red-500/5",
        removing && "opacity-50"
      )}
    >
      <Icon className="size-3.5 shrink-0 text-red-400/80" aria-hidden="true" />
      <span className="truncate font-mono text-xs text-foreground/90">{item.value}</span>
      <span className="shrink-0 rounded border border-border bg-background/60 px-1 py-px font-mono text-[9px] uppercase text-muted-foreground">
        {item.type}
      </span>
      <span className="ml-auto hidden shrink-0 font-mono text-[10px] text-muted-foreground sm:inline">
        {timeAgo(item.createdAt)}
      </span>
      <Button
        type="button"
        variant="ghost"
        size="icon"
        className="size-7 shrink-0 text-muted-foreground transition-opacity hover:text-red-300 focus-visible:opacity-100 sm:opacity-0 sm:group-hover:opacity-100"
        onClick={onRemove}
        disabled={removing}
        aria-label={`Remove ${item.value} from watchlist`}
      >
        {removing ? (
          <Loader2 className="size-3.5 animate-spin" aria-hidden="true" />
        ) : (
          <Trash2 className="size-3.5" aria-hidden="true" />
        )}
      </Button>
    </li>
  );
}
