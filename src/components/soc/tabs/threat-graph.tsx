"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Maximize,
  Network,
  MousePointerClick,
  ShieldAlert,
  Users,
  HardDrive,
  Globe,
  ZoomIn,
  ZoomOut,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/soc/error-state";
import { EmptyHero } from "@/components/soc/empty-hero";
import { apiGet } from "@/lib/api-client";
import type { GraphData, GraphNode } from "@/lib/types";
import { severityStyle } from "@/lib/ui-helpers";
import { useSocStore } from "@/store/soc-store";
import { cn } from "@/lib/utils";

// ------------------------------------------------------------------
// Layout math — deterministic radial "attack cluster" layout
// ------------------------------------------------------------------

const VB_W = 960;
const VB_H = 720;
const CX = VB_W / 2;
const CY = VB_H / 2;
const R_INCIDENT = 180;
const R_ENTITY = 300;

const SEV_RANK: Record<string, number> = {
  Critical: 0, High: 1, Medium: 2, Low: 3, "False Positive": 4, Info: 5,
};

interface Positioned {
  node: GraphNode;
  x: number;
  y: number;
}

function polar(r: number, angle: number): { x: number; y: number } {
  return { x: CX + r * Math.cos(angle), y: CY + r * Math.sin(angle) };
}

/** Hash a string into 0..1 — deterministic jitter for label offsets. */
function hash01(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return ((h >>> 0) % 1000) / 1000;
}

/**
 * Deterministic post-pass: nudge entity nodes apart until no two label boxes
 * overlap (labels render below glyphs, mono ~5.4px/char). Incident nodes stay fixed.
 */
function resolveLabelCollisions(positions: Map<string, Positioned>) {
  const ents = [...positions.values()].filter((p) => p.node.kind === "entity");
  const halfW = (p: Positioned) => (Math.min(p.node.label.length, 16) * 5.4) / 2 + 5;
  const MIN_GAP = 6;

  for (let pass = 0; pass < 40; pass++) {
    let movedAny = false;
    for (let i = 0; i < ents.length; i++) {
      for (let j = i + 1; j < ents.length; j++) {
        const a = ents[i];
        const b = ents[j];
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const needX = halfW(a) + halfW(b) + MIN_GAP;
        const needY = 22; // glyph + label stack height
        const overlapX = needX - Math.abs(dx);
        const overlapY = needY - Math.abs(dy);
        if (overlapX <= 0 || overlapY <= 0) continue;

        // push apart along the dominant separation axis (stable, less drift)
        let pushX = 0;
        let pushY = 0;
        if (overlapX / needX >= overlapY / needY) {
          const dir = dx >= 0 ? 1 : -1;
          // if vertically stacked, prefer horizontal slide opposite to overlap direction
          pushX = (overlapX / 2 + 0.5) * dir;
        } else {
          const dir = dy >= 0 ? 1 : -1;
          pushY = (overlapY / 2 + 0.5) * dir;
        }
        a.x += pushX;
        a.y += pushY;
        b.x -= pushX;
        b.y -= pushY;
        movedAny = true;
      }
    }
    // keep entities inside a sane ring band so the cluster shape survives
    for (const e of ents) {
      const dx = e.x - CX;
      const dy = e.y - CY;
      const r = Math.hypot(dx, dy) || 1;
      const clamped = Math.min(Math.max(r, R_ENTITY - 110), R_ENTITY + 135);
      if (Math.abs(clamped - r) > 0.01) {
        e.x = CX + (dx / r) * clamped;
        e.y = CY + (dy / r) * clamped;
      }
    }
    if (!movedAny) break;
  }
}

function computeLayout(data: GraphData) {
  const incidents = data.nodes
    .filter((n) => n.kind === "incident")
    .sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9) || b.weight - a.weight);

  const entityById = new Map(data.nodes.filter((n) => n.kind === "entity").map((n) => [n.id, n]));

  // group entities by their highest-priority incident
  const clusterEntities = new Map<string, GraphNode[]>();
  const orphans: GraphNode[] = [];
  const entityIncident = new Map<string, string>(); // entity id -> incident node id

  for (const [id, ent] of entityById) {
    const incNode = incidents.find((i) => ent.incidentDbIds.includes(i.incidentDbIds[0]));
    if (incNode && ent.incidentDbIds.length > 0) {
      // pick the highest-priority incident this entity connects to
      const best = ent.incidentDbIds
        .map((dbId) => incidents.find((i) => i.incidentDbIds[0] === dbId))
        .filter(Boolean)
        .sort((a, b) => (SEV_RANK[a!.severity] ?? 9) - (SEV_RANK[b!.severity] ?? 9))[0];
      const arr = clusterEntities.get(best!.id) ?? [];
      arr.push(ent);
      clusterEntities.set(best!.id, arr);
      entityIncident.set(id, best!.id);
    } else {
      orphans.push(ent);
    }
  }

  const positions = new Map<string, Positioned>();

  incidents.forEach((inc, i) => {
    const angle = (i / Math.max(incidents.length, 1)) * Math.PI * 2 - Math.PI / 2;
    const p = polar(R_INCIDENT, angle);
    positions.set(inc.id, { node: inc, x: p.x, y: p.y });

    const members = (clusterEntities.get(inc.id) ?? []).sort(
      (a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9) || a.label.localeCompare(b.label)
    );
    // wide enough angular window per cluster + radial stagger to avoid label overlap
    const spread = Math.min(1.7, 0.36 * members.length);
    members.forEach((ent, j) => {
      const off = members.length === 1 ? 0 : (j / (members.length - 1) - 0.5) * spread;
      const ea = angle + off + (hash01(ent.id) - 0.5) * 0.05;
      const ring = R_ENTITY + ((j % 3) - 1) * 34 + (hash01(ent.id + "r") - 0.5) * 18;
      const ep = polar(ring, ea);
      positions.set(ent.id, { node: ent, x: ep.x, y: ep.y });
    });
  });

  orphans
    .sort((a, b) => a.label.localeCompare(b.label))
    .forEach((ent, j) => {
      const angle = (j / Math.max(orphans.length, 1)) * Math.PI * 2 - Math.PI / 2 + Math.PI / Math.max(orphans.length, 1) / 2;
      const ring = R_ENTITY + 46 + (j % 2 ? 34 : 0); // alternate rings to avoid label collisions
      const p = polar(ring, angle);
      positions.set(ent.id, { node: ent, x: p.x, y: p.y });
    });

  resolveLabelCollisions(positions);

  return { positions, incidents, entityById };
}

// ------------------------------------------------------------------
// Node rendering helpers
// ------------------------------------------------------------------

function EntityGlyph({
  node,
  x,
  y,
  hovered,
  dimmed,
  onClick,
  onFocus,
}: {
  node: GraphNode;
  x: number;
  y: number;
  hovered: boolean;
  dimmed: boolean;
  onClick: () => void;
  onFocus: () => void;
}) {
  const sev = severityStyle(node.severity);
  const size = 7 + Math.min(node.alertCount, 8) * 0.55; // 7..11.4
  const stroke = node.malicious ? "#ef4444" : sev.hex;
  const isType = node.entityType;

  const common = {
    fill: "oklch(0.168 0.012 240)",
    stroke,
    strokeWidth: hovered ? 2.5 : 1.5,
    className: cn(
      "cursor-pointer transition-[opacity,stroke-width] duration-200",
      dimmed ? "opacity-15" : "opacity-100"
    ),
  };

  return (
    <g
      transform={`translate(${x},${y})`}
      role="button"
      tabIndex={0}
      aria-label={`${node.entityType ?? "entity"}: ${node.label} — ${node.sublabel}`}
      onClick={onClick}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onClick();
        }
      }}
      onFocus={onFocus}
      onMouseEnter={onFocus}
      className="outline-none focus-visible:[&>*:first-child]:stroke-emerald-300"
    >
      {isType === "user" && <circle r={size} {...common} />}
      {isType === "device" && (
        <rect x={-size} y={-size} width={size * 2} height={size * 2} rx={3} {...common} />
      )}
      {isType === "ip" && (
        <rect x={-size} y={-size} width={size * 2} height={size * 2} rx={1.5} transform="rotate(45)" {...common} />
      )}
      {!isType && <circle r={size} {...common} />}
      {node.malicious && (
        <circle r={size + 4.5} fill="none" stroke="#ef4444" strokeWidth={1} strokeDasharray="3 3" className="animate-[spin_9s_linear_infinite]" style={{ transformOrigin: "center", transformBox: "fill-box" }} />
      )}
      <text
        y={size + 11}
        textAnchor="middle"
        fontSize={9.5}
        className={cn("pointer-events-none select-none font-mono transition-opacity duration-200", dimmed ? "opacity-15" : "fill-foreground/75")}
      >
        {node.label.length > 16 ? node.label.slice(0, 15) + "…" : node.label}
      </text>
    </g>
  );
}

function IncidentGlyph({
  node,
  x,
  y,
  hovered,
  dimmed,
  onClick,
  onFocus,
}: {
  node: GraphNode;
  x: number;
  y: number;
  hovered: boolean;
  dimmed: boolean;
  onClick: () => void;
  onFocus: () => void;
}) {
  const sev = severityStyle(node.severity);
  const r = 15 + Math.min(node.weight, 100) / 100 * 9; // 15..24
  const critical = node.severity === "Critical";
  return (
    <g
      transform={`translate(${x},${y})`}
      role="button"
      tabIndex={0}
      aria-label={`incident ${node.label} — ${node.sublabel}`}
      onClick={onClick}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onClick();
        }
      }}
      onFocus={onFocus}
      onMouseEnter={onFocus}
      className={cn("cursor-pointer outline-none transition-opacity duration-200", dimmed ? "opacity-15" : "opacity-100")}
    >
      {critical && (
        <circle r={r + 7} fill="none" stroke={sev.hex} strokeWidth={1} opacity={0.5} className="animate-ping" />
      )}
      <circle
        r={hovered ? r + 2 : r}
        fill={sev.hex}
        fillOpacity={0.22}
        stroke={sev.hex}
        strokeWidth={hovered ? 3 : 2}
        className="transition-all duration-200"
        style={{ filter: `drop-shadow(0 0 6px ${sev.hex}66)` }}
      />
      <circle r={3} fill={sev.hex} className="pointer-events-none" />
      <text
        y={r + 14}
        textAnchor="middle"
        fontSize={11}
        fontWeight={700}
        className={cn("pointer-events-none select-none font-mono transition-opacity duration-200", dimmed ? "opacity-15" : severityStyle(node.severity).text)}
      >
        {node.label}
      </text>
    </g>
  );
}

// ------------------------------------------------------------------
// Info panel (hover details)
// ------------------------------------------------------------------

function NodeInfoBox({ node }: { node: GraphNode | null }) {
  if (!node) {
    return (
      <div className="rounded-lg border border-dashed border-border bg-background/60 px-3 py-2.5 text-xs text-muted-foreground">
        Hover a node to inspect entities &amp; incidents — click to open the investigation.
      </div>
    );
  }
  const sev = severityStyle(node.severity);
  const TypeIcon = node.entityType === "user" ? Users : node.entityType === "device" ? HardDrive : Globe;
  return (
    <div className="rounded-lg border border-border bg-background/80 px-3 py-2.5 shadow-lg backdrop-blur">
      <div className="flex items-center gap-2">
        {node.kind === "entity" ? (
          <TypeIcon className="size-3.5 shrink-0 text-emerald-400" aria-hidden="true" />
        ) : (
          <ShieldAlert className={cn("size-3.5 shrink-0", sev.text)} aria-hidden="true" />
        )}
        <span className="font-mono text-xs font-bold text-foreground">{node.label}</span>
        {node.malicious && (
          <span className="rounded border border-red-500/40 bg-red-500/10 px-1 py-px font-mono text-[9px] font-bold uppercase text-red-300">
            malicious ip
          </span>
        )}
        {node.internal === true && (
          <span className="rounded border border-border bg-muted/60 px-1 py-px font-mono text-[9px] uppercase text-muted-foreground">
            internal
          </span>
        )}
        <span className={cn("ml-auto rounded-full border px-1.5 py-px font-mono text-[9px] font-semibold uppercase", sev.border, sev.bg, sev.text)}>
          {node.severity}
        </span>
      </div>
      <p className="mt-1 line-clamp-2 text-[11px] leading-relaxed text-muted-foreground">{node.sublabel}</p>
      {node.kind === "entity" && node.entityType && (
        <p className="mt-0.5 font-mono text-[10px] uppercase tracking-wider text-emerald-400/70">
          {node.entityType} node · {node.alertCount} alert{node.alertCount === 1 ? "" : "s"}
        </p>
      )}
    </div>
  );
}

// ------------------------------------------------------------------
// Skeleton / empty
// ------------------------------------------------------------------

function GraphSkeleton() {
  return (
    <div className="flex flex-col gap-4" aria-busy="true" aria-label="Loading threat graph">
      <div className="flex flex-wrap items-center gap-2">
        <Skeleton className="h-8 w-52 rounded-lg" />
        <Skeleton className="h-8 w-64 rounded-lg" />
      </div>
      <Skeleton className="h-[560px] w-full rounded-xl" />
    </div>
  );
}

// ------------------------------------------------------------------
// Tab root
// ------------------------------------------------------------------

type TypeFilter = "all" | "user" | "device" | "ip";

const FILTERS: { value: TypeFilter; label: string }[] = [
  { value: "all", label: "All entities" },
  { value: "user", label: "Users" },
  { value: "device", label: "Devices" },
  { value: "ip", label: "IPs" },
];

// ------------------------------------------------------------------
// Pan & zoom (viewBox based — deterministic, no layout drift)
// ------------------------------------------------------------------

interface ViewState {
  x: number;
  y: number;
  k: number;
}

const K_MIN = 0.55;
const K_MAX = 3;

function clampView(v: ViewState): ViewState {
  const w = VB_W / v.k;
  const h = VB_H / v.k;
  return {
    k: v.k,
    x: Math.min(Math.max(v.x, -w * 0.35), w * 0.35),
    y: Math.min(Math.max(v.y, -h * 0.35), h * 0.35),
  };
}

export function ThreatGraph() {
  const openIncidentRaw = useSocStore((s) => s.openIncident);
  const [hoverId, setHoverId] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState<TypeFilter>("all");
  const [view, setView] = useState<ViewState>({ x: 0, y: 0, k: 1 });
  const svgRef = useRef<SVGSVGElement | null>(null);
  const panRef = useRef<{
    sx: number;
    sy: number;
    vx: number;
    vy: number;
    rectW: number;
    rectH: number;
    moved: boolean;
  } | null>(null);
  const didPanRef = useRef(false);

  const zoomAt = (factor: number, mx = 0.5, my = 0.5) => {
    setView((v) => {
      const k2 = Math.min(K_MAX, Math.max(K_MIN, v.k * factor));
      const px = v.x + mx * (VB_W / v.k);
      const py = v.y + my * (VB_H / v.k);
      return clampView({ k: k2, x: px - mx * (VB_W / k2), y: py - my * (VB_H / k2) });
    });
  };

  const resetView = () => setView({ x: 0, y: 0, k: 1 });

  // wheel zoom — non-passive so we can stop page scroll over the canvas
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const rect = svg.getBoundingClientRect();
      const mx = (e.clientX - rect.left) / rect.width;
      const my = (e.clientY - rect.top) / rect.height;
      zoomAt(Math.exp(-e.deltaY * 0.0016), mx, my);
    };
    svg.addEventListener("wheel", onWheel, { passive: false });
    return () => svg.removeEventListener("wheel", onWheel);
  }, []);

  const onPointerDown = (e: React.PointerEvent<SVGSVGElement>) => {
    if (e.button !== 0) return;
    const svg = svgRef.current;
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    panRef.current = {
      sx: e.clientX,
      sy: e.clientY,
      vx: view.x,
      vy: view.y,
      rectW: rect.width,
      rectH: rect.height,
      moved: false,
    };
    didPanRef.current = false;
    try {
      svg.setPointerCapture(e.pointerId);
    } catch {
      // synthetic/already-released pointers have no active pointer id —
      // pan still works while the cursor stays inside the svg
    }
  };

  const onPointerMove = (e: React.PointerEvent<SVGSVGElement>) => {
    const p = panRef.current;
    if (!p) return;
    if (!p.moved && Math.abs(e.clientX - p.sx) + Math.abs(e.clientY - p.sy) > 4) {
      p.moved = true;
      didPanRef.current = true;
    }
    if (!p.moved) return;
    const dx = (e.clientX - p.sx) * (VB_W / p.rectW);
    const dy = (e.clientY - p.sy) * (VB_H / p.rectH);
    setView((v) => clampView({ ...v, x: p.vx - dx, y: p.vy - dy }));
  };

  const onPointerUp = (e: React.PointerEvent<SVGSVGElement>) => {
    if (panRef.current) {
      panRef.current = null;
      try {
        svgRef.current?.releasePointerCapture?.(e.pointerId);
      } catch {
        // pointer may already be released
      }
      // click fires right after pointerup — keep the didPan flag for that tick
      setTimeout(() => {
        didPanRef.current = false;
      }, 0);
    }
  };

  const query = useQuery({
    queryKey: ["graph"],
    queryFn: () => apiGet<GraphData>("/api/graph"),
  });

  const { positions, incidents } = useMemo(
    () => (query.data ? computeLayout(query.data) : { positions: new Map<string, Positioned>(), incidents: [] }),
    [query.data]
  );

  const data = query.data;
  const neighbors = useMemo(() => {
    const m = new Map<string, Set<string>>();
    for (const l of data?.links ?? []) {
      if (!m.has(l.source)) m.set(l.source, new Set());
      if (!m.has(l.target)) m.set(l.target, new Set());
      m.get(l.source)!.add(l.target);
      m.get(l.target)!.add(l.source);
    }
    return m;
  }, [data]);

  if (query.isLoading) return <GraphSkeleton />;
  if (query.isError) {
    return (
      <ErrorState
        message={query.error instanceof Error ? query.error.message : undefined}
        onRetry={() => query.refetch()}
      />
    );
  }
  if (!data || data.nodes.length === 0) return <EmptyHero />;

  const hoverNode = hoverId ? data.nodes.find((n) => n.id === hoverId) ?? null : null;

  const isDimmed = (id: string): boolean => {
    if (!hoverId) return false;
    if (id === hoverId) return false;
    return !(neighbors.get(hoverId)?.has(id) ?? false);
  };

  const entityVisible = (n: GraphNode): boolean =>
    typeFilter === "all" || n.entityType === typeFilter;

  const openNode = (node: GraphNode) => {
    if (didPanRef.current) return; // ignore clicks that were actually drags
    if (node.incidentDbIds.length > 0) openIncidentRaw(node.incidentDbIds[0]);
  };

  const linkVisible = (sourceId: string, targetId: string): boolean => {
    const s = data.nodes.find((n) => n.id === sourceId);
    return s ? entityVisible(s) : true;
  };

  return (
    <div className="flex flex-col gap-4 sm:gap-6">
      {/* toolbar */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35 }}
      >
        <Card className="rounded-xl p-4">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Entity type filter">
              {FILTERS.map((f) => (
                <button
                  key={f.value}
                  type="button"
                  onClick={() => setTypeFilter(f.value)}
                  aria-pressed={typeFilter === f.value}
                  className={cn(
                    "inline-flex min-h-9 items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors",
                    typeFilter === f.value
                      ? "border-emerald-500/50 bg-emerald-500/15 text-emerald-300"
                      : "border-border bg-muted/40 text-muted-foreground hover:border-emerald-500/30 hover:text-foreground"
                  )}
                >
                  <Network className="size-3.5" aria-hidden="true" />
                  {f.label}
                </button>
              ))}
            </div>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[11px] text-muted-foreground">
              {(["Critical", "High", "Medium", "Low", "False Positive"] as const).map((sev) => (
                <span key={sev} className="flex items-center gap-1.5">
                  <span className={cn("size-2 rounded-full", severityStyle(sev).dot)} aria-hidden="true" />
                  {sev}
                </span>
              ))}
              <span className="hidden items-center gap-1.5 sm:flex">
                <span className="size-2 rotate-45 border border-red-500" aria-hidden="true" />
                malicious IP
              </span>
            </div>
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1 border-t border-border/60 pt-3 text-[11px] text-muted-foreground">
            <span className="font-mono">{data.stats.entityCount} entities</span>
            <span className="font-mono">{data.stats.incidentCount} incidents</span>
            <span className="font-mono">{data.stats.linkCount} relationships</span>
            {data.stats.unlinkedAlerts > 0 && (
              <span className="font-mono text-amber-400/80">{data.stats.unlinkedAlerts} unlinked alerts</span>
            )}
            <span className="ml-auto hidden items-center gap-1.5 md:flex">
              <MousePointerClick className="size-3.5" aria-hidden="true" />
              click a node to open its incident · drag to pan · scroll or +/- to zoom
            </span>
          </div>
        </Card>
      </motion.div>

      {/* graph */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.08 }}
      >
        <Card className="overflow-hidden rounded-xl p-0">
          <CardHeader className="border-b border-border/70 py-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <CardTitle className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                  <Network className="size-4 text-emerald-400" aria-hidden="true" />
                  Entity Relationship Graph
                </CardTitle>
                <CardDescription className="mt-1 text-xs">
                  Inner ring: correlated incidents · outer ring: users, devices and IPs clustered by the
                  incident they appear in
                </CardDescription>
              </div>
              <div className="w-full max-w-sm lg:w-auto">
                <NodeInfoBox node={hoverNode} />
              </div>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div className="relative">
              {/* zoom controls */}
              <div className="absolute right-3 top-3 z-10 flex flex-col items-center gap-1.5">
                <Button
                  type="button"
                  variant="outline"
                  size="icon"
                  className="size-8 bg-background/85 backdrop-blur"
                  onClick={() => zoomAt(1.25)}
                  aria-label="Zoom in"
                >
                  <ZoomIn className="size-4" aria-hidden="true" />
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="icon"
                  className="size-8 bg-background/85 backdrop-blur"
                  onClick={() => zoomAt(0.8)}
                  aria-label="Zoom out"
                >
                  <ZoomOut className="size-4" aria-hidden="true" />
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="icon"
                  className="size-8 bg-background/85 backdrop-blur"
                  onClick={resetView}
                  aria-label="Reset pan and zoom"
                >
                  <Maximize className="size-4" aria-hidden="true" />
                </Button>
                <span
                  className="rounded border border-border bg-background/85 px-1 py-px font-mono text-[9px] text-muted-foreground backdrop-blur"
                  aria-live="polite"
                >
                  {Math.round(view.k * 100)}%
                </span>
              </div>
              <div className="soc-scroll overflow-x-auto">
                <svg
                  ref={svgRef}
                  viewBox={`${view.x} ${view.y} ${VB_W / view.k} ${VB_H / view.k}`}
                  className="h-auto min-w-[760px] w-full cursor-grab touch-none select-none active:cursor-grabbing"
                  role="img"
                  aria-label="Threat graph: entities linked to incidents"
                  onPointerDown={onPointerDown}
                  onPointerMove={onPointerMove}
                  onPointerUp={onPointerUp}
                  onPointerCancel={onPointerUp}
                >
                {/* faint ring guides */}
                <circle cx={CX} cy={CY} r={R_INCIDENT} fill="none" stroke="oklch(1 0 0 / 4%)" strokeDasharray="2 6" />
                <circle cx={CX} cy={CY} r={R_ENTITY} fill="none" stroke="oklch(1 0 0 / 3%)" strokeDasharray="2 6" />
                <circle cx={CX} cy={CY} r={R_ENTITY + 46} fill="none" stroke="oklch(1 0 0 / 2%)" strokeDasharray="2 6" />

                {/* links */}
                {data.links.map((l) => {
                  const s = positions.get(l.source);
                  const t = positions.get(l.target);
                  if (!s || !t) return null;
                  const sev = severityStyle(l.severity);
                  const mx = (s.x + t.x) / 2;
                  const my = (s.y + t.y) / 2;
                  // control point pulled toward center → gentle arc
                  const cx = mx + (CX - mx) * 0.22;
                  const cy = my + (CY - my) * 0.22;
                  const active = hoverId === l.source || hoverId === l.target;
                  const dim = hoverId && !active;
                  const hidden = !linkVisible(l.source, l.target);
                  if (hidden) return null;
                  return (
                    <path
                      key={`${l.source}->${l.target}`}
                      d={`M ${s.x} ${s.y} Q ${cx} ${cy} ${t.x} ${t.y}`}
                      fill="none"
                      stroke={sev.hex}
                      strokeWidth={active ? 2.4 : 1.1}
                      strokeOpacity={active ? 0.9 : dim ? 0.08 : 0.3}
                      className="transition-all duration-200"
                    />
                  );
                })}

                {/* entity nodes */}
                {data.nodes
                  .filter((n) => n.kind === "entity" && entityVisible(n) && positions.has(n.id))
                  .map((n) => {
                    const p = positions.get(n.id)!;
                    return (
                      <EntityGlyph
                        key={n.id}
                        node={n}
                        x={p.x}
                        y={p.y}
                        hovered={hoverId === n.id}
                        dimmed={isDimmed(n.id)}
                        onClick={() => openNode(n)}
                        onFocus={() => setHoverId(n.id)}
                      />
                    );
                  })}

                {/* incident nodes on top */}
                {incidents
                  .filter((n) => positions.has(n.id))
                  .map((n) => {
                    const p = positions.get(n.id)!;
                    return (
                      <IncidentGlyph
                        key={n.id}
                        node={n}
                        x={p.x}
                        y={p.y}
                        hovered={hoverId === n.id}
                        dimmed={isDimmed(n.id)}
                        onClick={() => openNode(n)}
                        onFocus={() => setHoverId(n.id)}
                      />
                    );
                  })}
              </svg>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
