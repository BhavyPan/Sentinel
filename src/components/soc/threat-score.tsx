"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/utils";
import { scoreHex } from "@/lib/ui-helpers";

/**
 * Animated horizontal threat-score bar (0-100) + mono number.
 * Color follows the severity ramp (red ≥80, amber ≥60, yellow ≥40, emerald ≥20).
 */
export function ThreatScoreBar({
  score,
  className,
  showValue = true,
}: {
  score: number;
  className?: string;
  showValue?: boolean;
}) {
  const clamped = Math.max(0, Math.min(100, score));
  const color = scoreHex(clamped);
  return (
    <div className={cn("flex min-w-24 items-center gap-2", className)}>
      <div
        className="h-1.5 w-full min-w-14 overflow-hidden rounded-full bg-white/8"
        role="meter"
        aria-valuenow={clamped}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`Threat score ${clamped} of 100`}
      >
        <motion.div
          className="h-full rounded-full"
          style={{ backgroundColor: color }}
          initial={{ width: 0 }}
          animate={{ width: `${clamped}%` }}
          transition={{ duration: 0.8, ease: "easeOut" }}
        />
      </div>
      {showValue && (
        <span
          className="w-7 shrink-0 text-right font-mono text-xs font-semibold"
          style={{ color }}
        >
          {clamped}
        </span>
      )}
    </div>
  );
}

/**
 * Large radial gauge for the incident detail score panel.
 * SVG ring animated with framer-motion, score in the center.
 */
export function ScoreGauge({
  score,
  size = 132,
}: {
  score: number;
  size?: number;
}) {
  const clamped = Math.max(0, Math.min(100, score));
  const color = scoreHex(clamped);
  const stroke = 10;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const target = c * (1 - clamped / 100);

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90" aria-hidden="true">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="oklch(1 0 0 / 8%)"
          strokeWidth={stroke}
        />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          initial={{ strokeDashoffset: c }}
          animate={{ strokeDashoffset: target }}
          transition={{ duration: 1.1, ease: "easeOut" }}
          style={{ filter: `drop-shadow(0 0 6px ${color}55)` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span
          className="font-mono text-4xl font-bold tabular-nums"
          style={{ color }}
        >
          {clamped}
        </span>
        <span className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
          / 100
        </span>
      </div>
    </div>
  );
}
