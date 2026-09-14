"use client";

import { AlertTriangle, RotateCw } from "lucide-react";
import { Button } from "@/components/ui/button";

/** Shared async error state with retry action. */
export function ErrorState({
  message,
  onRetry,
  className,
}: {
  message?: string;
  onRetry: () => void;
  className?: string;
}) {
  return (
    <div
      role="alert"
      className={
        "flex flex-col items-center justify-center gap-3 rounded-xl border border-red-500/25 bg-red-500/5 p-8 text-center " +
        (className ?? "")
      }
    >
      <AlertTriangle className="size-6 text-red-400" aria-hidden="true" />
      <div>
        <p className="text-sm font-medium text-red-300">Couldn&apos;t load data</p>
        <p className="mt-1 max-w-sm text-xs text-muted-foreground">
          {message || "The SOC backend returned an error. The pipeline may still be ingesting — try again."}
        </p>
      </div>
      <Button variant="outline" size="sm" onClick={onRetry} className="min-h-9 gap-2">
        <RotateCw className="size-3.5" aria-hidden="true" />
        Retry
      </Button>
    </div>
  );
}
