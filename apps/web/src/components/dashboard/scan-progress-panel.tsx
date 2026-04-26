"use client";

import { Scan } from "@/lib/types";

type ScanProgressPanelProps = {
  scan: Scan;
  targetLabel: string;
  compact?: boolean;
};

const statusColors: Record<string, string> = {
  queued: "bg-slate-400",
  pending: "bg-amber-500",
  running: "bg-indigo-600",
  completed: "bg-emerald-500",
  failed: "bg-rose-500",
  cancelled: "bg-slate-300"
};

export function ScanProgressPanel({
  scan,
  targetLabel,
  compact = false
}: ScanProgressPanelProps) {
  const status = scan.status.toLowerCase();
  const color = statusColors[status] || "bg-slate-400";
  const progress = scan.progress || 0;

  if (compact) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className={`h-2 w-2 rounded-full ${status === "running" ? "animate-pulse" : ""} ${color}`} />
            <p className="text-sm font-medium text-slate-700">
              Scanning <span className="text-indigo-600 font-semibold">{targetLabel}</span>
            </p>
          </div>
          <p className="text-xs font-bold text-indigo-600">{progress}%</p>
        </div>
        <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-slate-100">
          <div
            className={`h-full transition-all duration-500 ${color}`}
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-8 shadow-sm">
      <div className="flex flex-col gap-8 lg:flex-row lg:items-center lg:justify-between">
        <div className="space-y-1.5">
          <div className="flex items-center gap-3">
            <div className={`h-3 w-3 rounded-full ${status === "running" ? "animate-pulse shadow-[0_0_8px_currentColor]" : ""} ${color}`} />
            <p className="text-lg font-bold tracking-tight text-slate-900 uppercase">
              {status}
            </p>
          </div>
          <p className="text-sm text-slate-500 font-medium">
            Target: <span className="text-indigo-600">{targetLabel}</span>
          </p>
        </div>

        <div className="flex-1 lg:max-w-md">
          <div className="flex items-end justify-between gap-4 mb-2.5">
            <p className="text-xs font-bold uppercase tracking-widest text-slate-400">Scan Progress</p>
            <p className="text-xl font-black text-slate-900">{progress}%</p>
          </div>
          <div className="h-4 w-full overflow-hidden rounded-full bg-slate-100 p-1 border border-slate-200">
            <div
              className={`h-full rounded-full transition-all duration-1000 ease-out ${color}`}
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-8 lg:flex lg:gap-12">
          <div>
            <p className="text-xs font-bold uppercase tracking-widest text-slate-400">Pages</p>
            <p className="mt-1 text-2xl font-bold text-slate-900">{scan.total_pages_found}</p>
          </div>
          <div>
            <p className="text-xs font-bold uppercase tracking-widest text-slate-400">Findings</p>
            <p className="mt-1 text-2xl font-bold text-rose-500">{scan.total_findings}</p>
          </div>
        </div>
      </div>

      {scan.current_page_url ? (
        <div className="mt-8 border-t border-slate-100 pt-5">
          <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Analyzing Current Page</p>
          <p className="mt-1 truncate font-mono text-xs text-indigo-600 font-medium">
            {scan.current_page_url}
          </p>
        </div>
      ) : null}
    </div>
  );
}
