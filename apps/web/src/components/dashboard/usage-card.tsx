"use client";

import { useEffect, useMemo, useState } from "react";

import { apiClient } from "@/lib/api-client";
import { Usage } from "@/lib/types";

function statusClass(status: string) {
  const value = status.toLowerCase();

  if (value === "active") return "bg-emerald-50 text-emerald-700 ring-emerald-200";
  if (value === "trial") return "bg-blue-50 text-blue-700 ring-blue-200";
  if (value === "expired") return "bg-red-50 text-red-700 ring-red-200";
  if (value === "suspended") return "bg-amber-50 text-amber-700 ring-amber-200";

  return "bg-slate-100 text-slate-700 ring-slate-200";
}

export function UsageCard() {
  const [usage, setUsage] = useState<Usage | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadUsage() {
      try {
        setError(null);
        setUsage(await apiClient.getMyUsage());
      } catch {
        setError("Unable to load weekly scan usage.");
      }
    }

    void loadUsage();
  }, []);

  const usageStats = useMemo(() => {
    if (!usage) {
      return {
        used: 0,
        limit: 0,
        remaining: 0,
        percent: 0,
      };
    }

    const isTrial = usage.subscription_status === "trial";

    const used = isTrial
      ? Number(usage.trial_scans_used || 0)
      : Number(usage.scans_used_this_week || 0);

    const limit = isTrial
      ? Number(usage.trial_scan_limit || 0)
      : Number(usage.scan_limit_per_week || 0);

    const remaining = isTrial
      ? Math.max(limit - used, 0)
      : Number(usage.scans_remaining_this_week || 0);

    const percent = limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 0;

    return {
      used,
      limit,
      remaining,
      percent,
    };
  }, [usage]);

  if (error) {
    return (
      <div className="rounded-2xl border border-red-200 bg-red-50 p-6 text-sm text-red-700 shadow-sm">
        {error}
      </div>
    );
  }

  if (!usage) {
    return (
      <div className="rounded-2xl border border-slate-200 bg-white p-6 text-sm text-slate-500 shadow-sm">
        Loading weekly scan usage...
      </div>
    );
  }

  const trial = usage.subscription_status === "trial";
  const trialEnds = usage.trial_ends_at
    ? new Date(usage.trial_ends_at).toLocaleDateString()
    : "Not set";

  const limitReached =
    trial ? usage.is_trial_limit_reached : usageStats.remaining <= 0;

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
        <div>
          <p className="text-sm font-medium uppercase tracking-wide text-blue-600">
            {trial ? "14-day free trial" : "Subscription"}
          </p>

          <h3 className="mt-2 text-2xl font-semibold tracking-tight text-slate-950">
            {usage.package_name ?? "No package"}
          </h3>

          <p className="mt-2 text-sm text-slate-500">
            {trial
              ? `Trial ends: ${trialEnds}`
              : `Status: ${usage.subscription_status}`}
          </p>
        </div>

        <span
          className={`inline-flex w-fit rounded-full px-3 py-1 text-xs font-medium capitalize ring-1 ring-inset ${statusClass(
            usage.subscription_status
          )}`}
        >
          {usage.subscription_status}
        </span>
      </div>

      <div className="mt-6">
        <div className="mb-2 flex items-center justify-between text-sm">
          <span className="font-medium text-slate-700">
            {trial ? "Trial scan usage" : "Weekly scan usage"}
          </span>
          <span className="font-semibold text-slate-950">
            {usageStats.used} / {usageStats.limit}
          </span>
        </div>

        <div className="h-3 overflow-hidden rounded-full bg-slate-100">
          <div
            className={[
              "h-full rounded-full transition-all",
              limitReached
                ? "bg-red-500"
                : usageStats.percent >= 70
                  ? "bg-amber-500"
                  : "bg-blue-600",
            ].join(" ")}
            style={{ width: `${usageStats.percent}%` }}
          />
        </div>

        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
          <span>{usageStats.percent}% used</span>
          <span>{usageStats.remaining} remaining</span>
        </div>
      </div>

      {limitReached ? (
        <div className="mt-5 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
          {trial
            ? "Your free trial includes 1 scan. Upgrade to continue scanning."
            : "Your weekly scan limit has been reached. Upgrade your package to continue scanning."}
        </div>
      ) : null}
    </div>
  );
}