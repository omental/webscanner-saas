"use client";

import { useEffect, useState } from "react";

import { apiClient, buildApiUrl } from "@/lib/api-client";
import { Usage } from "@/lib/types";

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

  if (error) {
    return (
      <div className="rounded-[1.75rem] border border-rose-400/20 bg-rose-400/10 p-6 text-sm text-rose-100">
        {error}
      </div>
    );
  }

  if (!usage) {
    return (
      <div className="rounded-[1.75rem] border border-white/10 bg-white/5 p-6 text-sm text-slate-400">
        Loading weekly scan usage...
      </div>
    );
  }

  const trial = usage.subscription_status === "trial";
  const trialEnds = usage.trial_ends_at
    ? new Date(usage.trial_ends_at).toLocaleDateString()
    : "Not set";

  return (
    <div className="rounded-[1.75rem] border border-white/10 bg-slate-950/70 p-6">
      <p className="text-sm uppercase tracking-[0.3em] text-cyan-300">
        {trial ? "14-day free trial" : "Subscription"}
      </p>
      <h3 className="mt-4 text-2xl font-semibold text-white">
        {usage.package_name ?? "No package"}
      </h3>
      {trial ? (
        <>
          <p className="mt-4 text-sm text-slate-300">Trial ends: {trialEnds}</p>
          <p className="mt-2 text-sm text-slate-300">
            Trial Scan: {usage.trial_scans_used} / {usage.trial_scan_limit}
          </p>
          {usage.is_trial_limit_reached ? (
            <p className="mt-3 rounded-2xl border border-amber-400/20 bg-amber-400/10 p-3 text-sm text-amber-100">
              Your free trial includes 1 scan. Upgrade to continue scanning.
            </p>
          ) : null}
        </>
      ) : (
        <>
          <p className="mt-4 text-sm text-slate-300">
            Status: {usage.subscription_status}
          </p>
          <p className="mt-2 text-sm text-slate-300">
            Scans used this week: {usage.scans_used_this_week} /{" "}
            {usage.scan_limit_per_week}
          </p>
          <p className="mt-2 text-sm text-slate-300">
            Remaining: {usage.scans_remaining_this_week}
          </p>
        </>
      )}
      {usage.current_invoice_status ? (
        <div className="mt-4 flex flex-col gap-3 border-t border-white/10 pt-4 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-sm text-slate-300">
            Invoice: {usage.current_invoice_status}
          </p>
          {usage.current_invoice_pdf_url ? (
            <a
              href={buildApiUrl(usage.current_invoice_pdf_url)}
              target="_blank"
              className="text-sm font-semibold text-cyan-300 hover:text-cyan-200"
            >
              Download invoice
            </a>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
