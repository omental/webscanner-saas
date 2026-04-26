"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";

import { apiClient } from "@/lib/api-client";
import { Scan, Target, Usage } from "@/lib/types";
import { getSessionUser, isAdmin, SessionUser } from "@/lib/session";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";

export function ScansManager() {
  const [sessionUser, setSessionUser] = useState<SessionUser | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [usage, setUsage] = useState<Usage | null>(null);
  const [targetId, setTargetId] = useState("");
  const [scanType, setScanType] = useState("full");
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [targetsData, scansData, usageData] = await Promise.all([
        apiClient.listTargets(),
        apiClient.listScans(),
        apiClient.getMyUsage().catch(() => null)
      ]);
      setTargets(targetsData);
      setScans(scansData);
      setUsage(usageData);
      if (!targetId && targetsData.length > 0) {
        setTargetId(String(targetsData[0].id));
      }
    } catch {
      setError("Unable to load scan data right now.");
    } finally {
      setLoading(false);
    }
  }, [targetId]);

  useEffect(() => {
    setSessionUser(getSessionUser());
    void loadData();
  }, [loadData]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    try {
      setSubmitting(true);
      setError(null);
      await apiClient.createScan({
        user_id: sessionUser?.id ?? 1,
        target_id: Number(targetId),
        scan_type: scanType
      });
      await loadData();
    } catch (scanError) {
      setError(
        scanError instanceof Error ? scanError.message : "Unable to create scan."
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="space-y-6">
      <div className="grid gap-6 xl:grid-cols-[1.2fr_0.9fr]">
        <div className="rounded-[1.75rem] border border-white/10 bg-white/5 p-6">
          <p className="text-sm uppercase tracking-[0.3em] text-cyan-300">
            Welcome
          </p>
          <h3 className="mt-4 text-2xl font-semibold text-white">
            Backend-connected dashboard
          </h3>
          <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-300">
            This page now reads scans and targets from FastAPI and can queue a
            new scan against an existing target.
          </p>
        </div>

        <div className="rounded-[1.75rem] border border-white/10 bg-slate-950/70 p-6">
          <p className="text-sm font-medium text-slate-200">Current state</p>
          <ul className="mt-4 space-y-3 text-sm text-slate-300">
            <li>Targets loaded from API</li>
            <li>Scans loaded from API</li>
            <li>Scan creation posts to backend</li>
          </ul>
        </div>
      </div>

      {isAdmin(sessionUser) ? (
      <div className="rounded-[1.75rem] border border-white/10 bg-slate-950/70 p-6">
        {usage?.subscription_status === "trial" && usage.is_trial_limit_reached ? (
          <p className="mb-4 rounded-2xl border border-amber-400/20 bg-amber-400/10 p-3 text-sm text-amber-100">
            Your free trial includes 1 scan. Upgrade to continue scanning.
          </p>
        ) : null}
        <form className="grid gap-4 md:grid-cols-[1fr_1fr_auto]" onSubmit={handleSubmit}>
          <Select
            label="Target"
            value={targetId}
            onChange={(event) => setTargetId(event.target.value)}
            disabled={loading || targets.length === 0}
          >
            {targets.length === 0 ? (
              <option value="">No targets available</option>
            ) : null}
            {targets.map((target) => (
              <option key={target.id} value={target.id}>
                {target.normalized_domain}
              </option>
            ))}
          </Select>
          <Select
            label="Scan type"
            value={scanType}
            onChange={(event) => setScanType(event.target.value)}
          >
            <option value="full">Full</option>
            <option value="quick">Quick</option>
          </Select>
          <div className="flex items-end">
            <Button
              type="submit"
              disabled={
                submitting ||
                !targetId ||
                Boolean(
                  usage?.subscription_status === "trial" &&
                    usage.is_trial_limit_reached
                )
              }
              fullWidth
            >
              {submitting ? "Creating..." : "Create scan"}
            </Button>
          </div>
        </form>
        {error ? <p className="mt-4 text-sm text-rose-300">{error}</p> : null}
      </div>
      ) : null}

      <div className="rounded-[1.75rem] border border-white/10 bg-white/5 p-6">
        <div className="flex items-center justify-between gap-4">
          <p className="text-sm font-medium text-white">Recent scans</p>
          <Button variant="secondary" onClick={() => void loadData()}>
            Refresh
          </Button>
        </div>

        {loading ? (
          <p className="mt-4 text-sm text-slate-400">Loading scans...</p>
        ) : scans.length === 0 ? (
          <p className="mt-4 text-sm text-slate-400">
            No scans yet.
          </p>
        ) : (
          <div className="mt-4 space-y-3">
            {scans.map((scan) => (
              <div
                key={scan.id}
                className="flex flex-col gap-3 rounded-2xl border border-white/10 bg-slate-950/70 p-4 sm:flex-row sm:items-center sm:justify-between"
              >
                <div>
                  <p className="font-medium text-white">
                    Scan #{scan.id} for target #{scan.target_id}
                  </p>
                  <p className="mt-1 text-sm text-slate-400">
                    Type: {scan.scan_type}
                  </p>
                </div>
                <Badge>{scan.status}</Badge>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
