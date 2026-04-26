"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

import { apiClient } from "@/lib/api-client";
import { Scan, Target, Usage } from "@/lib/types";
import { getSessionUser, isAdmin, SessionUser } from "@/lib/session";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { ScanStatusBadge } from "@/components/dashboard/scan-status-badge";

export function ScansPageClient() {
  const router = useRouter();

  const [sessionUser, setSessionUser] = useState<SessionUser | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [usage, setUsage] = useState<Usage | null>(null);

  const [targetId, setTargetId] = useState("");
  const [scanType, setScanType] = useState("full");

  const [showAdvanced, setShowAdvanced] = useState(false);
  const [maxDepth, setMaxDepth] = useState("2");
  const [maxPages, setMaxPages] = useState("25");
  const [timeoutSeconds, setTimeoutSeconds] = useState("10");

  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canCreateScan = isAdmin(sessionUser);
  const trialBlocked =
    usage?.subscription_status === "trial" && usage.is_trial_limit_reached;

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const [targetsData, scansData, usageData] = await Promise.all([
        apiClient.listTargets(),
        apiClient.listScans(),
        apiClient.getMyUsage().catch(() => null),
      ]);

      setTargets(Array.isArray(targetsData) ? targetsData : []);
      setScans(Array.isArray(scansData) ? scansData : []);
      setUsage(usageData);

      if (!targetId && Array.isArray(targetsData) && targetsData.length > 0) {
        setTargetId(String(targetsData[0].id));
      }
    } catch (err) {
      console.error("Unable to load scan data", err);
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

    if (!sessionUser?.id) {
      setError("Please sign in again before creating a scan.");
      return;
    }

    if (!targetId) {
      setError("Please select a target before creating a scan.");
      return;
    }

    try {
      setSubmitting(true);
      setError(null);

      const createdScan = await apiClient.createScan({
        user_id: sessionUser.id,
        target_id: Number(targetId),
        scan_type: scanType,
        max_depth: Number(maxDepth) || 2,
        max_pages: Number(maxPages) || 25,
        timeout_seconds: Number(timeoutSeconds) || 10,
      });

      if (createdScan?.id) {
        router.push(`/dashboard/scans/${createdScan.id}`);
        return;
      }

      await loadData();
    } catch (scanError) {
      console.error("Unable to create scan", scanError);
      setError(
        scanError instanceof Error ? scanError.message : "Unable to create scan."
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="space-y-6">
      <div className="flex flex-col justify-between gap-4 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm md:flex-row md:items-center">
        <div>
          <p className="text-sm font-medium uppercase tracking-wide text-blue-600">
            Scans
          </p>
          <h2 className="mt-2 text-2xl font-semibold tracking-tight text-slate-950">
            Scan Jobs
          </h2>
          <p className="mt-1 text-sm text-slate-500">
            Create scans from existing targets and review scan history.
          </p>
        </div>

        <Button variant="secondary" onClick={() => void loadData()}>
          Refresh
        </Button>
      </div>

      {canCreateScan ? (
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="mb-5">
            <h3 className="text-base font-semibold text-slate-950">
              Create a new scan
            </h3>
            <p className="mt-1 text-sm text-slate-500">
              Select a saved target and choose the scan type.
            </p>
          </div>

          {trialBlocked ? (
            <div className="mb-5 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
              Your free trial includes 1 scan. Upgrade to continue scanning.
            </div>
          ) : null}

          {targets.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-200 p-6 text-center">
              <p className="text-sm font-medium text-slate-900">
                No targets available.
              </p>
              <p className="mt-1 text-sm text-slate-500">
                Add a target before creating a scan.
              </p>
              <Link
                href="/dashboard/targets"
                className="mt-4 inline-flex rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-700"
              >
                Add Target
              </Link>
            </div>
          ) : (
            <form className="space-y-5" onSubmit={handleSubmit}>
              <div className="grid gap-4 md:grid-cols-[1fr_220px_auto]">
                <Select
                  label="Target"
                  value={targetId}
                  onChange={(event) => setTargetId(event.target.value)}
                  disabled={loading || targets.length === 0 || submitting}
                >
                  {targets.map((target) => (
                    <option key={target.id} value={target.id}>
                      {target.normalized_domain || target.base_url}
                    </option>
                  ))}
                </Select>

                <Select
                  label="Scan type"
                  value={scanType}
                  onChange={(event) => setScanType(event.target.value)}
                  disabled={submitting}
                >
                  <option value="full">Full</option>
                  <option value="quick">Quick</option>
                </Select>

                <div className="flex items-end">
                  <Button
                    type="submit"
                    disabled={submitting || !targetId || Boolean(trialBlocked)}
                    fullWidth
                  >
                    {submitting ? "Creating..." : "Create Scan"}
                  </Button>
                </div>
              </div>

              <div>
                <button
                  type="button"
                  onClick={() => setShowAdvanced((value) => !value)}
                  className="text-sm font-medium text-blue-600 hover:text-blue-700"
                  disabled={submitting}
                >
                  {showAdvanced
                    ? "Hide advanced options"
                    : "Show advanced options"}
                </button>

                {showAdvanced ? (
                  <div className="mt-4 grid gap-4 rounded-xl border border-slate-200 bg-slate-50 p-4 md:grid-cols-3">
                    <label className="space-y-2">
                      <span className="text-sm font-medium text-slate-700">
                        Max depth
                      </span>
                      <input
                        type="number"
                        min="1"
                        className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
                        value={maxDepth}
                        disabled={submitting}
                        onChange={(event) => setMaxDepth(event.target.value)}
                      />
                      <span className="text-xs text-slate-500">Default: 2</span>
                    </label>

                    <label className="space-y-2">
                      <span className="text-sm font-medium text-slate-700">
                        Max pages
                      </span>
                      <input
                        type="number"
                        min="1"
                        className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
                        value={maxPages}
                        disabled={submitting}
                        onChange={(event) => setMaxPages(event.target.value)}
                      />
                      <span className="text-xs text-slate-500">
                        Default: 25
                      </span>
                    </label>

                    <label className="space-y-2">
                      <span className="text-sm font-medium text-slate-700">
                        Timeout seconds
                      </span>
                      <input
                        type="number"
                        min="1"
                        className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
                        value={timeoutSeconds}
                        disabled={submitting}
                        onChange={(event) =>
                          setTimeoutSeconds(event.target.value)
                        }
                      />
                      <span className="text-xs text-slate-500">
                        Default: 10
                      </span>
                    </label>
                  </div>
                ) : null}
              </div>

              {error ? (
                <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                  {error}
                </div>
              ) : null}
            </form>
          )}
        </div>
      ) : null}

      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="flex flex-col gap-3 border-b border-slate-200 px-6 py-5 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h3 className="text-base font-semibold text-slate-950">
              Recent scans
            </h3>
            <p className="mt-1 text-sm text-slate-500">
              Review recent scan runs and open detailed results.
            </p>
          </div>

          <Button variant="secondary" onClick={() => void loadData()}>
            Refresh
          </Button>
        </div>

        {loading ? (
          <div className="px-6 py-6 text-sm text-slate-500">
            Loading scans...
          </div>
        ) : error && scans.length === 0 ? (
          <div className="px-6 py-6 text-sm text-red-600">{error}</div>
        ) : scans.length === 0 ? (
          <div className="px-6 py-10 text-center">
            <p className="text-sm font-medium text-slate-900">No scans yet.</p>
            <p className="mt-1 text-sm text-slate-500">
              Create your first scan from the form above.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-100">
            {scans.map((scan) => {
              const target = targets.find((item) => item.id === scan.target_id);

              return (
                <Link
                  key={scan.id}
                  href={`/dashboard/scans/${scan.id}`}
                  className="block px-6 py-4 transition hover:bg-slate-50"
                >
                  <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
                    <div>
                      <p className="font-medium text-slate-950">
                        {target?.normalized_domain ||
                          target?.base_url ||
                          `Target #${scan.target_id}`}
                      </p>
                      <p className="mt-1 text-sm text-slate-500">
                        Scan #{scan.id} · Type: {scan.scan_type}
                      </p>
                    </div>

                    <ScanStatusBadge status={scan.status} />
                  </div>
                </Link>
              );
            })}
          </div>
        )}
      </div>
    </section>
  );
}