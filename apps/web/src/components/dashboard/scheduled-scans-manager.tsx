"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

import { apiClient } from "@/lib/api-client";
import { getSessionUser, isAdmin, SessionUser } from "@/lib/session";
import {
  ScanFrequency,
  ScanProfile,
  ScheduledScan,
  Target,
} from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { useToast } from "@/components/ui/toast-provider";

const FREQUENCY_OPTIONS: { value: ScanFrequency; label: string }[] = [
  { value: "weekly", label: "Weekly" },
  { value: "monthly", label: "Monthly" },
  { value: "custom", label: "Custom" },
];

const PROFILE_OPTIONS: { value: ScanProfile; label: string }[] = [
  { value: "passive", label: "Passive" },
  { value: "quick", label: "Quick" },
  { value: "standard", label: "Standard" },
  { value: "deep", label: "Deep" },
  { value: "aggressive", label: "Aggressive" },
];

function formatDateTime(value?: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function formatFrequency(value?: string | null) {
  if (!value) return "—";
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function targetLabelFor(targets: Target[], targetId: number) {
  const target = targets.find((t) => t.id === targetId);
  if (!target) return `Target #${targetId}`;
  return target.normalized_domain || target.base_url || `Target #${targetId}`;
}

function toDateTimeLocalInputValue(value: string | null | undefined) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  const yyyy = date.getFullYear();
  const mm = pad(date.getMonth() + 1);
  const dd = pad(date.getDate());
  const hh = pad(date.getHours());
  const mi = pad(date.getMinutes());
  return `${yyyy}-${mm}-${dd}T${hh}:${mi}`;
}

function fromDateTimeLocalInputValue(value: string) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toISOString();
}

function defaultNextRunInputValue() {
  const date = new Date();
  date.setDate(date.getDate() + 7);
  date.setSeconds(0, 0);
  return toDateTimeLocalInputValue(date.toISOString());
}

type EditState = {
  scan_profile: string;
  frequency: string;
  next_run_at: string;
  is_active: boolean;
};

export function ScheduledScansManager() {
  const { showToast } = useToast();

  const [sessionUser, setSessionUser] = useState<SessionUser | null>(null);
  const [schedules, setSchedules] = useState<ScheduledScan[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);

  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Create form state
  const [targetId, setTargetId] = useState("");
  const [scanProfile, setScanProfile] = useState<ScanProfile>("standard");
  const [frequency, setFrequency] = useState<ScanFrequency>("weekly");
  const [nextRunAt, setNextRunAt] = useState<string>(defaultNextRunInputValue());
  const [isActive, setIsActive] = useState(true);

  // Edit modal state
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editState, setEditState] = useState<EditState | null>(null);

  const canManage = isAdmin(sessionUser);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const [schedulesData, targetsData] = await Promise.all([
        apiClient.listScheduledScans(),
        apiClient.listTargets().catch(() => [] as Target[]),
      ]);

      setSchedules(Array.isArray(schedulesData) ? schedulesData : []);
      setTargets(Array.isArray(targetsData) ? targetsData : []);

      if (
        Array.isArray(targetsData) &&
        targetsData.length > 0 &&
        !targetId
      ) {
        setTargetId(String(targetsData[0].id));
      }
    } catch (err) {
      console.error("Failed to load scheduled scans", err);
      setError("Unable to load scheduled scans right now.");
    } finally {
      setLoading(false);
    }
  }, [targetId]);

  useEffect(() => {
    setSessionUser(getSessionUser());
    void loadData();
  }, [loadData]);

  async function handleCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!canManage) return;

    if (!targetId) {
      setError("Please select a target before scheduling a scan.");
      return;
    }

    if (!nextRunAt) {
      setError("Please choose a next run time.");
      return;
    }

    const isoNextRun = fromDateTimeLocalInputValue(nextRunAt);
    if (!isoNextRun) {
      setError("The next run date is invalid.");
      return;
    }

    try {
      setSubmitting(true);
      setError(null);

      await apiClient.createScheduledScan({
        target_id: Number(targetId),
        scan_profile: scanProfile,
        frequency,
        next_run_at: isoNextRun,
        is_active: isActive,
      });

      showToast("Scheduled scan created.", "success");
      setNextRunAt(defaultNextRunInputValue());
      await loadData();
    } catch (err) {
      console.error("Failed to create scheduled scan", err);
      const message =
        err instanceof Error && err.message
          ? err.message
          : "Unable to create scheduled scan.";
      setError(message);
      showToast(message, "error");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleToggleActive(schedule: ScheduledScan) {
    if (!canManage || busyId) return;
    setBusyId(schedule.id);

    try {
      if (schedule.is_active) {
        await apiClient.disableScheduledScan(schedule.id);
        showToast("Scheduled scan disabled.", "success");
      } else {
        await apiClient.updateScheduledScan(schedule.id, { is_active: true });
        showToast("Scheduled scan enabled.", "success");
      }
      await loadData();
    } catch (err) {
      console.error("Failed to toggle scheduled scan", err);
      const message =
        err instanceof Error && err.message
          ? err.message
          : "Unable to update scheduled scan.";
      showToast(message, "error");
    } finally {
      setBusyId(null);
    }
  }

  function startEdit(schedule: ScheduledScan) {
    setEditingId(schedule.id);
    setEditState({
      scan_profile: schedule.scan_profile || "standard",
      frequency: schedule.frequency || "weekly",
      next_run_at: toDateTimeLocalInputValue(schedule.next_run_at),
      is_active: schedule.is_active,
    });
  }

  function cancelEdit() {
    setEditingId(null);
    setEditState(null);
  }

  async function saveEdit() {
    if (!editingId || !editState) return;
    setBusyId(editingId);

    try {
      const payload: {
        scan_profile?: string;
        frequency?: string;
        next_run_at?: string;
        is_active?: boolean;
      } = {
        scan_profile: editState.scan_profile,
        frequency: editState.frequency,
        is_active: editState.is_active,
      };

      const iso = fromDateTimeLocalInputValue(editState.next_run_at);
      if (iso) payload.next_run_at = iso;

      await apiClient.updateScheduledScan(editingId, payload);
      showToast("Scheduled scan updated.", "success");
      cancelEdit();
      await loadData();
    } catch (err) {
      console.error("Failed to update scheduled scan", err);
      const message =
        err instanceof Error && err.message
          ? err.message
          : "Unable to update scheduled scan.";
      showToast(message, "error");
    } finally {
      setBusyId(null);
    }
  }

  const sortedSchedules = useMemo(() => {
    return [...schedules].sort((a, b) => {
      const aTime = new Date(a.next_run_at).getTime() || 0;
      const bTime = new Date(b.next_run_at).getTime() || 0;
      return aTime - bTime;
    });
  }, [schedules]);

  return (
    <section className="space-y-6">
      <div className="flex flex-col justify-between gap-4 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm md:flex-row md:items-center">
        <div>
          <p className="text-sm font-medium uppercase tracking-wide text-blue-600">
            Scheduled Scans
          </p>
          <h2 className="mt-2 text-2xl font-semibold tracking-tight text-slate-950">
            Recurring Scan Schedules
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
            Run scans automatically on a schedule for any of your targets. The
            next run will queue at the configured time and frequency.
          </p>
        </div>

        <Button variant="secondary" onClick={() => void loadData()}>
          Refresh
        </Button>
      </div>

      {canManage ? (
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="mb-5">
            <h3 className="text-base font-semibold text-slate-950">
              Schedule a new scan
            </h3>
            <p className="mt-1 text-sm text-slate-500">
              Choose a target, profile, and frequency. The first scan will run at
              the next run time.
            </p>
          </div>

          <form
            className="grid gap-4 md:grid-cols-2 xl:grid-cols-5"
            onSubmit={handleCreate}
          >
            <Select
              label="Target"
              value={targetId}
              onChange={(event) => setTargetId(event.target.value)}
              required
            >
              {targets.length === 0 ? (
                <option value="">No targets available</option>
              ) : (
                <>
                  <option value="" disabled>
                    Select target...
                  </option>
                  {targets.map((target) => (
                    <option key={target.id} value={target.id}>
                      {target.normalized_domain || target.base_url}
                    </option>
                  ))}
                </>
              )}
            </Select>

            <Select
              label="Scan profile"
              value={scanProfile}
              onChange={(event) =>
                setScanProfile(event.target.value as ScanProfile)
              }
            >
              {PROFILE_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </Select>

            <Select
              label="Frequency"
              value={frequency}
              onChange={(event) =>
                setFrequency(event.target.value as ScanFrequency)
              }
            >
              {FREQUENCY_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </Select>

            <Input
              label="Next run at"
              type="datetime-local"
              value={nextRunAt}
              onChange={(event) => setNextRunAt(event.target.value)}
              required
            />

            <div className="flex flex-col justify-between gap-3">
              <label className="flex items-center gap-3 rounded-xl border border-slate-200 bg-white px-4 py-2.5">
                <input
                  type="checkbox"
                  className="h-4 w-4 rounded border-slate-300"
                  checked={isActive}
                  onChange={(event) => setIsActive(event.target.checked)}
                />
                <span className="text-sm font-medium text-slate-700">
                  Active
                </span>
              </label>

              <Button type="submit" disabled={submitting || targets.length === 0}>
                {submitting ? "Creating..." : "Create schedule"}
              </Button>
            </div>
          </form>

          {error ? (
            <p className="mt-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
              {error}
            </p>
          ) : null}

          {targets.length === 0 ? (
            <p className="mt-4 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-700">
              You don&apos;t have any targets yet. Add one from the Targets page
              before creating a schedule.
            </p>
          ) : null}
        </div>
      ) : null}

      <div className="rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="border-b border-slate-200 px-6 py-4">
          <h3 className="text-base font-semibold text-slate-950">
            Active and inactive schedules
          </h3>
          <p className="mt-1 text-sm text-slate-500">
            All scheduled scans you have access to.
          </p>
        </div>

        {loading ? (
          <div className="px-6 py-8 text-sm text-slate-500">
            Loading scheduled scans...
          </div>
        ) : error && schedules.length === 0 ? (
          <div className="px-6 py-8 text-sm text-red-600">{error}</div>
        ) : sortedSchedules.length === 0 ? (
          <div className="px-6 py-10 text-center">
            <p className="text-sm font-medium text-slate-900">
              No scheduled scans yet.
            </p>
            <p className="mt-1 text-sm text-slate-500">
              {canManage
                ? "Use the form above to create your first schedule."
                : "Ask a workspace admin to schedule scans for your targets."}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 text-slate-500">
                <tr>
                  <th className="px-6 py-3 text-left font-medium">Target</th>
                  <th className="px-6 py-3 text-left font-medium">Profile</th>
                  <th className="px-6 py-3 text-left font-medium">Frequency</th>
                  <th className="px-6 py-3 text-left font-medium">Next run</th>
                  <th className="px-6 py-3 text-left font-medium">Last run</th>
                  <th className="px-6 py-3 text-left font-medium">Status</th>
                  <th className="px-6 py-3 text-right font-medium">Actions</th>
                </tr>
              </thead>

              <tbody className="divide-y divide-slate-100">
                {sortedSchedules.map((schedule) => {
                  const isEditing = editingId === schedule.id;
                  const isBusy = busyId === schedule.id;

                  return (
                    <tr key={schedule.id} className="align-top">
                      <td className="px-6 py-4 font-medium text-slate-950">
                        {targetLabelFor(targets, schedule.target_id)}
                      </td>

                      <td className="px-6 py-4 text-slate-700">
                        {isEditing && editState ? (
                          <select
                            className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-sm"
                            value={editState.scan_profile}
                            onChange={(event) =>
                              setEditState((current) =>
                                current
                                  ? {
                                      ...current,
                                      scan_profile: event.target.value,
                                    }
                                  : current
                              )
                            }
                          >
                            {PROFILE_OPTIONS.map((option) => (
                              <option key={option.value} value={option.value}>
                                {option.label}
                              </option>
                            ))}
                          </select>
                        ) : (
                          formatFrequency(schedule.scan_profile)
                        )}
                      </td>

                      <td className="px-6 py-4 text-slate-700">
                        {isEditing && editState ? (
                          <select
                            className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-sm"
                            value={editState.frequency}
                            onChange={(event) =>
                              setEditState((current) =>
                                current
                                  ? {
                                      ...current,
                                      frequency: event.target.value,
                                    }
                                  : current
                              )
                            }
                          >
                            {FREQUENCY_OPTIONS.map((option) => (
                              <option key={option.value} value={option.value}>
                                {option.label}
                              </option>
                            ))}
                          </select>
                        ) : (
                          formatFrequency(schedule.frequency)
                        )}
                      </td>

                      <td className="px-6 py-4 text-slate-700">
                        {isEditing && editState ? (
                          <input
                            type="datetime-local"
                            className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-sm"
                            value={editState.next_run_at}
                            onChange={(event) =>
                              setEditState((current) =>
                                current
                                  ? {
                                      ...current,
                                      next_run_at: event.target.value,
                                    }
                                  : current
                              )
                            }
                          />
                        ) : (
                          formatDateTime(schedule.next_run_at)
                        )}
                      </td>

                      <td className="px-6 py-4 text-slate-700">
                        {formatDateTime(schedule.last_run_at)}
                      </td>

                      <td className="px-6 py-4">
                        {isEditing && editState ? (
                          <label className="inline-flex items-center gap-2 text-xs font-medium text-slate-700">
                            <input
                              type="checkbox"
                              className="h-4 w-4 rounded border-slate-300"
                              checked={editState.is_active}
                              onChange={(event) =>
                                setEditState((current) =>
                                  current
                                    ? {
                                        ...current,
                                        is_active: event.target.checked,
                                      }
                                    : current
                                )
                              }
                            />
                            Active
                          </label>
                        ) : schedule.is_active ? (
                          <span className="inline-flex rounded-full bg-emerald-50 px-2.5 py-1 text-xs font-medium text-emerald-700">
                            Active
                          </span>
                        ) : (
                          <span className="inline-flex rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600">
                            Disabled
                          </span>
                        )}
                      </td>

                      <td className="px-6 py-4 text-right">
                        {canManage ? (
                          <div className="flex flex-wrap justify-end gap-2">
                            {isEditing ? (
                              <>
                                <button
                                  type="button"
                                  onClick={() => void saveEdit()}
                                  disabled={isBusy}
                                  className="rounded-lg border border-blue-200 bg-blue-50 px-3 py-1.5 text-xs font-semibold text-blue-700 transition hover:bg-blue-100 disabled:opacity-60"
                                >
                                  {isBusy ? "Saving..." : "Save"}
                                </button>
                                <button
                                  type="button"
                                  onClick={cancelEdit}
                                  disabled={isBusy}
                                  className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 transition hover:bg-slate-50 disabled:opacity-60"
                                >
                                  Cancel
                                </button>
                              </>
                            ) : (
                              <>
                                <button
                                  type="button"
                                  onClick={() => startEdit(schedule)}
                                  disabled={isBusy}
                                  className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 transition hover:bg-slate-50 disabled:opacity-60"
                                >
                                  Edit
                                </button>
                                <button
                                  type="button"
                                  onClick={() => void handleToggleActive(schedule)}
                                  disabled={isBusy}
                                  className={[
                                    "rounded-lg px-3 py-1.5 text-xs font-semibold transition disabled:opacity-60",
                                    schedule.is_active
                                      ? "border border-amber-200 bg-amber-50 text-amber-700 hover:bg-amber-100"
                                      : "border border-emerald-200 bg-emerald-50 text-emerald-700 hover:bg-emerald-100",
                                  ].join(" ")}
                                >
                                  {isBusy
                                    ? "Working..."
                                    : schedule.is_active
                                    ? "Disable"
                                    : "Enable"}
                                </button>
                              </>
                            )}
                          </div>
                        ) : (
                          <span className="text-xs text-slate-400">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
