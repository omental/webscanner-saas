"use client";

import { FormEvent, useEffect, useState } from "react";

import { apiClient } from "@/lib/api-client";
import { getSessionUser, SessionUser } from "@/lib/session";
import { Target } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/components/ui/toast-provider";

export function TargetsManager() {
  const { showToast } = useToast();

  const [sessionUser, setSessionUser] = useState<SessionUser | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [baseUrl, setBaseUrl] = useState("");

  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canCreateTarget =
    sessionUser?.role === "admin" || sessionUser?.role === "super_admin";

  async function loadTargets() {
    try {
      setLoading(true);
      setError(null);

      const data = await apiClient.listTargets();
      setTargets(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error("Failed to load targets", err);
      setError("Unable to load targets right now.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    setSessionUser(getSessionUser());
    void loadTargets();
  }, []);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!baseUrl.trim()) return;

    try {
      setSubmitting(true);
      setError(null);

      await apiClient.createTarget({
        user_id: sessionUser?.id ?? 1,
        base_url: baseUrl.trim(),
      });

      setBaseUrl("");
      showToast("Target created successfully.", "success");
      await loadTargets();
    } catch (err) {
      console.error("Failed to create target", err);
      setError("Unable to create target.");
      showToast("Unable to create target.", "error");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="space-y-6">
      <div className="flex flex-col justify-between gap-4 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm md:flex-row md:items-center">
        <div>
          <p className="text-sm font-medium uppercase tracking-wide text-blue-600">
            Targets
          </p>
          <h2 className="mt-2 text-2xl font-semibold tracking-tight text-slate-950">
            Target Inventory
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
            Manage the websites and applications that can be scanned by your
            workspace.
          </p>
        </div>

        <Button variant="secondary" onClick={() => void loadTargets()}>
          Refresh
        </Button>
      </div>

      {canCreateTarget ? (
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="mb-5">
            <h3 className="text-base font-semibold text-slate-950">
              Add a new target
            </h3>
            <p className="mt-1 text-sm text-slate-500">
              Enter a full URL, for example https://example.com.
            </p>
          </div>

          <form className="grid gap-4 md:grid-cols-[1fr_auto]" onSubmit={handleSubmit}>
            <Input
              label="Base URL"
              placeholder="https://example.com"
              value={baseUrl}
              onChange={(event) => setBaseUrl(event.target.value)}
              required
            />

            <div className="flex items-end">
              <Button type="submit" disabled={submitting}>
                {submitting ? "Creating..." : "Create Target"}
              </Button>
            </div>
          </form>

          {error ? (
            <p className="mt-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
              {error}
            </p>
          ) : null}
        </div>
      ) : null}

      <div className="rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="border-b border-slate-200 px-6 py-4">
          <h3 className="text-base font-semibold text-slate-950">
            Saved targets
          </h3>
          <p className="mt-1 text-sm text-slate-500">
            These targets are available for future scans.
          </p>
        </div>

        {loading ? (
          <div className="px-6 py-8 text-sm text-slate-500">
            Loading targets...
          </div>
        ) : error && targets.length === 0 ? (
          <div className="px-6 py-8 text-sm text-red-600">{error}</div>
        ) : targets.length === 0 ? (
          <div className="px-6 py-10 text-center">
            <p className="text-sm font-medium text-slate-900">
              No targets added yet.
            </p>
            <p className="mt-1 text-sm text-slate-500">
              Add your first target to start scanning.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-100">
            {targets.map((target) => (
              <div
                key={target.id}
                className="flex flex-col justify-between gap-3 px-6 py-4 transition hover:bg-slate-50 md:flex-row md:items-center"
              >
                <div>
                  <p className="font-medium text-slate-950">
                    {target.base_url}
                  </p>
                  <p className="mt-1 text-sm text-slate-500">
                    Domain: {target.normalized_domain || "—"}
                  </p>
                </div>

                <span className="w-fit rounded-full bg-emerald-50 px-3 py-1 text-xs font-medium text-emerald-700">
                  Active
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}