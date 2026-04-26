"use client";

import { useEffect, useState } from "react";

import { apiClient } from "@/lib/api-client";
import { getSessionUser, isSuperAdmin } from "@/lib/session";
import { Package } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";

type PackageDraft = {
  name: string;
  slug: string;
  scan_limit_per_week: string;
  price_monthly: string;
  status: string;
};

function draftForPackage(item: Package): PackageDraft {
  return {
    name: item.name,
    slug: item.slug,
    scan_limit_per_week: String(item.scan_limit_per_week),
    price_monthly: String(item.price_monthly),
    status: item.status
  };
}

export function PackagesPanel() {
  const [packages, setPackages] = useState<Package[]>([]);
  const [drafts, setDrafts] = useState<Record<number, PackageDraft>>({});
  const [loading, setLoading] = useState(true);
  const [savingId, setSavingId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const superAdmin = isSuperAdmin(getSessionUser());

  async function loadPackages() {
    try {
      setLoading(true);
      setError(null);
      const nextPackages = await apiClient.listPackages();
      setPackages(nextPackages);
      setDrafts(
        Object.fromEntries(
          nextPackages.map((item) => [item.id, draftForPackage(item)])
        )
      );
    } catch {
      setError("Unable to load packages right now.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadPackages();
  }, []);

  function updateDraft(packageId: number, field: keyof PackageDraft, value: string) {
    setDrafts((current) => ({
      ...current,
      [packageId]: {
        ...current[packageId],
        [field]: value
      }
    }));
  }

  async function savePackage(packageId: number) {
    const draft = drafts[packageId];
    if (!draft) {
      return;
    }

    try {
      setSavingId(packageId);
      setError(null);
      await apiClient.updatePackage(packageId, {
        name: draft.name,
        slug: draft.slug,
        scan_limit_per_week: Number(draft.scan_limit_per_week),
        price_monthly: draft.price_monthly,
        status: draft.status
      });
      await loadPackages();
    } catch {
      setError("Unable to save package.");
    } finally {
      setSavingId(null);
    }
  }

return (
  <section className="space-y-6">

    {/* HEADER */}
    <div className="flex flex-col justify-between gap-4 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm sm:flex-row sm:items-center">
      <div>
        <p className="text-sm font-medium uppercase tracking-wide text-blue-600">
          Packages
        </p>
        <h2 className="mt-2 text-2xl font-semibold text-slate-950">
          Subscription plans
        </h2>
        <p className="mt-1 text-sm text-slate-500">
          Manage scan limits, pricing, and availability.
        </p>
      </div>

      <Button variant="secondary" onClick={() => void loadPackages()}>
        Refresh
      </Button>
    </div>

    {/* CONTENT */}
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      {loading ? (
        <p className="text-sm text-slate-500">Loading packages...</p>
      ) : error ? (
        <p className="text-sm text-red-600">{error}</p>
      ) : (
        <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
          {packages.map((item) => {
            const draft = drafts[item.id] ?? draftForPackage(item);

            return (
              <div
                key={item.id}
                className="rounded-2xl border border-slate-200 p-5 hover:shadow-md transition"
              >
                {/* TITLE */}
                <div className="mb-4">
                  <h3 className="text-lg font-semibold text-slate-900">
                    {draft.name}
                  </h3>
                  <p className="text-xs text-slate-500">
                    Slug: {draft.slug}
                  </p>
                </div>

                {/* FORM */}
                <div className="grid gap-4">
                  <Input
                    label="Name"
                    value={draft.name}
                    onChange={(e) =>
                      updateDraft(item.id, "name", e.target.value)
                    }
                    disabled={!superAdmin}
                  />

                  <Input
                    label="Slug"
                    value={draft.slug}
                    onChange={(e) =>
                      updateDraft(item.id, "slug", e.target.value)
                    }
                    disabled={!superAdmin}
                  />

                  <Input
                    label="Scan limit / week"
                    type="number"
                    value={draft.scan_limit_per_week}
                    onChange={(e) =>
                      updateDraft(item.id, "scan_limit_per_week", e.target.value)
                    }
                    disabled={!superAdmin}
                  />

                  <Input
                    label="Monthly price ($)"
                    type="number"
                    value={draft.price_monthly}
                    onChange={(e) =>
                      updateDraft(item.id, "price_monthly", e.target.value)
                    }
                    disabled={!superAdmin}
                  />

                  <Select
                    label="Status"
                    value={draft.status}
                    onChange={(e) =>
                      updateDraft(item.id, "status", e.target.value)
                    }
                    disabled={!superAdmin}
                  >
                    <option value="active">Active</option>
                    <option value="inactive">Inactive</option>
                  </Select>

                  {superAdmin && (
                    <Button
                      className="mt-2"
                      onClick={() => void savePackage(item.id)}
                      disabled={savingId === item.id}
                      fullWidth
                    >
                      {savingId === item.id ? "Saving..." : "Save package"}
                    </Button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  </section>
);
}
