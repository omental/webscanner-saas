"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

import { apiClient } from "@/lib/api-client";
import { Organization, Package } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";

function toDateTimeLocal(value: string | null) {
  return value ? value.slice(0, 16) : "";
}

function fromDateTimeLocal(value: string) {
  return value ? new Date(value).toISOString() : null;
}

export function OrganizationsManager() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [packages, setPackages] = useState<Package[]>([]);

  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [packageId, setPackageId] = useState("");

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [packageFilter, setPackageFilter] = useState("all");

  const [packageDrafts, setPackageDrafts] = useState<Record<number, string>>({});
  const [subscriptionDrafts, setSubscriptionDrafts] = useState<any>({});

  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  const [savingPackageId, setSavingPackageId] = useState<number | null>(null);
  const [savingSubscriptionId, setSavingSubscriptionId] = useState<number | null>(
    null
  );
  const [startingTrialId, setStartingTrialId] = useState<number | null>(null);

  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  async function loadData() {
    try {
      setLoading(true);
      setError(null);

      const [orgs, pkgs] = await Promise.all([
        apiClient.listOrganizations(),
        apiClient.listPackages(),
      ]);

      setOrganizations(Array.isArray(orgs) ? orgs : []);
      setPackages(Array.isArray(pkgs) ? pkgs : []);

      setPackageDrafts(
        Object.fromEntries(
          orgs.map((org) => [org.id, org.package_id?.toString() ?? ""])
        )
      );

      setSubscriptionDrafts(
        Object.fromEntries(
          orgs.map((org) => [
            org.id,
            {
              subscription_status: org.subscription_status,
              subscription_start: toDateTimeLocal(org.subscription_start),
              subscription_end: toDateTimeLocal(org.subscription_end),
              trial_ends_at: toDateTimeLocal(org.trial_ends_at),
            },
          ])
        )
      );
    } catch {
      setError("Unable to load organizations.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadData();
  }, []);

  useEffect(() => {
    if (!success) return;

    const timer = window.setTimeout(() => {
      setSuccess(null);
    }, 3500);

    return () => window.clearTimeout(timer);
  }, [success]);

  const filteredOrganizations = useMemo(() => {
    const query = search.trim().toLowerCase();

    return organizations.filter((org) => {
      const matchesSearch =
        !query ||
        org.name.toLowerCase().includes(query) ||
        org.slug.toLowerCase().includes(query);

      const matchesStatus =
        statusFilter === "all" || org.status === statusFilter;

      const currentPackageId = org.package_id?.toString() ?? "";
      const matchesPackage =
        packageFilter === "all" ||
        (packageFilter === "none" && !currentPackageId) ||
        currentPackageId === packageFilter;

      return matchesSearch && matchesStatus && matchesPackage;
    });
  }, [organizations, search, statusFilter, packageFilter]);

  const stats = useMemo(() => {
    return {
      total: organizations.length,
      active: organizations.filter((org) => org.status === "active").length,
      trial: organizations.filter((org) => org.subscription_status === "trial")
        .length,
      noPackage: organizations.filter((org) => !org.package_id).length,
    };
  }, [organizations]);

  async function handleCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    try {
      setSubmitting(true);
      setError(null);
      setSuccess(null);

      await apiClient.createOrganization({
        name,
        slug,
        package_id: packageId ? Number(packageId) : null,
        status: "active",
      });

      setName("");
      setSlug("");
      setPackageId("");
      setSuccess("Organization created successfully.");

      await loadData();
    } catch {
      setError("Unable to create organization.");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleAssignPackage(organizationId: number) {
    try {
      setSavingPackageId(organizationId);
      setError(null);
      setSuccess(null);

      await apiClient.assignOrganizationPackage(
        organizationId,
        packageDrafts[organizationId]
          ? Number(packageDrafts[organizationId])
          : null
      );

      setSuccess("Package updated successfully.");
      await loadData();
    } catch {
      setError("Unable to assign package.");
    } finally {
      setSavingPackageId(null);
    }
  }

  async function handleSaveSubscription(organizationId: number) {
    const draft = subscriptionDrafts[organizationId];

    if (!draft) return;

    try {
      setSavingSubscriptionId(organizationId);
      setError(null);
      setSuccess(null);

      await apiClient.updateOrganizationSubscription(organizationId, {
        subscription_status: draft.subscription_status,
        subscription_start: fromDateTimeLocal(draft.subscription_start),
        subscription_end: fromDateTimeLocal(draft.subscription_end),
        trial_ends_at: fromDateTimeLocal(draft.trial_ends_at),
      });

      setSuccess("Subscription updated successfully.");
      await loadData();
    } catch {
      setError("Unable to save subscription.");
    } finally {
      setSavingSubscriptionId(null);
    }
  }

  async function handleStartTrial(organizationId: number) {
    try {
      setStartingTrialId(organizationId);
      setError(null);
      setSuccess(null);

      await apiClient.startOrganizationTrial(organizationId, 14);

      setSuccess("14-day trial started successfully.");
      await loadData();
    } catch {
      setError("Unable to start trial.");
    } finally {
      setStartingTrialId(null);
    }
  }

  function updateSubscriptionDraft(
    organizationId: number,
    field:
      | "subscription_status"
      | "subscription_start"
      | "subscription_end"
      | "trial_ends_at",
    value: string
  ) {
    setSubscriptionDrafts((current: any) => ({
      ...current,
      [organizationId]: {
        ...current[organizationId],
        [field]: value,
      },
    }));
  }

  function getPackageName(id?: number | null) {
    if (!id) return "No package";
    return packages.find((item) => item.id === id)?.name || "Unknown package";
  }

  return (
    <section className="space-y-6">
      {success ? (
        <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-700">
          {success}
        </div>
      ) : null}

      {error ? (
        <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-700">
          {error}
        </div>
      ) : null}

      <div className="grid gap-4 md:grid-cols-4">
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <p className="text-sm font-medium text-slate-500">Total</p>
          <p className="mt-3 text-3xl font-semibold text-slate-950">
            {stats.total}
          </p>
        </div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <p className="text-sm font-medium text-slate-500">Active</p>
          <p className="mt-3 text-3xl font-semibold text-emerald-600">
            {stats.active}
          </p>
        </div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <p className="text-sm font-medium text-slate-500">Trial</p>
          <p className="mt-3 text-3xl font-semibold text-blue-600">
            {stats.trial}
          </p>
        </div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <p className="text-sm font-medium text-slate-500">No Package</p>
          <p className="mt-3 text-3xl font-semibold text-amber-600">
            {stats.noPackage}
          </p>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <h3 className="text-lg font-semibold text-slate-950">
          Create Organization
        </h3>
        <p className="mt-1 text-sm text-slate-500">
          Add a new tenant and optionally assign a package.
        </p>

        <form
          onSubmit={handleCreate}
          className="mt-5 grid gap-4 md:grid-cols-[1fr_1fr_1fr_auto]"
        >
          <Input
            label="Name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            required
          />

          <Input
            label="Slug"
            value={slug}
            onChange={(event) => setSlug(event.target.value)}
            required
          />

          <Select
            label="Package"
            value={packageId}
            onChange={(event) => setPackageId(event.target.value)}
          >
            <option value="">No package</option>
            {packages.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </Select>

          <div className="flex items-end">
            <Button type="submit" fullWidth disabled={submitting}>
              {submitting ? "Creating..." : "Create"}
            </Button>
          </div>
        </form>
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="border-b border-slate-200 px-6 py-5">
          <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-center">
            <div>
              <h3 className="text-base font-semibold text-slate-950">
                Organizations
              </h3>
              <p className="mt-1 text-sm text-slate-500">
                Search, filter, assign packages, and manage subscription status.
              </p>
            </div>

            <Button variant="secondary" onClick={() => void loadData()}>
              Refresh
            </Button>
          </div>

          <div className="mt-5 grid gap-3 md:grid-cols-[1fr_180px_220px]">
            <Input
              label="Search"
              placeholder="Search name or slug..."
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />

            <Select
              label="Status"
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value)}
            >
              <option value="all">All statuses</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
              <option value="suspended">Suspended</option>
            </Select>

            <Select
              label="Package"
              value={packageFilter}
              onChange={(event) => setPackageFilter(event.target.value)}
            >
              <option value="all">All packages</option>
              <option value="none">No package</option>
              {packages.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))}
            </Select>
          </div>
        </div>

        {loading ? (
          <div className="p-6 text-sm text-slate-500">Loading...</div>
        ) : filteredOrganizations.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <p className="text-sm font-medium text-slate-900">
              No organizations found.
            </p>
            <p className="mt-1 text-sm text-slate-500">
              Try changing your filters or create a new organization.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-100">
            {filteredOrganizations.map((org) => {
              const draft = subscriptionDrafts[org.id];

              return (
                <div key={org.id} className="space-y-5 p-6">
                  <div className="flex flex-col justify-between gap-4 md:flex-row md:items-start">
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <h4 className="font-semibold text-slate-950">
                          {org.name}
                        </h4>
                        <span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-700">
                          {org.status}
                        </span>
                        <span className="rounded-full bg-blue-50 px-3 py-1 text-xs font-medium text-blue-700">
                          {getPackageName(org.package_id)}
                        </span>
                      </div>

                      <p className="mt-1 text-sm text-slate-500">
                        Slug: <span className="font-mono">{org.slug}</span>
                      </p>
                    </div>
                  </div>

                  <div className="grid gap-4 rounded-xl border border-slate-200 bg-slate-50 p-4 lg:grid-cols-[260px_1fr]">
                    <div>
                      <p className="text-sm font-semibold text-slate-900">
                        Package Assignment
                      </p>
                      <p className="mt-1 text-xs text-slate-500">
                        Change the organization package.
                      </p>

                      <div className="mt-4 flex gap-3">
                        <Select
                          label="Package"
                          value={packageDrafts[org.id] ?? ""}
                          onChange={(event) =>
                            setPackageDrafts((current) => ({
                              ...current,
                              [org.id]: event.target.value,
                            }))
                          }
                        >
                          <option value="">No package</option>
                          {packages.map((item) => (
                            <option key={item.id} value={item.id}>
                              {item.name}
                            </option>
                          ))}
                        </Select>

                        <div className="flex items-end">
                          <Button
                            onClick={() => void handleAssignPackage(org.id)}
                            disabled={savingPackageId === org.id}
                          >
                            {savingPackageId === org.id ? "Saving..." : "Save"}
                          </Button>
                        </div>
                      </div>
                    </div>

                    <div>
                      <p className="text-sm font-semibold text-slate-900">
                        Subscription
                      </p>
                      <p className="mt-1 text-xs text-slate-500">
                        Manage status, billing period, and trial window.
                      </p>

                      <div className="mt-4 grid gap-3 md:grid-cols-4">
                        <Select
                          label="Status"
                          value={draft?.subscription_status ?? "active"}
                          onChange={(event) =>
                            updateSubscriptionDraft(
                              org.id,
                              "subscription_status",
                              event.target.value
                            )
                          }
                        >
                          <option value="active">Active</option>
                          <option value="trial">Trial</option>
                          <option value="expired">Expired</option>
                          <option value="suspended">Suspended</option>
                        </Select>

                        <Input
                          type="datetime-local"
                          label="Start"
                          value={draft?.subscription_start || ""}
                          onChange={(event) =>
                            updateSubscriptionDraft(
                              org.id,
                              "subscription_start",
                              event.target.value
                            )
                          }
                        />

                        <Input
                          type="datetime-local"
                          label="End"
                          value={draft?.subscription_end || ""}
                          onChange={(event) =>
                            updateSubscriptionDraft(
                              org.id,
                              "subscription_end",
                              event.target.value
                            )
                          }
                        />

                        <Input
                          type="datetime-local"
                          label="Trial Ends"
                          value={draft?.trial_ends_at || ""}
                          onChange={(event) =>
                            updateSubscriptionDraft(
                              org.id,
                              "trial_ends_at",
                              event.target.value
                            )
                          }
                        />
                      </div>

                      <div className="mt-4 flex flex-wrap gap-2">
                        <Button
                          onClick={() => void handleSaveSubscription(org.id)}
                          disabled={savingSubscriptionId === org.id}
                        >
                          {savingSubscriptionId === org.id
                            ? "Saving..."
                            : "Save Subscription"}
                        </Button>

                        <Button
                          variant="secondary"
                          onClick={() => void handleStartTrial(org.id)}
                          disabled={startingTrialId === org.id}
                        >
                          {startingTrialId === org.id
                            ? "Starting..."
                            : "Start 14-day Trial"}
                        </Button>
                      </div>
                    </div>
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