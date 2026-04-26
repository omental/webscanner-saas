"use client";

import { useCallback, useEffect, useState } from "react";

import { InvoicesManager } from "@/components/dashboard/invoices-manager";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { apiClient } from "@/lib/api-client";
import { Organization } from "@/lib/types";

export function AdminBillingManager() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [organizationId, setOrganizationId] = useState("");

  const [generating, setGenerating] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadOrganizations = useCallback(async () => {
    try {
      const data = await apiClient.listOrganizations();
      setOrganizations(Array.isArray(data) ? data : []);

      if (!organizationId && data[0]) {
        setOrganizationId(String(data[0].id));
      }
    } catch {
      setError("Failed to load organizations.");
    }
  }, [organizationId]);

  useEffect(() => {
    void loadOrganizations();
  }, [loadOrganizations]);

  async function generateInvoice() {
    if (!organizationId) return;

    try {
      setGenerating(true);
      setMessage(null);
      setError(null);

      const invoice = await apiClient.generateBillingInvoice(
        Number(organizationId)
      );

      setMessage(`Invoice ${invoice.invoice_number} generated successfully.`);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Unable to generate invoice."
      );
    } finally {
      setGenerating(false);
    }
  }

  return (
    <section className="space-y-6">

      {/* HEADER */}
      <div className="flex flex-col justify-between gap-4 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm sm:flex-row sm:items-center">
        <div>
          <p className="text-sm font-medium uppercase tracking-wide text-blue-600">
            Billing
          </p>
          <h2 className="mt-2 text-2xl font-semibold text-slate-950">
            Admin Billing
          </h2>
          <p className="mt-1 text-sm text-slate-500">
            Generate invoices and manage organization billing.
          </p>
        </div>
      </div>

      {/* GENERATE INVOICE */}
      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="grid gap-4 md:grid-cols-[1fr_auto] md:items-end">

          <Select
            label="Organization"
            value={organizationId}
            onChange={(event) => setOrganizationId(event.target.value)}
          >
            {organizations.map((org) => (
              <option key={org.id} value={org.id}>
                {org.name}
              </option>
            ))}
          </Select>

          <Button
            onClick={() => void generateInvoice()}
            disabled={generating || !organizationId}
          >
            {generating ? "Generating..." : "Generate invoice"}
          </Button>
        </div>

        {/* FEEDBACK */}
        {message && (
          <div className="mt-4 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700">
            {message}
          </div>
        )}

        {error && (
          <div className="mt-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {error}
          </div>
        )}
      </div>

      {/* INVOICES LIST */}
      <InvoicesManager superAdmin />

    </section>
  );
}