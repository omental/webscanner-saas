"use client";

import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { apiClient, buildApiUrl } from "@/lib/api-client";
import { getSessionUser } from "@/lib/session";
import { Invoice } from "@/lib/types";

type InvoicesManagerProps = {
  superAdmin?: boolean;
};

function formatDate(value: string) {
  if (!value) return "—";
  return new Date(value).toLocaleDateString();
}

function statusClass(status: string) {
  const value = status.toLowerCase();

  if (value === "paid") {
    return "bg-emerald-50 text-emerald-700 ring-emerald-200";
  }

  if (value === "overdue" || value === "failed") {
    return "bg-red-50 text-red-700 ring-red-200";
  }

  if (value === "pending" || value === "unpaid") {
    return "bg-amber-50 text-amber-700 ring-amber-200";
  }

  return "bg-slate-100 text-slate-700 ring-slate-200";
}

export function InvoicesManager({ superAdmin = false }: InvoicesManagerProps) {
  const [invoices, setInvoices] = useState<Invoice[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloadingId, setDownloadingId] = useState<number | null>(null);
  const [markingPaidId, setMarkingPaidId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function loadInvoices() {
    try {
      setLoading(true);
      setError(null);

      const data = await apiClient.listInvoices();
      setInvoices(Array.isArray(data) ? data : []);
    } catch (invoiceError) {
      setError(
        invoiceError instanceof Error
          ? invoiceError.message
          : "Unable to load invoices."
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadInvoices();
  }, []);

  async function markPaid(invoice: Invoice) {
    try {
      setMarkingPaidId(invoice.id);
      setError(null);

      await apiClient.markInvoicePaid(invoice.id);
      await loadInvoices();
    } catch {
      setError("Unable to mark invoice as paid.");
    } finally {
      setMarkingPaidId(null);
    }
  }

  async function handleDownload(invoice: Invoice) {
    try {
      setDownloadingId(invoice.id);
      setError(null);

      const user = getSessionUser();

      if (!user?.id) {
        throw new Error("User session missing. Please sign in again.");
      }

      const response = await fetch(
        buildApiUrl(`/api/v1/invoices/${invoice.id}/download`),
        {
          method: "GET",
          credentials: "include",
          cache: "no-store",
          headers: {
            "X-Current-User-Id": String(user.id),
          },
        }
      );

      if (!response.ok) {
        const text = await response.text().catch(() => "");
        throw new Error(text || "Download failed.");
      }

      const blob = await response.blob();
      const downloadUrl = window.URL.createObjectURL(blob);

      const link = document.createElement("a");
      link.href = downloadUrl;
      link.download = `${invoice.invoice_number || `invoice-${invoice.id}`}.pdf`;
      document.body.appendChild(link);
      link.click();

      link.remove();
      window.URL.revokeObjectURL(downloadUrl);
    } catch (downloadError) {
      console.error("Invoice download failed", downloadError);
      setError(
        downloadError instanceof Error
          ? downloadError.message
          : "Unable to download invoice."
      );
    } finally {
      setDownloadingId(null);
    }
  }

  if (loading) {
    return (
      <div className="rounded-2xl border border-slate-200 bg-white p-6 text-sm text-slate-500 shadow-sm">
        Loading invoices...
      </div>
    );
  }

  if (error && invoices.length === 0) {
    return (
      <div className="rounded-2xl border border-red-200 bg-red-50 p-6 text-sm text-red-700">
        {error}
      </div>
    );
  }

  return (
    <section className="space-y-4">
      {error ? (
        <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-700">
          {error}
        </div>
      ) : null}

      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="flex flex-col justify-between gap-4 border-b border-slate-200 px-6 py-5 sm:flex-row sm:items-center">
          <div>
            <h3 className="text-base font-semibold text-slate-950">
              Invoices
            </h3>
            <p className="mt-1 text-sm text-slate-500">
              Review generated invoices and download PDF copies.
            </p>
          </div>

          <Button variant="secondary" onClick={() => void loadInvoices()}>
            Refresh
          </Button>
        </div>

        {invoices.length === 0 ? (
          <div className="px-6 py-10 text-center">
            <p className="text-sm font-medium text-slate-900">
              No invoices yet.
            </p>
            <p className="mt-1 text-sm text-slate-500">
              Generated billing invoices will appear here.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-6 py-3 font-medium">Invoice</th>
                  <th className="px-6 py-3 font-medium">Organization</th>
                  <th className="px-6 py-3 font-medium">Package</th>
                  <th className="px-6 py-3 font-medium">Amount</th>
                  <th className="px-6 py-3 font-medium">Status</th>
                  <th className="px-6 py-3 text-right font-medium">Actions</th>
                </tr>
              </thead>

              <tbody className="divide-y divide-slate-100">
                {invoices.map((invoice) => (
                  <tr key={invoice.id} className="hover:bg-slate-50">
                    <td className="px-6 py-4">
                      <p className="font-medium text-slate-950">
                        {invoice.invoice_number}
                      </p>
                      <p className="mt-1 text-xs text-slate-500">
                        Due {formatDate(invoice.due_date)}
                      </p>
                    </td>

                    <td className="px-6 py-4 text-slate-600">
                      {invoice.organization_name ?? `#${invoice.organization_id}`}
                    </td>

                    <td className="px-6 py-4 text-slate-600">
                      {invoice.package_name ?? "Package"}
                    </td>

                    <td className="px-6 py-4 font-medium text-slate-900">
                      {invoice.currency} {invoice.amount}
                    </td>

                    <td className="px-6 py-4">
                      <span
                        className={`inline-flex rounded-full px-3 py-1 text-xs font-medium capitalize ring-1 ring-inset ${statusClass(
                          invoice.status
                        )}`}
                      >
                        {invoice.status}
                      </span>
                    </td>

                    <td className="px-6 py-4">
                      <div className="flex flex-wrap justify-end gap-2">
                        <button
                          type="button"
                          onClick={() => void handleDownload(invoice)}
                          disabled={downloadingId === invoice.id}
                          className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-700 shadow-sm transition hover:bg-slate-50 hover:text-slate-950 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          {downloadingId === invoice.id
                            ? "Downloading..."
                            : "Download"}
                        </button>

                        {superAdmin && invoice.status !== "paid" ? (
                          <button
                            type="button"
                            onClick={() => void markPaid(invoice)}
                            disabled={markingPaidId === invoice.id}
                            className="rounded-lg border border-emerald-200 bg-white px-3 py-2 text-xs font-semibold text-emerald-700 shadow-sm transition hover:bg-emerald-50 disabled:cursor-not-allowed disabled:opacity-50"
                          >
                            {markingPaidId === invoice.id
                              ? "Saving..."
                              : "Mark paid"}
                          </button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}