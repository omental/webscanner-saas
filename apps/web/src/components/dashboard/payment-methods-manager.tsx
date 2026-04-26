"use client";

import { FormEvent, useEffect, useState } from "react";

import { apiClient } from "@/lib/api-client";
import { PaymentMethod } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

type Draft = {
  description: string;
  displayName: string;
  mode: "test" | "live";
  publicKey: string;
  secretKey: string;
  webhookSecret: string;
  webhookEnabled: boolean;
  bankName: string;
  accountName: string;
  accountNumber: string;
  iban: string;
  swift: string;
  routingNumber: string;
  instructions: string;
};

const gatewaySlugs = new Set(["stripe", "paypal"]);

function readConfigValue(
  config: Record<string, unknown> | null,
  key: string
): string {
  const value = config?.[key];
  return typeof value === "string" ? value : "";
}

function emptyDraft(method: PaymentMethod): Draft {
  return {
    description: method.description ?? "",
    displayName: readConfigValue(method.config_json, "display_name"),
    mode: method.mode,
    publicKey: method.public_key ?? "",
    secretKey: "",
    webhookSecret: "",
    webhookEnabled: method.webhook_enabled,
    bankName: readConfigValue(method.config_json, "bank_name"),
    accountName: readConfigValue(method.config_json, "account_name"),
    accountNumber: readConfigValue(method.config_json, "account_number"),
    iban: readConfigValue(method.config_json, "iban"),
    swift: readConfigValue(method.config_json, "swift"),
    routingNumber: readConfigValue(method.config_json, "routing_number"),
    instructions: readConfigValue(method.config_json, "instructions"),
  };
}

export function PaymentMethodsManager() {
  const [paymentMethods, setPaymentMethods] = useState<PaymentMethod[]>([]);
  const [drafts, setDrafts] = useState<Record<number, Draft>>({});
  const [loading, setLoading] = useState(true);
  const [savingId, setSavingId] = useState<number | null>(null);
  const [togglingId, setTogglingId] = useState<number | null>(null);
  const [clearingId, setClearingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  async function loadPaymentMethods() {
    try {
      setLoading(true);
      setError(null);

      const data = await apiClient.listPaymentMethods();

      setPaymentMethods(Array.isArray(data) ? data : []);
      setDrafts(
        Object.fromEntries(
          data.map((method) => [method.id, emptyDraft(method)])
        )
      );
    } catch {
      setError("Unable to load payment methods.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadPaymentMethods();
  }, []);

  useEffect(() => {
    if (!success) return;

    const timer = window.setTimeout(() => {
      setSuccess(null);
    }, 3500);

    return () => window.clearTimeout(timer);
  }, [success]);

  function updateDraft(
    id: number,
    field: keyof Draft,
    value: string | boolean
  ) {
    setDrafts((current) => ({
      ...current,
      [id]: {
        ...current[id],
        [field]: value,
      },
    }));
  }

  async function toggleActive(method: PaymentMethod) {
    try {
      setTogglingId(method.id);
      setError(null);
      setSuccess(null);

      await apiClient.updatePaymentMethod(method.id, {
        is_active: !method.is_active,
      });

      setSuccess(`${method.name} status updated.`);
      await loadPaymentMethods();
    } catch {
      setError("Unable to update payment method status.");
    } finally {
      setTogglingId(null);
    }
  }

  async function saveMethod(
    event: FormEvent<HTMLFormElement>,
    method: PaymentMethod
  ) {
    event.preventDefault();

    const draft = drafts[method.id] ?? emptyDraft(method);
    const isGateway = gatewaySlugs.has(method.slug);

    const config_json =
      method.slug === "bank_transfer"
        ? {
            bank_name: draft.bankName || null,
            account_name: draft.accountName || null,
            account_number: draft.accountNumber || null,
            iban: draft.iban || null,
            swift: draft.swift || null,
            routing_number: draft.routingNumber || null,
            instructions: draft.instructions || null,
          }
        : draft.displayName
          ? { display_name: draft.displayName }
          : null;

    try {
      setSavingId(method.id);
      setError(null);
      setSuccess(null);

      await apiClient.updatePaymentMethod(method.id, {
        description: draft.description || null,
        config_json,
        ...(isGateway
          ? {
              mode: draft.mode,
              public_key: draft.publicKey || null,
              secret_key: draft.secretKey || null,
              webhook_secret: draft.webhookSecret || null,
              webhook_enabled: draft.webhookEnabled,
            }
          : {}),
      });

      setSuccess(`${method.name} settings saved.`);
      await loadPaymentMethods();
    } catch {
      setError("Unable to save payment method.");
    } finally {
      setSavingId(null);
    }
  }

  async function clearSecret(method: PaymentMethod, field: "secret" | "webhook") {
    try {
      setClearingId(`${method.id}-${field}`);
      setError(null);
      setSuccess(null);

      await apiClient.updatePaymentMethod(method.id, {
        [field === "secret" ? "clear_secret_key" : "clear_webhook_secret"]: true,
      });

      setSuccess(
        field === "secret" ? "Secret key cleared." : "Webhook secret cleared."
      );

      await loadPaymentMethods();
    } catch {
      setError("Unable to clear secret.");
    } finally {
      setClearingId(null);
    }
  }

  const selectClass =
    "w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-100";

  return (
    <section className="space-y-6">
      <div className="flex flex-col justify-between gap-4 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm sm:flex-row sm:items-center">
        <div>
          <p className="text-sm font-medium uppercase tracking-wide text-blue-600">
            Payment Methods
          </p>
          <h2 className="mt-2 text-2xl font-semibold tracking-tight text-slate-950">
            Gateway Settings
          </h2>
          <p className="mt-1 text-sm text-slate-500">
            Configure Stripe, PayPal, and manual bank transfer payment options.
          </p>
        </div>

        <Button variant="secondary" onClick={() => void loadPaymentMethods()}>
          Refresh
        </Button>
      </div>

      {success ? (
        <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-700">
          {success}
        </div>
      ) : null}

      {loading ? (
        <div className="rounded-2xl border border-slate-200 bg-white p-6 text-sm text-slate-500 shadow-sm">
          Loading payment methods...
        </div>
      ) : error ? (
        <div className="rounded-2xl border border-red-200 bg-red-50 p-6 text-sm text-red-700">
          {error}
        </div>
      ) : (
        <div className="grid gap-6 xl:grid-cols-3">
          {paymentMethods.map((method) => {
            const draft = drafts[method.id] ?? emptyDraft(method);
            const isGateway = gatewaySlugs.has(method.slug);

            const publicLabel =
              method.slug === "paypal" ? "Client ID" : "Publishable key";

            const secretLabel =
              method.slug === "paypal" ? "Client secret" : "Secret key";

            const webhookSecretLabel =
              method.slug === "paypal"
                ? "Webhook ID / secret"
                : "Webhook signing secret";

            return (
              <form
                key={method.id}
                className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm"
                onSubmit={(event) => void saveMethod(event, method)}
              >
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <h3 className="text-lg font-semibold text-slate-950">
                      {method.name}
                    </h3>
                    <p className="mt-1 text-sm text-slate-500">{method.slug}</p>
                  </div>

                  <button
                    type="button"
                    onClick={() => void toggleActive(method)}
                    disabled={togglingId === method.id}
                    className={[
                      "rounded-full px-3 py-1 text-xs font-semibold transition disabled:cursor-not-allowed disabled:opacity-50",
                      method.is_active
                        ? "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200"
                        : "bg-slate-100 text-slate-700 ring-1 ring-slate-200",
                    ].join(" ")}
                  >
                    {togglingId === method.id
                      ? "Updating..."
                      : method.is_active
                        ? "Active"
                        : "Inactive"}
                  </button>
                </div>

                <div className="mt-6 space-y-4">
                  <Input
                    label="Description"
                    value={draft.description}
                    onChange={(event) =>
                      updateDraft(method.id, "description", event.target.value)
                    }
                  />

                  <Input
                    label="Display name"
                    value={draft.displayName}
                    onChange={(event) =>
                      updateDraft(method.id, "displayName", event.target.value)
                    }
                  />

                  {isGateway ? (
                    <>
                      <label className="block space-y-2">
                        <span className="text-sm font-medium text-slate-700">
                          Mode
                        </span>
                        <select
                          value={draft.mode}
                          onChange={(event) =>
                            updateDraft(
                              method.id,
                              "mode",
                              event.target.value as "test" | "live"
                            )
                          }
                          className={selectClass}
                        >
                          <option value="test">Test</option>
                          <option value="live">Live</option>
                        </select>
                      </label>

                      <Input
                        label={publicLabel}
                        value={draft.publicKey}
                        onChange={(event) =>
                          updateDraft(method.id, "publicKey", event.target.value)
                        }
                      />

                      <div className="space-y-2">
                        <Input
                          label={secretLabel}
                          type="password"
                          value={draft.secretKey}
                          placeholder="Leave blank to keep existing secret"
                          onChange={(event) =>
                            updateDraft(method.id, "secretKey", event.target.value)
                          }
                        />

                        <div className="flex items-center justify-between gap-3">
                          {method.has_secret_key ? (
                            <span className="rounded-full bg-emerald-50 px-3 py-1 text-xs font-semibold text-emerald-700 ring-1 ring-emerald-200">
                              Secret saved
                            </span>
                          ) : (
                            <span className="text-xs text-slate-500">
                              No secret saved
                            </span>
                          )}

                          <button
                            type="button"
                            onClick={() => void clearSecret(method, "secret")}
                            disabled={clearingId === `${method.id}-secret`}
                            className="text-xs font-medium text-red-600 hover:text-red-700 disabled:opacity-50"
                          >
                            Clear secret
                          </button>
                        </div>
                      </div>

                      <Input
                        label="Webhook URL"
                        value={
                          method.webhook_url ?? `/api/v1/webhooks/${method.slug}`
                        }
                        readOnly
                      />

                      <label className="flex items-center justify-between gap-3 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
                        <span className="font-medium">Webhook enabled</span>
                        <input
                          type="checkbox"
                          checked={draft.webhookEnabled}
                          onChange={(event) =>
                            updateDraft(
                              method.id,
                              "webhookEnabled",
                              event.target.checked
                            )
                          }
                          className="h-4 w-4 accent-blue-600"
                        />
                      </label>

                      <div className="space-y-2">
                        <Input
                          label={webhookSecretLabel}
                          type="password"
                          value={draft.webhookSecret}
                          placeholder="Leave blank to keep existing secret"
                          onChange={(event) =>
                            updateDraft(
                              method.id,
                              "webhookSecret",
                              event.target.value
                            )
                          }
                        />

                        <div className="flex items-center justify-between gap-3">
                          {method.has_webhook_secret ? (
                            <span className="rounded-full bg-emerald-50 px-3 py-1 text-xs font-semibold text-emerald-700 ring-1 ring-emerald-200">
                              Webhook secret saved
                            </span>
                          ) : (
                            <span className="text-xs text-slate-500">
                              No webhook secret saved
                            </span>
                          )}

                          <button
                            type="button"
                            onClick={() => void clearSecret(method, "webhook")}
                            disabled={clearingId === `${method.id}-webhook`}
                            className="text-xs font-medium text-red-600 hover:text-red-700 disabled:opacity-50"
                          >
                            Clear webhook secret
                          </button>
                        </div>
                      </div>
                    </>
                  ) : null}

                  {method.slug === "bank_transfer" ? (
                    <>
                      <Input
                        label="Bank name"
                        value={draft.bankName}
                        onChange={(event) =>
                          updateDraft(method.id, "bankName", event.target.value)
                        }
                      />

                      <Input
                        label="Account name"
                        value={draft.accountName}
                        onChange={(event) =>
                          updateDraft(method.id, "accountName", event.target.value)
                        }
                      />

                      <Input
                        label="Account number"
                        value={draft.accountNumber}
                        onChange={(event) =>
                          updateDraft(
                            method.id,
                            "accountNumber",
                            event.target.value
                          )
                        }
                      />

                      <Input
                        label="IBAN"
                        value={draft.iban}
                        onChange={(event) =>
                          updateDraft(method.id, "iban", event.target.value)
                        }
                      />

                      <Input
                        label="SWIFT"
                        value={draft.swift}
                        onChange={(event) =>
                          updateDraft(method.id, "swift", event.target.value)
                        }
                      />

                      <Input
                        label="Routing number"
                        value={draft.routingNumber}
                        onChange={(event) =>
                          updateDraft(
                            method.id,
                            "routingNumber",
                            event.target.value
                          )
                        }
                      />

                      <Input
                        label="Instructions"
                        value={draft.instructions}
                        onChange={(event) =>
                          updateDraft(method.id, "instructions", event.target.value)
                        }
                      />
                    </>
                  ) : null}
                </div>

                <Button
                  type="submit"
                  className="mt-6"
                  fullWidth
                  disabled={savingId === method.id}
                >
                  {savingId === method.id ? "Saving..." : "Save settings"}
                </Button>
              </form>
            );
          })}
        </div>
      )}
    </section>
  );
}