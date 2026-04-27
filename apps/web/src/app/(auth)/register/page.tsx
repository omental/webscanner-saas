"use client";

import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";

import { AuthForm } from "@/components/auth/auth-form";
import { AuthShell } from "@/components/auth/auth-shell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { apiClient } from "@/lib/api-client";
import { Package, TrialRegistrationResponse } from "@/lib/types";

export default function RegisterPage() {
  const [packages, setPackages] = useState<Package[]>([]);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [selectedPackageId, setSelectedPackageId] = useState("");

  const [submitting, setSubmitting] = useState(false);
  const [packagesLoading, setPackagesLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<TrialRegistrationResponse | null>(null);

  useEffect(() => {
    async function loadPackages() {
      try {
        setPackagesLoading(true);
        setError(null);

        const data = await apiClient.listPackages();
        const activePackages = Array.isArray(data)
          ? data.filter((item) => item.status === "active")
          : [];

        setPackages(activePackages);

        if (activePackages[0]) {
          setSelectedPackageId(String(activePackages[0].id));
        }
      } catch {
        setError("Unable to load packages.");
      } finally {
        setPackagesLoading(false);
      }
    }

    void loadPackages();
  }, []);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!selectedPackageId) {
      setError("Please select a package.");
      return;
    }

    try {
      setSubmitting(true);
      setError(null);

      const response = await apiClient.registerTrial({
        name,
        email,
        password,
        organization_name: organizationName,
        selected_package_id: Number(selectedPackageId),
      });

      setSuccess(response);
    } catch (registrationError) {
      setError(
        registrationError instanceof Error
          ? registrationError.message
          : "Unable to start trial."
      );
    } finally {
      setSubmitting(false);
    }
  }

  if (success) {
    return (
      <AuthShell
        eyebrow="Trial Started"
        title="Your 14-day trial is ready."
        description="Your workspace has been created. Sign in to add targets, run your first scan, and download invoices from your dashboard."
        footer={
          <p>
            Ready to scan?{" "}
            <Link href="/login" className="font-semibold text-cyan-200 hover:text-white">
              Sign in
            </Link>
          </p>
        }
      >
        <div className="space-y-5">
          <div className="rounded-2xl border border-emerald-400/20 bg-emerald-400/10 p-4 text-sm leading-7 text-emerald-100">
            {success.message}
          </div>

          <div className="rounded-2xl border border-white/10 bg-white/[0.05] p-4 text-sm leading-7 text-slate-300">
            Your invoice has been generated. Please sign in first, then download
            it from the Invoices page.
          </div>

          <Button fullWidth onClick={() => (window.location.href = "/login")}>
            Go to login
          </Button>
        </div>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      eyebrow="Start Free Trial"
      title="Create your scanner workspace."
      description="No credit card required. Start a 14-day trial, choose a package, and run your first scan from the dashboard."
      footer={
        <p>
          Already have an account?{" "}
          <Link href="/login" className="font-semibold text-cyan-200 hover:text-white">
            Sign in
          </Link>
        </p>
      }
    >
      <AuthForm
        submitLabel={packagesLoading ? "Loading packages..." : "Start free trial"}
        helperText="No credit card required. Includes 1 trial scan."
        onSubmit={handleSubmit}
        submitting={submitting || packagesLoading}
      >
        <Input
          label="Full name"
          placeholder="Muba Tasnim"
          value={name}
          onChange={(event) => setName(event.target.value)}
          required
        />

        <Input
          label="Work email"
          type="email"
          placeholder="team@webscanner.dev"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          required
        />

        <Input
          label="Password"
          type="password"
          placeholder="Create a strong password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          required
        />

        <Input
          label="Organization"
          placeholder="Acme Security"
          value={organizationName}
          onChange={(event) => setOrganizationName(event.target.value)}
          required
        />

        <Select
          label="Package"
          value={selectedPackageId}
          onChange={(event) => setSelectedPackageId(event.target.value)}
          required
          disabled={packagesLoading || packages.length === 0}
        >
          {packages.length === 0 ? (
            <option value="">No active packages available</option>
          ) : null}

          {packages.map((plan) => (
            <option key={plan.id} value={plan.id}>
              {plan.name} · {plan.scan_limit_per_week} scans/week · $
              {plan.price_monthly}/mo
            </option>
          ))}
        </Select>

        {error ? (
          <div className="rounded-2xl border border-rose-400/20 bg-rose-400/10 px-4 py-3 text-sm text-rose-100">
            {error}
          </div>
        ) : null}
      </AuthForm>
    </AuthShell>
  );
}