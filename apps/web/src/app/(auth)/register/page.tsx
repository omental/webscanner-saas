"use client";

import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";

import { AuthForm } from "@/components/auth/auth-form";
import { AuthShell } from "@/components/auth/auth-shell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { apiClient, buildApiUrl } from "@/lib/api-client";
import { Package, TrialRegistrationResponse } from "@/lib/types";

export default function RegisterPage() {
  const [packages, setPackages] = useState<Package[]>([]);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [selectedPackageId, setSelectedPackageId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<TrialRegistrationResponse | null>(null);

  useEffect(() => {
    async function loadPackages() {
      try {
        const data = await apiClient.listPackages();
        setPackages(data);
        if (data[0]) {
          setSelectedPackageId(String(data[0].id));
        }
      } catch {
        setError("Unable to load packages.");
      }
    }

    void loadPackages();
  }, []);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    try {
      setSubmitting(true);
      setError(null);
      const response = await apiClient.registerTrial({
        name,
        email,
        password,
        organization_name: organizationName,
        selected_package_id: Number(selectedPackageId)
      });
      setSuccess(response);
      window.open(buildApiUrl(response.invoice_pdf_url), "_blank");
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
        title="Your 14-day free trial has started."
        description="No credit card required. Your first invoice has been generated for after your trial."
        footer={
          <p>
            Ready to scan?{" "}
            <Link href="/login" className="text-cyan-300 hover:text-cyan-200">
              Sign in
            </Link>
          </p>
        }
      >
        <div className="space-y-5">
          <div className="rounded-2xl border border-emerald-400/20 bg-emerald-400/10 p-4 text-sm text-emerald-100">
            {success.message}
          </div>
          <Button
            fullWidth
            onClick={() => window.open(buildApiUrl(success.invoice_pdf_url), "_blank")}
          >
            Download Invoice
          </Button>
        </div>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      eyebrow="Start your 14-day free trial"
      title="Create your account"
      description="No credit card required. Includes 1 trial scan so your team can evaluate the scanner before billing begins."
      footer={
        <p>
          Already have an account?{" "}
          <Link href="/login" className="text-cyan-300 hover:text-cyan-200">
            Sign in
          </Link>
        </p>
      }
    >
      <AuthForm
        submitLabel="Start free trial"
        helperText="No credit card required. Includes 1 trial scan."
        onSubmit={handleSubmit}
        submitting={submitting}
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
        >
          {packages.map((plan) => (
            <option key={plan.id} value={plan.id}>
              {plan.name} · {plan.scan_limit_per_week} scans/week · $
              {plan.price_monthly}/mo
            </option>
          ))}
        </Select>
        {error ? <p className="text-sm text-rose-300">{error}</p> : null}
      </AuthForm>
    </AuthShell>
  );
}
