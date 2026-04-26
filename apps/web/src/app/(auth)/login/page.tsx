"use client";

import Link from "next/link";
import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";

import { AuthForm } from "@/components/auth/auth-form";
import { AuthShell } from "@/components/auth/auth-shell";
import { Input } from "@/components/ui/input";
import { apiClient } from "@/lib/api-client";
import { setSessionUser } from "@/lib/session";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    console.log("LOGIN SUBMIT FIRED");

    try {
      setSubmitting(true);
      setError(null);
      const user = await apiClient.login({ email, password });
      setSessionUser({
        user_id: user.id,
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        organization_id: user.organization_id ?? null,
        status: user.status,
        logged_in: true
      });
      router.replace("/dashboard");
    } catch (loginError) {
      setError(
        loginError instanceof Error ? loginError.message : "Unable to sign in."
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthShell
      eyebrow="Access Portal"
      title="Sign in to your workspace"
      description="Sign in with an active dashboard account. The MVP session stays in this browser and carries your role for dashboard permissions."
      footer={
        <p>
          Need an account?{" "}
          <Link href="/register" className="text-cyan-300 hover:text-cyan-200">
            Create one
          </Link>
        </p>
      }
    >
      <AuthForm
        submitLabel="Continue"
        helperText="Use an active dashboard user account."
        onSubmit={handleSubmit}
        submitting={submitting}
      >
        <Input
          label="Work email"
          type="email"
          placeholder="founder@webscanner.dev"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          required
        />
        <Input
          label="Password"
          type="password"
          placeholder="••••••••"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          required
        />
        {error ? <p className="text-sm text-rose-300">{error}</p> : null}
      </AuthForm>
    </AuthShell>
  );
}
