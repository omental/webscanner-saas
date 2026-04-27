"use client";

import Link from "next/link";
import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";

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
        logged_in: true,
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
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#080d18] px-4 py-10 text-white">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_20%,rgba(96,165,250,0.22),transparent_32%),radial-gradient(circle_at_80%_30%,rgba(168,85,247,0.22),transparent_34%),radial-gradient(circle_at_50%_90%,rgba(34,211,238,0.16),transparent_36%)]" />

      <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.035)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.035)_1px,transparent_1px)] bg-[size:72px_72px] [mask-image:radial-gradient(circle_at_center,black,transparent_75%)]" />

      <motion.section
        initial={{ opacity: 0, y: 36, scale: 0.96 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.75, ease: [0.16, 1, 0.3, 1] }}
        className="relative grid w-full max-w-6xl overflow-hidden rounded-[2rem] border border-white/10 bg-white/[0.06] shadow-2xl shadow-black/40 backdrop-blur-2xl lg:grid-cols-[1.05fr_0.95fr]"
      >
        <div className="relative overflow-hidden p-8 sm:p-12 lg:p-16">
          <div className="absolute -left-24 -top-24 h-72 w-72 rounded-full bg-cyan-400/20 blur-3xl" />

          <div className="relative">
            <Link href="/" className="inline-flex items-center gap-3">
              <span className="flex h-10 w-10 items-center justify-center rounded-2xl bg-white text-sm font-black text-[#080d18]">
                W
              </span>
              <span className="text-sm font-bold uppercase tracking-[0.28em] text-cyan-100">
                Web Scanner
              </span>
            </Link>

            <p className="mt-16 text-sm font-semibold uppercase tracking-[0.35em] text-cyan-200">
              Access Portal
            </p>

            <h1 className="mt-5 max-w-xl text-5xl font-semibold leading-[0.98] tracking-[-0.06em] text-white sm:text-6xl">
              Sign in to your security workspace.
            </h1>

            <p className="mt-6 max-w-xl text-base leading-8 text-slate-300">
              Continue into your dashboard to manage scans, targets, reports,
              usage limits, billing, and team access.
            </p>

            <div className="mt-12 rounded-[1.5rem] border border-white/10 bg-white/[0.06] p-5 backdrop-blur-xl">
              <div className="flex items-start gap-4">
                <span className="mt-1 h-2.5 w-2.5 rounded-full bg-emerald-400 shadow-[0_0_20px_rgba(52,211,153,0.8)]" />
                <div>
                  <p className="font-semibold text-white">
                    Ready for enterprise audits
                  </p>
                  <p className="mt-2 text-sm leading-7 text-slate-300">
                    Built for SaaS teams that need clean scan operations,
                    reports, tenant control, and billing records.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="relative border-t border-white/10 bg-white/[0.04] p-8 sm:p-12 lg:border-l lg:border-t-0 lg:p-16">
          <form onSubmit={handleSubmit} className="relative mx-auto max-w-md">
            <div className="mb-8">
              <h2 className="text-2xl font-semibold tracking-[-0.03em] text-white">
                Welcome back
              </h2>
              <p className="mt-2 text-sm text-slate-400">
                Use an active dashboard account.
              </p>
            </div>

            <label className="block space-y-2">
              <span className="text-sm font-medium text-slate-200">
                Work email
              </span>
              <input
                type="email"
                placeholder="founder@webscanner.dev"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                required
                className="w-full rounded-2xl border border-white/10 bg-white/10 px-4 py-3.5 text-sm text-white outline-none transition placeholder:text-slate-500 focus:border-cyan-300/60 focus:ring-4 focus:ring-cyan-300/10"
              />
            </label>

            <label className="mt-5 block space-y-2">
              <span className="text-sm font-medium text-slate-200">
                Password
              </span>
              <input
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
                className="w-full rounded-2xl border border-white/10 bg-white/10 px-4 py-3.5 text-sm text-white outline-none transition placeholder:text-slate-500 focus:border-cyan-300/60 focus:ring-4 focus:ring-cyan-300/10"
              />
            </label>

            {error ? (
              <div className="mt-5 rounded-2xl border border-rose-400/20 bg-rose-400/10 px-4 py-3 text-sm text-rose-100">
                {error}
              </div>
            ) : null}

            <motion.button
              whileHover={{ scale: 1.015 }}
              whileTap={{ scale: 0.98 }}
              type="submit"
              disabled={submitting}
              className="mt-7 w-full rounded-2xl bg-[linear-gradient(110deg,#60a5fa,#a855f7,#22d3ee)] px-5 py-4 text-sm font-bold text-white shadow-xl shadow-cyan-500/20 transition disabled:cursor-not-allowed disabled:opacity-60"
            >
              {submitting ? "Signing in..." : "Continue"}
            </motion.button>

            <div className="mt-8 border-t border-white/10 pt-6 text-center text-sm text-slate-400">
              Need an account?{" "}
              <Link href="/register" className="font-semibold text-cyan-200 hover:text-white">
                Create one
              </Link>
            </div>
          </form>
        </div>
      </motion.section>
    </main>
  );
}