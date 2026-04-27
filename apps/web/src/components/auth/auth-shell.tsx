import Link from "next/link";
import { ReactNode } from "react";

type AuthShellProps = {
  children: ReactNode;
  eyebrow: string;
  title: string;
  description: string;
  footer: ReactNode;
};

export function AuthShell({
  children,
  eyebrow,
  title,
  description,
  footer,
}: AuthShellProps) {
  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#080d18] px-4 py-10 text-white selection:bg-cyan-300 selection:text-[#080d18]">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_20%,rgba(96,165,250,0.22),transparent_32%),radial-gradient(circle_at_80%_30%,rgba(168,85,247,0.22),transparent_34%),radial-gradient(circle_at_50%_90%,rgba(34,211,238,0.16),transparent_36%)]" />

      <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.035)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.035)_1px,transparent_1px)] bg-[size:72px_72px] [mask-image:radial-gradient(circle_at_center,black,transparent_75%)]" />

      <section className="relative grid w-full max-w-6xl overflow-hidden rounded-[2rem] border border-white/10 bg-white/[0.06] shadow-2xl shadow-black/40 backdrop-blur-2xl lg:grid-cols-[1.05fr_0.95fr]">
        <div className="relative overflow-hidden p-8 sm:p-12 lg:p-16">
          <div className="absolute -left-24 -top-24 h-72 w-72 rounded-full bg-cyan-400/20 blur-3xl" />
          <div className="absolute -bottom-24 right-10 h-72 w-72 rounded-full bg-purple-500/20 blur-3xl" />

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
              {eyebrow}
            </p>

            <h1 className="mt-5 max-w-xl text-5xl font-semibold leading-[0.98] tracking-[-0.06em] text-white sm:text-6xl">
              {title}
            </h1>

            <p className="mt-6 max-w-xl text-base leading-8 text-slate-300">
              {description}
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
          <div className="mx-auto flex min-h-full w-full max-w-md flex-col justify-center">
            {children}

            <div className="mt-8 border-t border-white/10 pt-6 text-center text-sm text-slate-400">
              {footer}
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}