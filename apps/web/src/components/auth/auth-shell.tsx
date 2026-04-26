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
  footer
}: AuthShellProps) {
  return (
    <main className="min-h-screen bg-slate-50 px-6 py-16 text-slate-900 selection:bg-indigo-100 selection:text-indigo-600">
      <div className="mx-auto flex min-h-[80vh] max-w-6xl items-center justify-center">
        <div className="grid w-full gap-0 overflow-hidden rounded-[2.5rem] border border-slate-200 bg-white shadow-2xl lg:grid-cols-[1.1fr_0.9fr]">
          <section className="flex flex-col justify-between bg-slate-50 p-10 lg:p-16">
            <div>
              <Link
                href="/"
                className="flex items-center gap-2 text-sm font-bold uppercase tracking-[0.2em] text-indigo-600"
              >
                <div className="h-6 w-6 rounded bg-indigo-600" />
                Web Scanner
              </Link>
              <p className="mt-12 text-xs font-bold uppercase tracking-[0.3em] text-slate-400">
                {eyebrow}
              </p>
              <h1 className="mt-6 text-4xl font-black tracking-tight text-slate-900 lg:text-5xl">
                {title}
              </h1>
              <p className="mt-6 max-w-md text-lg leading-8 text-slate-600">
                {description}
              </p>
            </div>

            <div className="mt-12 rounded-2xl border border-indigo-100 bg-white p-6 shadow-sm">
              <div className="flex items-center gap-3">
                <div className="h-2 w-2 rounded-full bg-indigo-600 animate-pulse" />
                <p className="text-sm font-bold text-slate-900">
                  Ready for enterprise audits
                </p>
              </div>
              <p className="mt-2 text-sm leading-6 text-slate-500">
                Our scanner is built to meet the security requirements of modern SaaS teams.
              </p>
            </div>
          </section>

          <section className="flex flex-col justify-center p-10 lg:p-16">
            <div className="mx-auto w-full max-w-sm">
              {children}
              <div className="mt-10 border-t border-slate-100 pt-8 text-center text-sm font-medium text-slate-500">
                {footer}
              </div>
            </div>
          </section>
        </div>
      </div>
    </main>
  );
}
