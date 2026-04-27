import { FormEventHandler, ReactNode } from "react";

type AuthFormProps = {
  children: ReactNode;
  submitLabel: string;
  helperText: string;
  onSubmit?: FormEventHandler<HTMLFormElement>;
  submitting?: boolean;
};

export function AuthForm({
  children,
  submitLabel,
  helperText,
  onSubmit,
  submitting = false,
}: AuthFormProps) {
  return (
    <form className="space-y-6" onSubmit={onSubmit}>
      <div className="space-y-4">{children}</div>

      <button
        type="submit"
        disabled={submitting}
        className="relative h-14 w-full overflow-hidden rounded-2xl bg-[linear-gradient(110deg,#60a5fa,#a855f7,#22d3ee)] px-5 text-sm font-bold text-white shadow-xl shadow-cyan-500/20 transition hover:scale-[1.01] disabled:cursor-not-allowed disabled:opacity-60"
      >
        {submitting ? "Processing..." : submitLabel}
      </button>

      <p className="text-center text-xs font-medium leading-6 text-slate-400">
        {helperText}
      </p>
    </form>
  );
}