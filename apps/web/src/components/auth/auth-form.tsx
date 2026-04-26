import { FormEventHandler, ReactNode } from "react";

import { Button } from "@/components/ui/button";

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
  submitting = false
}: AuthFormProps) {
  return (
    <form className="space-y-6" onSubmit={onSubmit}>
      <div className="space-y-4">
        {children}
      </div>
      <Button fullWidth type="submit" disabled={submitting} className="h-12 text-base">
        {submitting ? "Processing..." : submitLabel}
      </Button>
      <p className="text-center text-xs font-medium leading-6 text-slate-400">{helperText}</p>
    </form>
  );
}
