"use client";

import { ReactNode } from "react";

import { ToastProvider } from "@/components/ui/toast-provider";

export function AppProviders({ children }: { children: ReactNode }) {
  return <ToastProvider>{children}</ToastProvider>;
}
