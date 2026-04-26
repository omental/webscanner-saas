"use client";

import { useEffect, useState } from "react";

import { getSessionUser, SessionUser } from "@/lib/session";
import { DashboardOverview } from "@/components/dashboard/dashboard-overview";
import { SuperAdminOverview } from "@/components/dashboard/super-admin-overview";

export function DashboardRoleSwitcher() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    setUser(getSessionUser());
    setReady(true);
  }, []);

  if (!ready) {
    return (
      <div className="rounded-2xl border border-slate-200 bg-white p-6 text-sm text-slate-500 shadow-sm">
        Loading dashboard...
      </div>
    );
  }

  if (user?.role === "super_admin") {
    return <SuperAdminOverview />;
  }

  return <DashboardOverview />;
}