"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ReactNode, useEffect, useState } from "react";

import { getSessionUser, SessionUser } from "@/lib/session";

export type Role = "super_admin" | "admin" | "team_member";

type NavItem = {
  label: string;
  href: string;
};

const superAdminNav: NavItem[] = [
  { label: "Dashboard", href: "/dashboard" },
  { label: "Organizations", href: "/dashboard/organizations" },
  { label: "Users", href: "/dashboard/users" },
  { label: "Packages", href: "/dashboard/packages" },
  { label: "Payment Methods", href: "/dashboard/payment-methods" },
  { label: "Admin Billing", href: "/dashboard/admin-billing" },
  { label: "Targets", href: "/dashboard/targets" },
  { label: "Scans", href: "/dashboard/scans" },
  { label: "Profile", href: "/dashboard/profile" },
];

const adminNav: NavItem[] = [
  { label: "Dashboard", href: "/dashboard" },
  { label: "Targets", href: "/dashboard/targets" },
  { label: "Scans", href: "/dashboard/scans" },
  { label: "Users", href: "/dashboard/users" },
  { label: "Invoices", href: "/dashboard/invoices" },
  { label: "Profile", href: "/dashboard/profile" },
];

const teamMemberNav: NavItem[] = [
  { label: "Dashboard", href: "/dashboard" },
  { label: "Scans", href: "/dashboard/scans" },
  { label: "Profile", href: "/dashboard/profile" },
];

function getNavItems(role: Role): NavItem[] {
  if (role === "super_admin") return superAdminNav;
  if (role === "team_member") return teamMemberNav;
  return adminNav;
}

function formatRole(role: Role) {
  if (role === "super_admin") return "Super Admin";
  if (role === "team_member") return "Team Member";
  return "Admin";
}

function formatTitle(pathname: string) {
  if (pathname === "/dashboard") return "Dashboard";

  const lastSegment = pathname.split("/").filter(Boolean).pop();

  if (!lastSegment) return "Dashboard";

  return lastSegment
    .replace(/-/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export function DashboardShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const [user, setUser] = useState<SessionUser | null>(null);

  useEffect(() => {
    setUser(getSessionUser());
  }, []);

  const role = ((user?.role as Role) || "admin") as Role;
  const navItems = getNavItems(role);

  function handleSignOut() {
    localStorage.removeItem("session_user");
    localStorage.removeItem("user");
    localStorage.removeItem("auth_user");

    document.cookie = "session=; Max-Age=0; path=/";
    document.cookie = "session_id=; Max-Age=0; path=/";
    document.cookie = "access_token=; Max-Age=0; path=/";

    window.location.href = "/login";
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-950">
      <div className="flex min-h-screen">
        <aside className="hidden w-64 flex-col border-r border-slate-200 bg-white lg:flex">
          <div className="border-b border-slate-100 px-6 py-6">
            <Link href="/dashboard" className="block">
              <div className="text-lg font-semibold tracking-tight text-slate-950">
                WebScanner
              </div>
              <div className="mt-1 text-xs font-medium text-slate-500">
                Vulnerability Scanner
              </div>
            </Link>
          </div>

          <nav className="flex-1 space-y-1 px-4 py-5">
            {navItems.map((item) => {
              const isActive =
                pathname === item.href ||
                (item.href !== "/dashboard" && pathname.startsWith(item.href));

              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={[
                    "block rounded-xl px-3 py-2 text-sm font-medium transition-colors",
                    isActive
                      ? "bg-blue-50 text-blue-700"
                      : "text-slate-600 hover:bg-slate-50 hover:text-slate-950",
                  ].join(" ")}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>

          <div className="border-t border-slate-100 px-6 py-4">
            <div className="text-sm font-semibold text-slate-900">
              {user?.name || user?.email || "User"}
            </div>
            <div className="mt-1 text-xs text-slate-500">{formatRole(role)}</div>
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-slate-200 bg-white/90 px-6 backdrop-blur">
            <div>
              <h1 className="text-lg font-semibold tracking-tight text-slate-950">
                {formatTitle(pathname)}
              </h1>
              <p className="text-xs text-slate-500">
                Manage your scans, targets, reports, and workspace.
              </p>
            </div>

            <button
              type="button"
              onClick={handleSignOut}
              className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 hover:text-slate-950"
            >
              Sign out
            </button>
          </header>

          <main className="flex-1 p-6">{children}</main>
        </div>
      </div>
    </div>
  );
}