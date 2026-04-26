"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Scan, Target } from "@/lib/types";
import { ScanStatusBadge } from "./scan-status-badge";
import { apiClient } from "@/lib/api-client";
import { UsageCard } from "@/components/dashboard/usage-card";
type DashboardOverviewProps = {
  scans?: Scan[];
  targets?: Target[];
};

function formatDate(value: string) {
  return new Date(value).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric"
  });
}

function targetLabel(targets: Target[], targetId: number) {
  const target = targets.find((t) => t.id === targetId);
  return target?.normalized_domain ?? `Target #${targetId}`;
}

export function DashboardOverview({
  scans: initialScans,
  targets: initialTargets
}: DashboardOverviewProps) {
  const [scans, setScans] = useState<Scan[]>(initialScans || []);
  const [targets, setTargets] = useState<Target[]>(initialTargets || []);
  const [loading, setLoading] = useState(!initialScans || !initialTargets);

  useEffect(() => {
    if (!initialScans || !initialTargets) {
      const loadData = async () => {
        try {
          const [s, t] = await Promise.all([
            apiClient.listScans(),
            apiClient.listTargets()
          ]);
          setScans(s);
          setTargets(t);
        } catch (err) {
          console.error("Failed to load dashboard data:", err);
        } finally {
          setLoading(false);
        }
      };
      void loadData();
    }
  }, [initialScans, initialTargets]);

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center text-slate-400">
        Loading dashboard...
      </div>
    );
  }

  /* ---------------- SMART STATS ---------------- */

  const completed = scans.filter((s) => s.status === "completed").length;
  const running = scans.filter((s) => s.status === "running").length;
  const failed = scans.filter((s) => s.status === "failed").length;

  const totalFindings = scans.reduce(
    (acc, s) => acc + (s.total_findings || 0),
    0
  );

  const stats = [
    { label: "Total Scans", value: scans.length },
    { label: "Targets", value: targets.length },
    { label: "Findings", value: totalFindings },
    { label: "Running", value: running },
    { label: "Completed", value: completed },
    { label: "Failed", value: failed }
  ];

  return (
    <div className="space-y-8">

      {/* HEADER */}


 <div className="grid gap-6 lg:grid-cols-3">

  {/* LEFT: Stats */}
  <div className="lg:col-span-2 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
    {stats.map((stat) => (
      <div
        key={stat.label}
        className="rounded-xl border bg-white p-5 shadow-sm"
      >
        <p className="text-xs text-slate-500">{stat.label}</p>
        <p className="mt-2 text-xl font-semibold text-slate-900">
          {stat.value}
        </p>
      </div>
    ))}
  </div>

  {/* RIGHT: Usage */}
  <div>
    <UsageCard />
  </div>

</div>
      {/* RECENT SCANS */}
      <div className="rounded-2xl border bg-white shadow-sm">

        <div className="flex justify-between p-6 border-b">
          <h3 className="font-semibold text-slate-900">Recent Scans</h3>
          <Link href="/dashboard/scans" className="text-blue-600 text-sm">
            View all
          </Link>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-slate-500">
              <tr>
                <th className="px-6 py-3 text-left">Target</th>
                <th className="px-6 py-3 text-left">Status</th>
                <th className="px-6 py-3 text-left">Date</th>
                <th className="px-6 py-3 text-right">Action</th>
              </tr>
            </thead>

            <tbody className="divide-y">
              {scans.slice(0, 5).map((scan) => (
                <tr key={scan.id}>
                  <td className="px-6 py-4 font-medium">
                    {targetLabel(targets, scan.target_id)}
                  </td>

                  <td className="px-6 py-4">
                    <ScanStatusBadge status={scan.status} />
                  </td>

                  <td className="px-6 py-4">
                    {formatDate(scan.created_at)}
                  </td>

                  <td className="px-6 py-4 text-right">
                    <Link
                      href={`/dashboard/scans/${scan.id}`}
                      className="text-blue-600"
                    >
                      View
                    </Link>
                  </td>
                </tr>
              ))}

              {scans.length === 0 && (
                <tr>
                  <td colSpan={4} className="text-center py-10 text-slate-400">
                    No scans yet. Create a target and start scanning.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}