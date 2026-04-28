"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Finding, Scan, Target } from "@/lib/types";
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

function normalizeConfidence(finding: Finding) {
  return String(finding.confidence_level || finding.confidence || "info").toLowerCase();
}

function isInformationalObservation(finding: Finding) {
  const confidence = normalizeConfidence(finding);
  return confidence === "low" || confidence === "info" || confidence === "informational";
}

function StatCard({
  label,
  value,
  color = "text-slate-900"
}: {
  label: string;
  value: number | string;
  color?: string;
}) {
  return (
    <div className="rounded-xl border bg-white p-5 shadow-sm">
      <p className="text-xs text-slate-500">{label}</p>
      <p className={`mt-2 text-xl font-semibold ${color}`}>{value}</p>
    </div>
  );
}

function BreakdownCard({
  title,
  items
}: {
  title: string;
  items: { label: string; value: number; color: string }[];
}) {
  const total = items.reduce((sum, item) => sum + item.value, 0);

  if (total === 0) {
    return (
      <div className="rounded-2xl border bg-white p-5 shadow-sm">
        <h3 className="font-semibold text-slate-900">{title}</h3>
        <p className="mt-4 text-sm text-slate-400">No data available yet.</p>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border bg-white p-5 shadow-sm">
      <h3 className="font-semibold text-slate-900">{title}</h3>
      <div className="mt-4 space-y-3">
        {items.map((item) => {
          const percent = total > 0 ? Math.round((item.value / total) * 100) : 0;

          return (
            <div key={item.label}>
              <div className="mb-1 flex items-center justify-between text-xs">
                <span className="font-medium text-slate-600">{item.label}</span>
                <span className="text-slate-400">{item.value}</span>
              </div>
              <div className="h-2 rounded-full bg-slate-100">
                <div
                  className={`h-2 rounded-full ${item.color}`}
                  style={{ width: `${percent}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function DashboardOverview({
  scans: initialScans,
  targets: initialTargets
}: DashboardOverviewProps) {
  const [scans, setScans] = useState<Scan[]>(initialScans || []);
  const [targets, setTargets] = useState<Target[]>(initialTargets || []);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(!initialScans || !initialTargets);

  useEffect(() => {
    if (!initialScans || !initialTargets) {
      const loadData = async () => {
        try {
          const [s, t] = await Promise.all([
            apiClient.listScans(),
            apiClient.listTargets()
          ]);
          const recentScans = Array.isArray(s) ? s.slice(0, 10) : [];
          const findingResults = await Promise.allSettled(
            recentScans.map((scan) => apiClient.getScanFindings(scan.id))
          );
          const loadedFindings = findingResults.flatMap((result) =>
            result.status === "fulfilled" && Array.isArray(result.value)
              ? result.value
              : []
          );

          setScans(s);
          setTargets(t);
          setFindings(loadedFindings);
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

  const riskScores = scans
    .map((scan) => scan.risk_score)
    .filter((score): score is number => typeof score === "number");
  const riskScore = riskScores.length ? Math.max(...riskScores) : "—";
  const mainSecurityFindings = findings.filter(
    (finding) => !isInformationalObservation(finding)
  ).length;
  const informationalObservations = findings.filter(isInformationalObservation).length;
  const confirmedFindings = findings.filter(
    (finding) => normalizeConfidence(finding) === "confirmed" || finding.is_confirmed
  ).length;
  const highConfidenceFindings = findings.filter(
    (finding) => normalizeConfidence(finding) === "high"
  ).length;

  const severityCounts = findings.reduce(
    (acc, finding) => {
      const severity = String(finding.severity || "info").toLowerCase();
      if (severity === "critical") acc.critical += 1;
      else if (severity === "high") acc.high += 1;
      else if (severity === "medium") acc.medium += 1;
      else if (severity === "low") acc.low += 1;
      else acc.info += 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  const confidenceCounts = findings.reduce(
    (acc, finding) => {
      const confidence = normalizeConfidence(finding);
      if (confidence === "confirmed") acc.confirmed += 1;
      else if (confidence === "high") acc.high += 1;
      else if (confidence === "medium") acc.medium += 1;
      else if (confidence === "low") acc.low += 1;
      else acc.info += 1;
      return acc;
    },
    { confirmed: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  const retestCounts = scans.reduce(
    (acc, scan) => {
      const summary = scan.comparison_summary;
      if (!summary || typeof summary !== "object") return acc;
      acc.fixed += Number(summary.fixed || 0);
      acc.stillVulnerable += Number(summary.still_vulnerable || 0);
      acc.new += Number(summary.new || 0);
      acc.notRetested += Number(summary.not_retested || 0);
      return acc;
    },
    { fixed: 0, stillVulnerable: 0, new: 0, notRetested: 0 }
  );

  return (
    <div className="space-y-8">

      {/* HEADER */}


 <div className="grid gap-6 lg:grid-cols-3">

  {/* LEFT: Stats */}
  <div className="lg:col-span-2 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
    <StatCard label="Risk Score" value={riskScore} color="text-red-600" />
    <StatCard label="Total Findings" value={totalFindings} />
    <StatCard label="Main Security Findings" value={mainSecurityFindings || "—"} color="text-red-600" />
    <StatCard label="Informational Observations" value={informationalObservations || "—"} color="text-blue-600" />
    <StatCard label="Confirmed Findings" value={confirmedFindings || "—"} color="text-emerald-600" />
    <StatCard label="High Confidence Findings" value={highConfidenceFindings || "—"} color="text-orange-600" />
  </div>

  {/* RIGHT: Usage */}
  <div>
    <UsageCard />
  </div>

</div>
      <div className="grid gap-6 lg:grid-cols-3">
        <BreakdownCard
          title="Severity Distribution"
          items={[
            { label: "Critical", value: severityCounts.critical, color: "bg-red-600" },
            { label: "High", value: severityCounts.high, color: "bg-orange-500" },
            { label: "Medium", value: severityCounts.medium, color: "bg-amber-500" },
            { label: "Low", value: severityCounts.low, color: "bg-blue-500" },
            { label: "Info", value: severityCounts.info, color: "bg-slate-400" }
          ]}
        />
        <BreakdownCard
          title="Confidence Distribution"
          items={[
            { label: "Confirmed", value: confidenceCounts.confirmed, color: "bg-emerald-600" },
            { label: "High", value: confidenceCounts.high, color: "bg-red-500" },
            { label: "Medium", value: confidenceCounts.medium, color: "bg-amber-500" },
            { label: "Low", value: confidenceCounts.low, color: "bg-blue-500" },
            { label: "Info", value: confidenceCounts.info, color: "bg-slate-400" }
          ]}
        />
        <BreakdownCard
          title="Retest Outcomes"
          items={[
            { label: "Fixed", value: retestCounts.fixed, color: "bg-emerald-600" },
            { label: "Still Vulnerable", value: retestCounts.stillVulnerable, color: "bg-red-500" },
            { label: "New", value: retestCounts.new, color: "bg-blue-500" },
            { label: "Not Retested", value: retestCounts.notRetested, color: "bg-slate-400" }
          ]}
        />
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
