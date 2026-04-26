"use client";

import { useEffect, useMemo, useState } from "react";
import dynamic from "next/dynamic";

import { apiClient } from "@/lib/api-client";
import { Usage, Invoice, Scan } from "@/lib/types";

const Chart = dynamic(() => import("react-apexcharts"), { ssr: false });

export function SuperAdminOverview() {
  const [counts, setCounts] = useState({
    organizations: 0,
    users: 0,
    packages: 0,
    scans: 0,
  });

  const [usage, setUsage] = useState<Usage[]>([]);
  const [invoices, setInvoices] = useState<Invoice[]>([]);
  const [scansData, setScansData] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadCounts() {
      try {
        setLoading(true);

        const [
          organizations,
          users,
          packages,
          scans,
          usageRows,
          invoiceRows,
        ] = await Promise.all([
          apiClient.listOrganizations(),
          apiClient.listUsers(),
          apiClient.listPackages(),
          apiClient.listScans(),
          apiClient.listOrganizationUsage(),
          apiClient.listInvoices(),
        ]);

        setCounts({
          organizations: organizations.length,
          users: users.length,
          packages: packages.length,
          scans: scans.length,
        });

        setUsage(Array.isArray(usageRows) ? usageRows : []);
        setInvoices(Array.isArray(invoiceRows) ? invoiceRows : []);
        setScansData(Array.isArray(scans) ? scans : []);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }

    loadCounts();
  }, []);

  // =============================
  // EXISTING ANALYTICS
  // =============================
  const analytics = useMemo(() => {
    const totalWeeklyUsed = usage.reduce(
      (t, r) => t + Number(r.scans_used_this_week || 0),
      0
    );

    const totalWeeklyLimit = usage.reduce(
      (t, r) => t + Number(r.scan_limit_per_week || 0),
      0
    );

    const packageDistribution = usage.reduce<Record<string, number>>(
      (acc, row) => {
        const key = row.package_name || "No package";
        acc[key] = (acc[key] || 0) + 1;
        return acc;
      },
      {}
    );

    const topOrganizations = [...usage]
      .sort(
        (a, b) =>
          Number(b.scans_used_this_week || 0) -
          Number(a.scans_used_this_week || 0)
      )
      .slice(0, 5);

    return {
      totalWeeklyUsed,
      totalWeeklyLimit,
      packageDistribution,
      topOrganizations,
    };
  }, [usage]);

  // =============================
  // 📈 TIME ANALYTICS
  // =============================
  const scansPerDay = useMemo(() => {
    const map: Record<string, number> = {};

    scansData.forEach((scan) => {
      const d = scan.created_at.slice(0, 10);
      map[d] = (map[d] || 0) + 1;
    });

    return map;
  }, [scansData]);

  const last7Days = useMemo(() => {
    const arr: string[] = [];
    const today = new Date();

    for (let i = 6; i >= 0; i--) {
      const d = new Date(today);
      d.setDate(today.getDate() - i);
      arr.push(d.toISOString().slice(0, 10));
    }

    return arr;
  }, []);

  const scansChart = {
    options: { xaxis: { categories: last7Days } },
    series: [
      {
        name: "Scans",
        data: last7Days.map((d) => scansPerDay[d] || 0),
      },
    ],
  };

  // =============================
  // 💰 REVENUE ANALYTICS
  // =============================
  const revenue = useMemo(() => {
    let total = 0;
    let paid = 0;
    let unpaid = 0;

    const monthly: Record<string, number> = {};

    invoices.forEach((inv) => {
      const amt = Number(inv.amount || 0);

      total += amt;

      if (inv.status === "paid") paid += amt;
      else unpaid += amt;

      const month = inv.created_at.slice(0, 7);
      monthly[month] = (monthly[month] || 0) + amt;
    });

    return { total, paid, unpaid, monthly };
  }, [invoices]);

  const revenueChart = {
    options: {
      xaxis: {
        categories: Object.keys(revenue.monthly),
      },
    },
    series: [
      {
        name: "Revenue",
        data: Object.values(revenue.monthly),
      },
    ],
  };

  if (loading) {
    return <div className="p-6">Loading...</div>;
  }

  const weeklyCapacity =
    analytics.totalWeeklyLimit > 0
      ? Math.round(
          (analytics.totalWeeklyUsed / analytics.totalWeeklyLimit) * 100
        )
      : 0;

  const packageLabels = Object.keys(analytics.packageDistribution);
  const packageSeries = Object.values(analytics.packageDistribution);

  return (
    <section className="space-y-6">

      {/* KPI */}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Organizations" value={counts.organizations} />
        <StatCard label="Users" value={counts.users} />
        <StatCard label="Packages" value={counts.packages} />
        <StatCard label="Total Scans" value={counts.scans} />
      </div>

      {/* 💰 REVENUE KPI */}
      <div className="grid gap-4 md:grid-cols-3">
        <StatCard label="Total Revenue" value={`$${revenue.total}`} />
        <StatCard label="Paid Revenue" value={`$${revenue.paid}`} />
        <StatCard label="Pending Revenue" value={`$${revenue.unpaid}`} />
      </div>

      {/* CAPACITY */}
      <div className="bg-white p-6 rounded-2xl border">
        <h3>Weekly Capacity</h3>
        <div className="h-3 bg-slate-100 rounded">
          <div
            className="bg-blue-600 h-full"
            style={{ width: `${weeklyCapacity}%` }}
          />
        </div>
      </div>

      {/* EXISTING CHARTS */}
      <div className="grid gap-6 xl:grid-cols-3">
        <Chart type="donut" series={packageSeries} options={{ labels: packageLabels }} height={250}/>
        <Chart type="bar" series={[{ data: usage.map(u=>u.scans_used_this_week) }]} options={{ xaxis:{ categories: usage.map(u=>u.organization_name)}}}/>
        <Chart type="bar" series={[{ data: analytics.topOrganizations.map(o=>o.scans_used_this_week)}]} options={{ plotOptions:{bar:{horizontal:true}}, xaxis:{ categories: analytics.topOrganizations.map(o=>o.organization_name)}}}/>
      </div>

      {/* 📈 SCANS TIME */}
      <div className="bg-white p-6 rounded-2xl border">
        <h3>Scans (Last 7 Days)</h3>
        <Chart type="line" height={300} series={scansChart.series} options={scansChart.options}/>
      </div>

      {/* 💰 REVENUE CHART */}
      <div className="bg-white p-6 rounded-2xl border">
        <h3>Revenue Growth</h3>
        <Chart type="bar" height={300} series={revenueChart.series} options={revenueChart.options}/>
      </div>

    </section>
  );
}

function StatCard({ label, value }: any) {
  return (
    <div className="bg-white p-5 rounded-2xl border shadow-sm">
      <p className="text-sm text-slate-500">{label}</p>
      <p className="text-2xl font-semibold mt-2">{value}</p>
    </div>
  );
}