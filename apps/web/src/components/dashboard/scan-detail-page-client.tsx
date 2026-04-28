"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { apiClient } from "@/lib/api-client";
import { Scan } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { useToast } from "@/components/ui/toast-provider";
import { ScanDetailSections } from "@/components/dashboard/scan-detail-sections";
import { AiReportSection } from "@/components/dashboard/ai-report-section";
import { ScanProgressPanel } from "@/components/dashboard/scan-progress-panel";

function isActiveScan(status?: string) {
  const value = (status || "").toLowerCase();
  return value === "queued" || value === "pending" || value === "running";
}

function isDoneScan(status?: string) {
  const value = (status || "").toLowerCase();
  return value === "completed" || value === "failed" || value === "cancelled";
}

export function ScanDetailPageClient({ scanId }: { scanId: number }) {
  const router = useRouter();
  const { showToast } = useToast();
  const [scan, setScan] = useState<Scan | null>(null);
  const [pages, setPages] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [technologies, setTechnologies] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [softRefreshing, setSoftRefreshing] = useState(false);
  const [retesting, setRetesting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const previousStatusRef = useRef<string | null>(null);

  const handleRetest = useCallback(async () => {
    if (retesting) return;

    setRetesting(true);
    try {
      const newScan = await apiClient.retestScan(scanId);
      showToast(
        `Retest started. New scan #${newScan.id} is queued.`,
        "success"
      );

      if (newScan?.id && newScan.id !== scanId) {
        router.push(`/dashboard/scans/${newScan.id}`);
      }
    } catch (err) {
      console.error("Failed to start retest", err);
      const message =
        err instanceof Error && err.message
          ? err.message
          : "Unable to start retest.";
      showToast(message, "error");
      setError(message);
    } finally {
      setRetesting(false);
    }
  }, [retesting, scanId, router, showToast]);

  const loadScanDetails = useCallback(
    async (silent = false) => {
      try {
        if (silent) setSoftRefreshing(true);
        else setLoading(true);

        setError(null);

        const [scanData, pagesData, findingsData, technologiesData] =
          await Promise.all([
            apiClient.getScan(scanId),
            apiClient.getScanPages(scanId),
            apiClient.getScanFindings(scanId),
            apiClient.getScanTechnologies(scanId),
          ]);

        const nextStatus = String(scanData?.status || "").toLowerCase();
        const previousStatus = previousStatusRef.current;

        setScan(scanData);
        setPages(Array.isArray(pagesData) ? pagesData : []);
        setFindings(Array.isArray(findingsData) ? findingsData : []);
        setTechnologies(Array.isArray(technologiesData) ? technologiesData : []);

        if (
          previousStatus &&
          previousStatus !== nextStatus &&
          nextStatus === "completed"
        ) {
          setToast("Scan completed successfully.");
        }

        if (
          previousStatus &&
          previousStatus !== nextStatus &&
          nextStatus === "failed"
        ) {
          setToast("Scan failed. Please review the results.");
        }

        previousStatusRef.current = nextStatus;
      } catch (err) {
        console.error("Failed to load scan details", err);
        setError("Unable to load scan details.");
      } finally {
        setLoading(false);
        setSoftRefreshing(false);
      }
    },
    [scanId]
  );

  useEffect(() => {
    void loadScanDetails(false);
  }, [loadScanDetails]);

  useEffect(() => {
    if (!scan || !isActiveScan(scan.status)) return;

    const interval = window.setInterval(() => {
      void loadScanDetails(true);
    }, 2500);

    return () => window.clearInterval(interval);
  }, [scan, loadScanDetails]);

  useEffect(() => {
    if (!toast) return;

    const timeout = window.setTimeout(() => {
      setToast(null);
    }, 4500);

    return () => window.clearTimeout(timeout);
  }, [toast]);

  const liveScan = useMemo(() => {
    if (!scan) return null;

    const status = String(scan.status || "").toLowerCase();

    let progress = Number((scan as any).progress || 0);

    if (!progress) {
      if (status === "completed") progress = 100;
      else if (status === "failed" || status === "cancelled") progress = 100;
      else if (pages.length > 0 || findings.length > 0 || technologies.length > 0) {
        progress = 65;
      } else if (status === "running") {
        progress = 35;
      } else {
        progress = 10;
      }
    }

    return {
      ...scan,
      progress,
      total_pages_found: (scan as any).total_pages_found ?? pages.length,
      total_findings: (scan as any).total_findings ?? findings.length,
    };
  }, [scan, pages.length, findings.length, technologies.length]);

  if (loading) {
    return (
      <div className="rounded-2xl border border-slate-200 bg-white p-6 text-sm text-slate-500 shadow-sm">
        Loading scan details...
      </div>
    );
  }

  if (error && !scan) {
    return (
      <div className="rounded-2xl border border-red-200 bg-red-50 p-6 text-sm text-red-700">
        {error}
      </div>
    );
  }

  if (!scan || !liveScan) {
    return (
      <div className="rounded-2xl border border-slate-200 bg-white p-6 text-sm text-slate-500 shadow-sm">
        No scan data found.
      </div>
    );
  }

  const targetLabel =
    (scan as any).target?.normalized_domain ||
    (scan as any).target?.base_url ||
    `Target #${scan.target_id}`;

  return (
    <section className="relative space-y-6">
      {toast ? (
        <div className="fixed right-6 top-6 z-50 rounded-xl border border-emerald-200 bg-white px-5 py-4 text-sm font-medium text-emerald-700 shadow-lg">
          {toast}
        </div>
      ) : null}

      <div className="flex flex-col justify-between gap-4 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm md:flex-row md:items-center">
        <div>
          <p className="text-sm font-medium uppercase tracking-wide text-blue-600">
            Scan Details
          </p>
          <h2 className="mt-2 text-2xl font-semibold tracking-tight text-slate-950">
            Scan #{scan.id}
          </h2>
          <p className="mt-1 text-sm text-slate-500">
            Live scan progress, crawled pages, security issues, SEO issues,
            performance signals, and detected technologies.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {softRefreshing ? (
            <span className="text-xs font-medium text-slate-400">
              Updating...
            </span>
          ) : null}

          <Button variant="secondary" onClick={() => void loadScanDetails(false)}>
            Refresh
          </Button>

          <Button
            variant="primary"
            onClick={() => void handleRetest()}
            disabled={retesting || isActiveScan(scan?.status)}
            aria-busy={retesting}
            title={
              isActiveScan(scan?.status)
                ? "Wait for the current scan to finish before retesting."
                : "Run this scan again against the same target."
            }
          >
            {retesting ? "Starting retest..." : "Retest Scan"}
          </Button>
        </div>
      </div>

<ScanProgressPanel scan={liveScan as Scan} targetLabel={targetLabel} />

{!isDoneScan(scan.status) ? (
  <div className="rounded-2xl border border-blue-100 bg-blue-50 p-6 text-sm text-blue-700">
    Scan is still running. Results below will update automatically as the
    crawler finds pages and issues.
  </div>
) : null}

<ScanDetailSections
  scan={scan}
  pages={pages}
  findings={findings}
  technologies={technologies}
/>

<AiReportSection
  scanId={scan.id}
  scanStatus={scan.status}
  scan={scan}
  findings={findings}
/>
    </section>
  );
}
