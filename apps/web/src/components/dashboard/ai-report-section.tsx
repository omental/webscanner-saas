"use client";

import { useCallback, useEffect, useState } from "react";
import { buildApiUrl } from "@/lib/api-client";
import { getSessionUser } from "@/lib/session";
import { Finding, Scan } from "@/lib/types";

type Props = {
  scanId: number;
  scanStatus: string;
  scan?: Scan | null;
  findings?: Finding[];
};

type AiReportResponse = {
  report_id: number;
  scan_id: number;
  report_text: string;
  download_url: string;
  generated_at: string;
};

type ReportHistoryItem = {
  id: number;
  scan_id: number;
  status?: string;
  created_at: string | null;
  download_url: string;
  has_pdf?: boolean;
  provider?: string | null;
  model?: string | null;
  report_text?: string | null;
};

function getAuthHeaders(): Record<string, string> {
  const user = getSessionUser();

  if (!user?.id) {
    return {};
  }

  return {
    "X-Current-User-Id": String(user.id),
  };
}

function normalizeApiPath(path?: string | null) {
  if (!path) return "";

  if (path.startsWith("/api/v1")) {
    return path;
  }

  if (path.startsWith("/")) {
    return `/api/v1${path}`;
  }

  return `/api/v1/${path}`;
}

function formatDate(value?: string | null) {
  if (!value) return "Not available";
  return new Date(value).toLocaleString();
}

function reportPreview(text?: string | null) {
  if (!text) return "Report preview is not available for this entry.";
  const normalized = text.replace(/\s+/g, " ").trim();
  return normalized.length > 220 ? `${normalized.slice(0, 220)}...` : normalized;
}

function normalizeConfidence(finding: Finding) {
  return String(finding.confidence_level || finding.confidence || "info").toLowerCase();
}

function isInformationalObservation(finding: Finding) {
  const confidence = normalizeConfidence(finding);
  return confidence === "low" || confidence === "info" || confidence === "informational";
}

function StatusBadge({ status }: { status: string }) {
  const value = status.toLowerCase();
  const classes =
    value === "completed"
      ? "bg-emerald-50 text-emerald-700"
      : value === "generating"
        ? "bg-blue-50 text-blue-700"
        : value === "failed"
          ? "bg-red-50 text-red-700"
          : "bg-slate-100 text-slate-700";

  return (
    <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${classes}`}>
      {status}
    </span>
  );
}

export function AiReportSection({
  scanId,
  scanStatus,
  scan,
  findings = [],
}: Props) {
  const [reportText, setReportText] = useState<string | null>(null);
  const [generatedAt, setGeneratedAt] = useState<string | null>(null);
  const [downloadUrl, setDownloadUrl] = useState<string | null>(null);
  const [reportId, setReportId] = useState<number | null>(null);

  const [history, setHistory] = useState<ReportHistoryItem[]>([]);
  const [isGenerating, setIsGenerating] = useState(false);
  const [downloadingReportId, setDownloadingReportId] = useState<number | null>(
    null
  );
  const [error, setError] = useState<string | null>(null);

  const isCompleted = scanStatus?.toLowerCase() === "completed";
  const latestReport = history[0] || null;
  const reportStatus = isGenerating
    ? "generating"
    : error
      ? "failed"
      : reportText || latestReport
        ? "completed"
        : "not generated";
  const mainSecurityFindings = findings.filter(
    (finding) => !isInformationalObservation(finding)
  ).length;
  const informationalObservations = findings.filter(isInformationalObservation).length;
  const activeReportPreview = reportText || latestReport?.report_text || null;
  const activeGeneratedAt = generatedAt || latestReport?.created_at || null;
  const activeProvider = latestReport?.provider || "AI provider not reported";
  const activeModel = latestReport?.model || "Model not reported";

  const fetchHistory = useCallback(async () => {
    try {
      const res = await fetch(
        buildApiUrl(`/api/v1/scans/${scanId}/reports`),
        {
          method: "GET",
          credentials: "include",
          cache: "no-store",
          headers: getAuthHeaders(),
        }
      );

      if (!res.ok) {
        const body = await res.text();
        console.error("Report history failed", res.status, body);
        return;
      }

      const data = await res.json();
      setHistory(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error("Report history request failed", err);
    }
  }, [scanId]);

  useEffect(() => {
    void fetchHistory();
  }, [fetchHistory]);

  async function handleGenerate() {
    try {
      setIsGenerating(true);
      setError(null);

      const res = await fetch(
        buildApiUrl(`/api/v1/scans/${scanId}/ai-report`),
        {
          method: "POST",
          credentials: "include",
          cache: "no-store",
          headers: getAuthHeaders(),
        }
      );

      if (!res.ok) {
        const body = await res.text();
        console.error("AI report generation failed", res.status, body);

        if (res.status === 401) {
          throw new Error("Please sign in again before generating a report.");
        }

        if (res.status === 403) {
          throw new Error("You do not have permission to generate this report.");
        }

        throw new Error(body || "Failed to generate AI report.");
      }

      const data: AiReportResponse = await res.json();

      setReportId(data.report_id);
      setReportText(data.report_text);
      setGeneratedAt(data.generated_at);
      setDownloadUrl(data.download_url);

      await fetchHistory();
    } catch (err) {
      console.error("AI report error", err);
      setError(
        err instanceof Error ? err.message : "Failed to generate AI report."
      );
    } finally {
      setIsGenerating(false);
    }
  }

  async function downloadReport(id: number, url?: string | null) {
    try {
      setDownloadingReportId(id);
      setError(null);

      const endpoint = url
        ? normalizeApiPath(url)
        : `/api/v1/scan-reports/${id}/download`;

      const res = await fetch(buildApiUrl(endpoint), {
        method: "GET",
        credentials: "include",
        cache: "no-store",
        headers: getAuthHeaders(),
      });

      if (!res.ok) {
        const body = await res.text();
        console.error("PDF download failed", res.status, body);

        if (res.status === 401) {
          throw new Error("Please sign in again before downloading the report.");
        }

        if (res.status === 403) {
          throw new Error("You do not have permission to download this report.");
        }

        throw new Error(body || "Unable to generate PDF report.");
      }

      const blob = await res.blob();
      const blobUrl = window.URL.createObjectURL(blob);

      const a = document.createElement("a");
      a.href = blobUrl;
      a.download = `scan-report-${scanId}-${id}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();

      window.URL.revokeObjectURL(blobUrl);
    } catch (err) {
      console.error("PDF download error", err);
      setError(
        err instanceof Error ? err.message : "Unable to generate PDF report."
      );
    } finally {
      setDownloadingReportId(null);
    }
  }

  return (
    <section className="rounded-2xl border border-blue-100 bg-white p-6 shadow-sm ring-1 ring-blue-50">
      <div className="flex flex-col justify-between gap-4 border-b border-slate-200 pb-5 md:flex-row md:items-center">
        <div>
          <p className="text-sm font-medium uppercase tracking-wide text-blue-600">
            Report Center
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-3">
            <h3 className="text-xl font-semibold text-slate-950">
              Security Report
            </h3>
            <StatusBadge status={reportStatus} />
          </div>
          <p className="mt-1 text-sm text-slate-500">
            Generate, review, and download a client-ready report for this scan.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            disabled={!isCompleted || isGenerating}
            onClick={handleGenerate}
            className="inline-flex items-center justify-center rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {isGenerating
              ? "Generating..."
              : reportText || latestReport
                ? "Regenerate Report"
                : "Generate AI Report"}
          </button>

          {(downloadUrl && reportId) || latestReport ? (
            <button
              type="button"
              onClick={() =>
                reportId
                  ? void downloadReport(reportId, downloadUrl)
                  : latestReport
                    ? void downloadReport(latestReport.id, latestReport.download_url)
                    : undefined
              }
              disabled={downloadingReportId !== null}
              className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:opacity-50"
            >
              {downloadingReportId !== null ? "Downloading..." : "Download PDF Report"}
            </button>
          ) : null}
        </div>
      </div>

      <div className="mt-5 grid gap-3 md:grid-cols-3">
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <p className="text-xs font-medium text-slate-500">Risk Score</p>
          <p className="mt-2 text-2xl font-semibold text-red-600">
            {scan?.risk_score ?? "—"}
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <p className="text-xs font-medium text-slate-500">Main Security Findings</p>
          <p className="mt-2 text-2xl font-semibold text-slate-950">
            {mainSecurityFindings}
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <p className="text-xs font-medium text-slate-500">Informational Observations</p>
          <p className="mt-2 text-2xl font-semibold text-blue-600">
            {informationalObservations}
          </p>
        </div>
      </div>

      {!isCompleted ? (
        <div className="mt-5 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
          Security reports are available after the scan is completed.
        </div>
      ) : null}

      {isGenerating ? (
        <div className="mt-5 rounded-xl border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-800">
          Generating security report. Large scans may take 1–2 minutes.
        </div>
      ) : null}

      {error ? (
        <div className="mt-5 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      ) : null}

      {reportText ? (
        <div className="mt-6 space-y-4">
          <div className="flex flex-col justify-between gap-3 rounded-xl border border-slate-200 bg-slate-50 p-4 md:flex-row md:items-center">
            <div>
              <p className="text-sm font-medium text-slate-900">
                Report generated
              </p>
              <p className="mt-1 text-xs text-slate-500">
                {formatDate(generatedAt)}
              </p>
            </div>

            {downloadUrl && reportId ? (
              <button
                type="button"
                onClick={() => void downloadReport(reportId, downloadUrl)}
                disabled={downloadingReportId !== null}
                className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:opacity-50"
              >
                {downloadingReportId !== null
                  ? "Downloading..."
                  : "Download PDF"}
              </button>
            ) : null}
          </div>

          <div className="max-h-[520px] overflow-auto whitespace-pre-wrap rounded-xl border border-slate-200 bg-white p-5 text-sm leading-7 text-slate-700">
            {reportText}
          </div>
        </div>
      ) : latestReport ? (
        <div className="mt-6 rounded-xl border border-slate-200 bg-slate-50 p-5">
          <div className="flex flex-col justify-between gap-3 md:flex-row md:items-start">
            <div>
              <p className="text-sm font-semibold text-slate-950">
                Latest generated report
              </p>
              <p className="mt-1 text-xs text-slate-500">
                {activeProvider} · {activeModel} · {formatDate(activeGeneratedAt)}
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => void downloadReport(latestReport.id, latestReport.download_url)}
                disabled={downloadingReportId === latestReport.id}
                className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:opacity-50"
              >
                {downloadingReportId === latestReport.id ? "Downloading..." : "Download PDF"}
              </button>
              <button
                type="button"
                onClick={() => void downloadReport(latestReport.id, latestReport.download_url)}
                disabled={downloadingReportId === latestReport.id}
                className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:opacity-50"
              >
                View generated report
              </button>
            </div>
          </div>
          <p className="mt-4 text-sm leading-6 text-slate-600">
            {reportPreview(activeReportPreview)}
          </p>
        </div>
      ) : (
        <div className="mt-6 rounded-xl border border-dashed border-slate-200 p-8 text-center">
          <p className="text-sm font-medium text-slate-900">
            No security report generated yet.
          </p>
          <p className="mt-1 text-sm text-slate-500">
            Click Generate AI Report to create a professional scan report.
          </p>
        </div>
      )}

      <div className="mt-6">
        <div className="mb-3 flex items-center justify-between">
          <h4 className="text-sm font-semibold text-slate-950">
            Previous Reports
          </h4>

          <button
            type="button"
            onClick={() => void fetchHistory()}
            className="text-xs font-medium text-slate-500 transition hover:text-slate-900"
          >
            Refresh
          </button>
        </div>

        {history.length === 0 ? (
          <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-500">
            No previous reports found.
          </div>
        ) : (
          <div className="divide-y divide-slate-100 overflow-hidden rounded-xl border border-slate-200">
            {history.map((report) => (
              <div
                key={report.id}
                className="flex flex-col justify-between gap-3 bg-white px-4 py-3 md:flex-row md:items-center"
              >
                <div>
                  <p className="text-sm font-medium text-slate-950">
                    Report #{report.id}
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    {(report.provider || "Provider not reported") +
                      " · " +
                      (report.model || "Model not reported") +
                      " · " +
                      formatDate(report.created_at)}
                  </p>
                  {report.status ? (
                    <div className="mt-2">
                      <StatusBadge status={report.status} />
                    </div>
                  ) : null}
                </div>

                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() =>
                      void downloadReport(report.id, report.download_url)
                    }
                    disabled={downloadingReportId === report.id}
                    className="w-fit rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:opacity-50"
                  >
                    {downloadingReportId === report.id
                      ? "Downloading..."
                      : "Download PDF"}
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      void downloadReport(report.id, report.download_url)
                    }
                    disabled={downloadingReportId === report.id}
                    className="w-fit rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:opacity-50"
                  >
                    Open
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <p className="mt-5 text-xs leading-5 text-slate-500">
        AI-generated content should be reviewed before being shared externally.
      </p>
    </section>
  );
}
