"use client";

import { useMemo, useState } from "react";
import { Scan } from "@/lib/types";

type FilterType = "all" | "security" | "seo" | "performance";

type Props = {
  scan: Scan;
  pages: any[];
  findings: any[];
  technologies: any[];
};

function normalizeCategory(category?: string): FilterType {
  const value = (category || "").toLowerCase();

  if (value.includes("seo")) return "seo";
  if (value.includes("performance") || value.includes("speed")) {
    return "performance";
  }

  return "security";
}

function severityClass(severity?: string) {
  const value = (severity || "").toLowerCase();

  if (value === "critical") return "bg-red-50 text-red-700 ring-red-600/10";
  if (value === "high") return "bg-orange-50 text-orange-700 ring-orange-600/10";
  if (value === "medium") return "bg-yellow-50 text-yellow-700 ring-yellow-600/10";
  if (value === "low") return "bg-blue-50 text-blue-700 ring-blue-600/10";

  return "bg-slate-100 text-slate-700 ring-slate-600/10";
}

function categoryBadgeClass(category?: string) {
  const normalized = normalizeCategory(category);

  if (normalized === "security") return "bg-red-50 text-red-700";
  if (normalized === "seo") return "bg-blue-50 text-blue-700";
  if (normalized === "performance") return "bg-amber-50 text-amber-700";

  return "bg-slate-100 text-slate-700";
}

function normalizeConfidence(finding: any) {
  return String(finding?.confidence_level || finding?.confidence || "info").toLowerCase();
}

function confidenceBadgeClass(confidence?: string | null) {
  const value = String(confidence || "info").toLowerCase();

  if (value === "confirmed") return "bg-emerald-50 text-emerald-700 ring-emerald-600/10";
  if (value === "high") return "bg-red-50 text-red-700 ring-red-600/10";
  if (value === "medium") return "bg-yellow-50 text-yellow-700 ring-yellow-600/10";
  if (value === "low") return "bg-blue-50 text-blue-700 ring-blue-600/10";

  return "bg-slate-100 text-slate-700 ring-slate-600/10";
}

function isInformationalObservation(finding: any) {
  const confidence = normalizeConfidence(finding);
  return confidence === "low" || confidence === "info" || confidence === "informational";
}

function formatFieldValue(value: unknown) {
  if (value === null || value === undefined || value === "") return "Not available";
  if (Array.isArray(value)) return value.join(", ");
  return String(value);
}

function slugify(text: string) {
  return text
    .toLowerCase()
    .replace(/<=/g, "")
    .replace(/>=/g, "")
    .replace(/[()]/g, "")
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

function extractCveFromText(text?: string | null) {
  if (!text) return null;
  const match = text.match(/CVE-\d{4}-\d+/i);
  return match ? match[0].toUpperCase() : null;
}

function extractCweFromText(text?: string | null) {
  if (!text) return null;
  const match = text.match(/CWE-\d+/i);
  return match ? match[0].toUpperCase() : null;
}

function extractOwaspFromText(text?: string | null) {
  if (!text) return null;
  const match = text.match(/OWASP\s+A\d{2}/i);
  return match ? match[0].toUpperCase().replace(/\s+/, " ") : null;
}

function extractExploitDbFromText(text?: string | null) {
  if (!text) return null;
  const match = text.match(/(?:EDB-ID|Exploit-DB)[:\s#-]*(\d+)/i);
  return match ? `Exploit-DB ${match[1]}` : null;
}

function extractPluginSlug(text?: string | null) {
  if (!text) return null;

  const match =
    text.match(/plugin slug:\s*([a-z0-9-_]+)/i) ||
    text.match(/detected plugin slug:\s*([a-z0-9-_]+)/i) ||
    text.match(/slug:\s*([a-z0-9-_]+)/i);

  return match ? match[1].toLowerCase() : null;
}

function buildWordfenceUrl(finding: any, reference?: any) {
  const directUrl =
    reference?.url ||
    reference?.href ||
    reference?.link ||
    reference?.wordfence_url ||
    finding?.wordfence_url;

  if (typeof directUrl === "string" && directUrl.includes("wordfence.com")) {
    return directUrl;
  }

  const pluginSlug =
    reference?.plugin_slug ||
    finding?.plugin_slug ||
    extractPluginSlug(finding?.evidence) ||
    extractPluginSlug(finding?.description);

  const title =
    reference?.title ||
    finding?.title ||
    finding?.name;

  if (!pluginSlug || !title) return null;

  const vulnerabilitySlug = slugify(title);

  if (!vulnerabilitySlug) return null;

  return `https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/${pluginSlug}/${vulnerabilitySlug}`;
}

function buildReferenceLinks(finding: any) {
  const links = new Map<string, { label: string; url?: string; kind: string }>();

  const references = Array.isArray(finding?.references)
    ? finding.references
    : [];

  function add(label?: string | null, url?: string | null, kind = "reference") {
    if (!label) return;
    const key = url || `${kind}:${label}`;
    if (!links.has(key)) links.set(key, { label, url: url || undefined, kind });
  }

  for (const ref of references) {
    const source = String(ref?.source || ref?.provider || ref?.ref_type || "").toLowerCase();
    const value = ref?.ref_value || ref?.value || ref?.title || ref?.name;
    const directUrl = ref?.ref_url || ref?.url || ref?.href || ref?.link;

    if (directUrl) {
      const label =
        value ||
        ref?.title ||
        ref?.name ||
        ref?.cve ||
        ref?.cve_id ||
        ref?.source ||
        "Reference";

      add(label, directUrl, source || "advisory");
      continue;
    }

    const cve =
      extractCveFromText(value) ||
      ref?.cve ||
      ref?.cve_id ||
      extractCveFromText(ref?.title) ||
      extractCveFromText(ref?.name) ||
      extractCveFromText(ref?.description);

    if (cve) {
      add(cve, `https://nvd.nist.gov/vuln/detail/${cve}`, "cve");
      continue;
    }

    const cwe = extractCweFromText(value) || extractCweFromText(ref?.description);
    if (cwe) {
      add(cwe, `https://cwe.mitre.org/data/definitions/${cwe.replace("CWE-", "")}.html`, "cwe");
      continue;
    }

    const owasp = extractOwaspFromText(value) || extractOwaspFromText(ref?.description);
    if (owasp) {
      add(owasp, "https://owasp.org/www-project-top-ten/", "owasp");
      continue;
    }

    const exploitDb =
      extractExploitDbFromText(value) || extractExploitDbFromText(ref?.description);
    if (exploitDb) {
      add(exploitDb, undefined, "exploitdb");
      continue;
    }

    if (source.includes("wordfence")) {
      add("Wordfence Vulnerability", buildWordfenceUrl(finding, ref), "advisory");
      continue;
    }

    if (source.includes("nvd")) {
      const fallbackCve =
        extractCveFromText(finding?.title) ||
        extractCveFromText(finding?.description) ||
        extractCveFromText(finding?.evidence);

      if (fallbackCve) {
        add(fallbackCve, `https://nvd.nist.gov/vuln/detail/${fallbackCve}`, "cve");
      }
      continue;
    }

    if (source.includes("kev") || source.includes("cisa")) {
      add("KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "kev");
    }
  }

  const cveFromFinding =
    finding?.cve ||
    finding?.cve_id ||
    extractCveFromText(finding?.title) ||
    extractCveFromText(finding?.description) ||
    extractCveFromText(finding?.evidence);

  if (cveFromFinding) {
    add(cveFromFinding, `https://nvd.nist.gov/vuln/detail/${cveFromFinding}`, "cve");
  }

  const cweFromFinding =
    finding?.cwe ||
    finding?.cwe_id ||
    extractCweFromText(finding?.title) ||
    extractCweFromText(finding?.description) ||
    extractCweFromText(finding?.evidence);

  if (cweFromFinding) {
    add(
      cweFromFinding,
      `https://cwe.mitre.org/data/definitions/${String(cweFromFinding).replace("CWE-", "")}.html`,
      "cwe"
    );
  }

  const owaspFromFinding =
    finding?.owasp_category ||
    extractOwaspFromText(finding?.title) ||
    extractOwaspFromText(finding?.description) ||
    extractOwaspFromText(finding?.evidence);

  if (owaspFromFinding) {
    add(owaspFromFinding, "https://owasp.org/www-project-top-ten/", "owasp");
  }

  const exploitDbFromFinding =
    finding?.exploitdb_id ||
    extractExploitDbFromText(finding?.title) ||
    extractExploitDbFromText(finding?.description) ||
    extractExploitDbFromText(finding?.evidence);

  if (exploitDbFromFinding) {
    add(String(exploitDbFromFinding), undefined, "exploitdb");
  }

  const wordfenceUrl = buildWordfenceUrl(finding);
  if (wordfenceUrl) {
    add("External advisory", wordfenceUrl, "advisory");
  }

  const evidence = String(finding?.evidence || "").toLowerCase();
  const description = String(finding?.description || "").toLowerCase();

  if (
    evidence.includes("kev") ||
    evidence.includes("known exploited") ||
    description.includes("known exploited")
  ) {
    add("KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "kev");
  }

  return Array.from(links.values());
}

function referenceBadgeClass(kind?: string) {
  const value = String(kind || "").toLowerCase();

  if (value.includes("cve") || value.includes("nvd")) return "bg-red-50 text-red-700 hover:bg-red-100";
  if (value.includes("kev") || value.includes("cisa")) return "bg-orange-50 text-orange-700 hover:bg-orange-100";
  if (value.includes("cwe")) return "bg-violet-50 text-violet-700 hover:bg-violet-100";
  if (value.includes("owasp")) return "bg-blue-50 text-blue-700 hover:bg-blue-100";
  if (value.includes("exploit")) return "bg-rose-50 text-rose-700 hover:bg-rose-100";

  return "bg-slate-100 text-slate-700 hover:bg-blue-50 hover:text-blue-700";
}

function ReferenceLinks({ finding }: { finding: any }) {
  const links = buildReferenceLinks(finding);

  if (links.length === 0) return null;

  return (
    <div className="mt-3">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
        References
      </p>

      <div className="mt-2 flex flex-wrap gap-2">
        {links.map((link) =>
          link.url ? (
            <a
              key={`${link.kind}:${link.label}:${link.url}`}
              href={link.url}
              target="_blank"
              rel="noreferrer"
              className={`inline-flex items-center rounded-full px-3 py-1.5 text-xs font-medium transition ${referenceBadgeClass(
                link.kind
              )}`}
            >
              {link.label}
            </a>
          ) : (
            <span
              key={`${link.kind}:${link.label}`}
              className={`inline-flex items-center rounded-full px-3 py-1.5 text-xs font-medium ${referenceBadgeClass(
                link.kind
              )}`}
            >
              {link.label}
            </span>
          )
        )}
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  color = "text-slate-950",
}: {
  label: string;
  value: number | string;
  color?: string;
}) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-sm font-medium text-slate-500">{label}</p>
      <p className={`mt-3 text-3xl font-semibold ${color}`}>{value}</p>
    </div>
  );
}

function FindingDetail({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: unknown;
  mono?: boolean;
}) {
  if (value === null || value === undefined || value === "") return null;

  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
        {label}
      </p>
      <p
        className={[
          "mt-1 break-words text-sm leading-5 text-slate-700",
          mono ? "font-mono text-xs" : "",
        ].join(" ")}
      >
        {formatFieldValue(value)}
      </p>
    </div>
  );
}

function formatVerificationSteps(value: unknown) {
  if (!value) return null;
  if (Array.isArray(value)) return value.map(String);
  if (typeof value === "string") return [value];
  return null;
}

function FindingSummaryMeta({ finding }: { finding: any }) {
  const affected = finding.request_url || finding.affected_parameter || finding.tested_parameter;
  const retestStatus = finding.comparison_status || finding.retest_status;

  if (!affected && !retestStatus) return null;

  return (
    <div className="mt-3 flex flex-wrap gap-2 text-xs">
      {affected ? (
        <span className="rounded-full bg-slate-100 px-2.5 py-1 font-medium text-slate-700">
          Affected: {affected}
        </span>
      ) : null}
      {retestStatus ? (
        <span className="rounded-full bg-indigo-50 px-2.5 py-1 font-medium text-indigo-700">
          Retest: {retestStatus}
        </span>
      ) : null}
    </div>
  );
}

function FilterButton({
  active,
  label,
  count,
  onClick,
}: {
  active: boolean;
  label: string;
  count: number;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        "inline-flex items-center gap-2 rounded-full border px-4 py-2 text-sm font-medium transition",
        active
          ? "border-blue-200 bg-blue-50 text-blue-700"
          : "border-slate-200 bg-white text-slate-600 hover:bg-slate-50",
      ].join(" ")}
    >
      {label}
      <span
        className={[
          "rounded-full px-2 py-0.5 text-xs",
          active ? "bg-blue-100 text-blue-700" : "bg-slate-100 text-slate-600",
        ].join(" ")}
      >
        {count}
      </span>
    </button>
  );
}

function FindingCard({ finding }: { finding: any }) {
  const confidenceLabel = normalizeConfidence(finding);
  const [expanded, setExpanded] = useState(false);
  const verificationSteps = formatVerificationSteps(finding.verification_steps);

  return (
    <div className="px-6 py-4">
      <div className="flex flex-col justify-between gap-4 md:flex-row md:items-start">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h4 className="font-medium text-slate-950">
              {finding.title || "Untitled issue"}
            </h4>

            <span
              className={`inline-flex rounded-full px-2.5 py-1 text-xs font-medium ring-1 ring-inset ${severityClass(
                finding.severity
              )}`}
            >
              {finding.severity || "Informational"}
            </span>

            <span
              className={`rounded-full px-2.5 py-1 text-xs font-medium ${categoryBadgeClass(
                finding.category
              )}`}
            >
              {finding.category || "Security"}
            </span>

            <span
              className={`inline-flex rounded-full px-2.5 py-1 text-xs font-medium ring-1 ring-inset ${confidenceBadgeClass(
                confidenceLabel
              )}`}
            >
              {confidenceLabel} confidence
              {finding.confidence_score !== null &&
              finding.confidence_score !== undefined
                ? ` · ${finding.confidence_score}`
                : ""}
            </span>

            {finding.evidence_type ? (
              <span className="rounded-full bg-violet-50 px-2.5 py-1 text-xs font-medium text-violet-700">
                {finding.evidence_type}
              </span>
            ) : null}
          </div>

          {finding.description ? (
            <p className="mt-2 max-w-4xl text-sm leading-6 text-slate-600">
              {finding.description}
            </p>
          ) : null}

          <FindingSummaryMeta finding={finding} />

          <div className="mt-4 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => setExpanded((value) => !value)}
              className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 transition hover:bg-slate-50"
            >
              {expanded ? "Hide evidence" : "Review evidence"}
            </button>
          </div>

          {expanded ? (
            <div className="mt-3 space-y-3">
              {finding.evidence ? (
                <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                  <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Evidence
                  </p>
                  <p className="mt-1 break-words font-mono text-xs leading-5 text-slate-600">
                    {finding.evidence}
                  </p>
                </div>
              ) : null}

              <div className="grid gap-3 md:grid-cols-2">
                <FindingDetail label="Payload used" value={finding.payload_used} mono />
                <FindingDetail label="Evidence type" value={finding.evidence_type} />
                <FindingDetail
                  label="Response diff"
                  value={finding.response_diff_summary}
                  mono
                />
                <FindingDetail
                  label="False positive notes"
                  value={finding.false_positive_notes}
                />
              </div>

              {verificationSteps?.length ? (
                <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                  <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Verification steps
                  </p>
                  <ol className="mt-2 list-decimal space-y-1 pl-4 text-sm leading-6 text-slate-700">
                    {verificationSteps.map((step, index) => (
                      <li key={`${finding.id}-step-${index}`}>{step}</li>
                    ))}
                  </ol>
                </div>
              ) : null}
            </div>
          ) : null}

          {finding.remediation ? (
            <div className="mt-3 rounded-xl border border-emerald-200 bg-emerald-50 p-3">
              <p className="text-xs font-semibold uppercase tracking-wide text-emerald-700">
                Recommended fix
              </p>
              <p className="mt-1 text-sm leading-6 text-emerald-800">
                {finding.remediation}
              </p>
            </div>
          ) : null}

          <ReferenceLinks finding={finding} />
        </div>

        <span className="whitespace-nowrap rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-700">
          {finding.is_confirmed ? "Confirmed" : "Detected"}
        </span>
      </div>
    </div>
  );
}

function FindingGroups({ findings }: { findings: any[] }) {
  const mainFindings = findings.filter((finding) => !isInformationalObservation(finding));
  const observations = findings.filter(isInformationalObservation);

  if (findings.length === 0) {
    return (
      <div className="px-6 py-5 text-sm text-slate-500">
        No issues found for this page.
      </div>
    );
  }

  return (
    <div className="divide-y divide-slate-100">
      {mainFindings.length > 0 ? (
        <div>
          <div className="bg-white px-6 py-3">
            <h4 className="text-sm font-semibold text-slate-950">
              Main Security Findings
            </h4>
            <p className="mt-1 text-xs text-slate-500">
              Confirmed, high, and medium confidence findings.
            </p>
          </div>
          <div className="divide-y divide-slate-100">
            {mainFindings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
          </div>
        </div>
      ) : null}

      {observations.length > 0 ? (
        <div>
          <div className="bg-slate-50 px-6 py-3">
            <h4 className="text-sm font-semibold text-slate-950">
              Informational Observations
            </h4>
            <p className="mt-1 text-xs text-slate-500">
              Low-confidence or informational signals that need review.
            </p>
          </div>
          <div className="divide-y divide-slate-100">
            {observations.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

export function ScanDetailSections({
  scan,
  pages,
  findings,
  technologies,
}: Props) {
  const [filter, setFilter] = useState<FilterType>("all");
  const [openPageIds, setOpenPageIds] = useState<Set<number>>(new Set());

  function togglePage(pageId: number) {
    setOpenPageIds((previous) => {
      const next = new Set(previous);

      if (next.has(pageId)) next.delete(pageId);
      else next.add(pageId);

      return next;
    });
  }

  const counts = useMemo(() => {
    return findings.reduce(
      (acc, finding) => {
        const category = normalizeCategory(finding.category);
        const confidence = normalizeConfidence(finding);
        acc.total += 1;
        acc[category] += 1;
        if (confidence === "confirmed" || finding.is_confirmed) acc.confirmed += 1;
        if (confidence === "high") acc.highConfidence += 1;
        if (confidence === "medium") acc.mediumConfidence += 1;
        if (isInformationalObservation(finding)) acc.informational += 1;
        return acc;
      },
      {
        total: 0,
        security: 0,
        seo: 0,
        performance: 0,
        confirmed: 0,
        highConfidence: 0,
        mediumConfidence: 0,
        informational: 0,
      }
    );
  }, [findings]);

  const filteredFindings = useMemo(() => {
    if (filter === "all") return findings;
    return findings.filter(
      (finding) => normalizeCategory(finding.category) === filter
    );
  }, [findings, filter]);

  const findingsByPage = useMemo(() => {
    const map = new Map<number | string, any[]>();

    for (const finding of filteredFindings) {
      const key = finding.scan_page_id ?? "general";
      if (!map.has(key)) map.set(key, []);
      map.get(key)?.push(finding);
    }

    return map;
  }, [filteredFindings]);

  const generalFindings = findingsByPage.get("general") || [];

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-6">
        <StatCard
          label="Risk Score"
          value={scan.risk_score ?? "—"}
          color="text-red-600"
        />
        <StatCard label="Total Findings" value={counts.total} />
        <StatCard
          label="Confirmed Findings"
          value={counts.confirmed}
          color="text-emerald-600"
        />
        <StatCard
          label="High Confidence"
          value={counts.highConfidence}
          color="text-red-600"
        />
        <StatCard
          label="Medium Confidence"
          value={counts.mediumConfidence}
          color="text-amber-600"
        />
        <StatCard
          label="Informational Observations"
          value={counts.informational}
          color="text-blue-600"
        />
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <StatCard label="Pages Scanned" value={pages.length} />
        <StatCard label="Security Findings" value={counts.security} color="text-red-600" />
        <StatCard label="Technologies" value={technologies.length} color="text-emerald-600" />
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap gap-3">
          <FilterButton
            active={filter === "all"}
            label="All"
            count={counts.total}
            onClick={() => setFilter("all")}
          />
          <FilterButton
            active={filter === "security"}
            label="Security"
            count={counts.security}
            onClick={() => setFilter("security")}
          />
          <FilterButton
            active={filter === "seo"}
            label="SEO"
            count={counts.seo}
            onClick={() => setFilter("seo")}
          />
          <FilterButton
            active={filter === "performance"}
            label="Performance"
            count={counts.performance}
            onClick={() => setFilter("performance")}
          />
        </div>
      </div>

      <div className="space-y-4">
        <div>
          <h3 className="text-lg font-semibold text-slate-950">
            Page-by-page results
          </h3>
          <p className="mt-1 text-sm text-slate-500">
            Expand each page to review security, SEO, and performance findings.
          </p>
        </div>

        {pages.length === 0 ? (
          <div className="rounded-2xl border border-slate-200 bg-white p-8 text-center text-sm text-slate-500 shadow-sm">
            No page-level results available.
          </div>
        ) : (
          pages.map((page) => {
            const pageFindings = findingsByPage.get(page.id) || [];

            const securityCount = pageFindings.filter(
              (finding) => normalizeCategory(finding.category) === "security"
            ).length;

            const seoCount = pageFindings.filter(
              (finding) => normalizeCategory(finding.category) === "seo"
            ).length;

            const performanceCount = pageFindings.filter(
              (finding) => normalizeCategory(finding.category) === "performance"
            ).length;

            const isOpen = openPageIds.has(page.id);

            if (filter !== "all" && pageFindings.length === 0) return null;

            return (
              <div
                key={page.id}
                className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm"
              >
                <button
                  type="button"
                  onClick={() => togglePage(page.id)}
                  className="w-full border-b border-slate-200 bg-slate-50 px-6 py-4 text-left transition hover:bg-slate-100"
                >
                  <div className="flex flex-col justify-between gap-3 lg:flex-row lg:items-center">
                    <div className="min-w-0">
                      <p className="max-w-4xl truncate font-mono text-sm font-medium text-slate-950">
                        {page.url}
                      </p>

                      <p className="mt-1 text-xs text-slate-500">
                        Method: {page.method || "GET"} · Status:{" "}
                        {page.status_code || "—"} · Response:{" "}
                        {page.response_time_ms
                          ? `${page.response_time_ms}ms`
                          : "—"}
                      </p>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded-full bg-red-50 px-2.5 py-1 text-xs font-medium text-red-700">
                        Security {securityCount}
                      </span>
                      <span className="rounded-full bg-blue-50 px-2.5 py-1 text-xs font-medium text-blue-700">
                        SEO {seoCount}
                      </span>
                      <span className="rounded-full bg-amber-50 px-2.5 py-1 text-xs font-medium text-amber-700">
                        Performance {performanceCount}
                      </span>
                      <span className="rounded-full bg-slate-200 px-2.5 py-1 text-xs font-medium text-slate-700">
                        {isOpen ? "Hide" : "View"}
                      </span>
                    </div>
                  </div>
                </button>

                {isOpen ? <FindingGroups findings={pageFindings} /> : null}
              </div>
            );
          })
        )}

        {generalFindings.length > 0 ? (
          <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
            <div className="border-b border-slate-200 bg-slate-50 px-6 py-4">
              <h3 className="font-semibold text-slate-950">General findings</h3>
              <p className="mt-1 text-sm text-slate-500">
                Findings not linked to a specific scanned page.
              </p>
            </div>

            <FindingGroups findings={generalFindings} />
          </div>
        ) : null}
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <h3 className="text-lg font-semibold text-slate-950">
          Technologies detected
        </h3>

        <p className="mt-1 text-sm text-slate-500">
          Technologies identified during the scan.
        </p>

        {technologies.length === 0 ? (
          <div className="mt-6 rounded-xl border border-dashed border-slate-200 p-8 text-center text-sm text-slate-500">
            No technologies detected.
          </div>
        ) : (
          <div className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {technologies.map((technology) => (
              <div
                key={technology.id}
                className="rounded-xl border border-slate-200 bg-slate-50 p-4"
              >
                <p className="font-medium text-slate-950">
                  {technology.product_name || "Unknown technology"}
                </p>

                <p className="mt-1 text-sm text-slate-500">
                  {technology.category || "Technology"}
                  {technology.version ? ` · ${technology.version}` : ""}
                </p>

                {technology.vendor ? (
                  <p className="mt-1 text-xs text-slate-400">
                    Vendor: {technology.vendor}
                  </p>
                ) : null}

                {technology.confidence_score !== null &&
                technology.confidence_score !== undefined ? (
                  <p className="mt-1 text-xs text-slate-400">
                    Confidence:{" "}
                    {Math.round(Number(technology.confidence_score) * 100)}%
                  </p>
                ) : null}

                {technology.detection_method ? (
                  <p className="mt-1 text-xs text-slate-400">
                    Method: {technology.detection_method}
                  </p>
                ) : null}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
