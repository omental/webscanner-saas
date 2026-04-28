export type UserRole = "super_admin" | "admin" | "team_member";

export type RetestStatus =
  | "fixed"
  | "still_vulnerable"
  | "new"
  | "existing"
  | "not_retested";

export type User = {
  id: number;
  name: string;
  email: string;
  role: UserRole;
  organization_id: number | null;
  organization_name?: string | null;
  status: "active" | "inactive";
  created_at: string;
  updated_at: string;
};

export type Target = {
  id: number;
  user_id: number;
  organization_id: number | null;
  base_url: string;
  normalized_domain: string;
  created_at: string;
  updated_at: string;
};

export type Scan = {
  id: number;
  user_id: number;
  organization_id: number | null;
  target_id: number;
  scan_type: string;
  scan_profile: string | null;
  status: string;
  progress: number;
  current_page_url: string | null;
  total_pages_found: number;
  total_findings: number;
  risk_score: number | null;
  max_depth: number | null;
  max_pages: number | null;
  timeout_seconds: number | null;
  previous_scan_id: number | null;
  comparison_summary: {
    fixed?: number;
    still_vulnerable?: number;
    new?: number;
    existing?: number;
    not_retested?: number;
  } | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
};

export type ScanDetail = Scan & {
  target: Target | null;
  completed_at: string | null;
  findings: Finding[];
  technologies: DetectedTechnology[];
  pages: ScanPage[];
};

export type ScanComparison = {
  previous_scan_id: number | null;
  current_scan_id: number;
  fixed_findings: Finding[];
  still_vulnerable_findings: Finding[];
  new_findings: Finding[];
  existing_findings: Finding[];
  not_retested_findings: Finding[];
  summary: {
    fixed?: number;
    still_vulnerable?: number;
    new?: number;
    existing?: number;
    not_retested?: number;
  };
};

export type Organization = {
  id: number;
  name: string;
  slug: string;
  package_id: number | null;
  package_name?: string | null;
  status: string;
  subscription_status: "active" | "trial" | "expired" | "suspended";
  subscription_start: string | null;
  subscription_end: string | null;
  trial_ends_at: string | null;
  created_at: string;
  updated_at: string;
};

export type Package = {
  id: number;
  name: string;
  slug: string;
  scan_limit_per_week: number;
  price_monthly: string;
  status: string;
  created_at: string;
  updated_at: string;
};

export type Usage = {
  organization_id: number;
  organization_name: string;
  package_name: string | null;
  subscription_status: "active" | "trial" | "expired" | "suspended";
  trial_ends_at: string | null;
  subscription_end: string | null;
  scan_limit_per_week: number;
  scans_used_this_week: number;
  scans_remaining_this_week: number;
  trial_scan_limit: number;
  trial_scans_used: number;
  trial_scans_remaining: number;
  is_trial_limit_reached: boolean;
  is_blocked: boolean;
  current_invoice_id: number | null;
  current_invoice_status: string | null;
  current_invoice_pdf_url: string | null;
  week_start: string;
  week_end: string;
  status: string;
};

export type Invoice = {
  id: number;
  organization_id: number;
  organization_name: string | null;
  billing_record_id: number;
  package_id: number | null;
  package_name: string | null;
  invoice_number: string;
  amount: string;
  currency: string;
  status: "unpaid" | "paid" | "canceled";
  issued_at: string;
  due_date: string;
  paid_at: string | null;
  pdf_url: string | null;
  created_at: string;
  updated_at: string;
};

export type TrialRegistrationResponse = {
  success: boolean;
  message: string;
  trial_ends_at: string;
  invoice_id: number;
  invoice_pdf_url: string;
};

export type PaymentMethod = {
  id: number;
  name: string;
  slug: string;
  is_active: boolean;
  mode: "test" | "live";
  description: string | null;
  config_json: Record<string, unknown> | null;
  public_key: string | null;
  webhook_url: string | null;
  webhook_enabled: boolean;
  has_secret_key: boolean;
  has_webhook_secret: boolean;
  created_at: string;
  updated_at: string;
};

export type ScanPage = {
  id: number;
  scan_id: number;
  url: string;
  method: string;
  status_code: number | null;
  content_type: string | null;
  response_time_ms: number | null;
  page_title: string | null;
  discovered_from: string | null;
  depth: number;
  created_at: string;
};

export type FindingReference = {
  id: number;
  finding_id: number;
  ref_type: string;
  ref_value: string;
  ref_url: string | null;
  source: string | null;
  created_at: string;
};

export type Finding = {
  id: number;
  scan_id: number;
  scan_page_id: number | null;
  category: string;
  title: string;
  description: string;
  severity: string;
  confidence: string | null;
  confidence_level: string | null;
  confidence_score: number | null;
  evidence_type: string | null;
  verification_steps: unknown | null;
  payload_used: string | null;
  affected_parameter: string | null;
  response_snippet: string | null;
  false_positive_notes: string | null;
  request_url: string | null;
  http_method: string | null;
  tested_parameter: string | null;
  payload: string | null;
  baseline_status_code: number | null;
  attack_status_code: number | null;
  baseline_response_size: number | null;
  attack_response_size: number | null;
  baseline_response_time_ms: number | null;
  attack_response_time_ms: number | null;
  response_diff_summary: string | null;
  deduplication_key: string | null;
  comparison_status: RetestStatus | string | null;
  evidence: string | null;
  remediation: string | null;
  is_confirmed: boolean;
  references: FindingReference[];
  created_at: string;
  updated_at: string;
};

export type ScanFrequency = "weekly" | "monthly" | "custom";
export type ScanProfile =
  | "passive"
  | "quick"
  | "standard"
  | "deep"
  | "aggressive";

export type ScheduledScan = {
  id: number;
  organization_id: number;
  target_id: number;
  created_by_user_id: number;
  scan_profile: string | null;
  frequency: string;
  next_run_at: string;
  last_run_at: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
};

export type DetectedTechnology = {
  id: number;
  scan_id: number;
  scan_page_id: number | null;
  product_name: string;
  category: string;
  version: string | null;
  vendor: string | null;
  confidence_score: number | null;
  detection_method: string | null;
  created_at: string;
};
