import {
  DetectedTechnology,
  Finding,
  Invoice,
  Organization,
  Package,
  PaymentMethod,
  Scan,
  ScanComparison,
  ScanDetail,
  ScanPage,
  ScheduledScan,
  Target,
  TrialRegistrationResponse,
  Usage,
  User
} from "@/lib/types";
import { getSessionUser } from "@/lib/session";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000";

type RequestOptions = RequestInit & {
  path: string;
};

type ApiError = Error & {
  status?: number;
  path?: string;
};

export type LoginUser = Pick<
  User,
  "id" | "email" | "name" | "role" | "status" | "organization_id"
>;

function isLoginUser(payload: unknown): payload is LoginUser {
  if (!payload || typeof payload !== "object") {
    return false;
  }

  const user = payload as Partial<LoginUser>;
  return (
    typeof user.id === "number" &&
    typeof user.email === "string" &&
    typeof user.name === "string" &&
    typeof user.role === "string" &&
    (typeof user.organization_id === "number" || user.organization_id === null) &&
    typeof user.status === "string"
  );
}

async function request<T>({
  path,
  headers,
  body,
  ...init
}: RequestOptions): Promise<T> {
  const sessionUser = getSessionUser();
  const response = await fetch(`${API_BASE_URL}${path}`, {
    cache: "no-store",
    credentials: "include",
    ...init,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(sessionUser ? { "X-Current-User-Id": String(sessionUser.id) } : {}),
      ...headers
    },
    body
  });

  if (!response.ok) {
    let detail = `Request failed with status ${response.status}`;

    try {
      const payload = (await response.json()) as { detail?: unknown };
      if (payload.detail) {
        detail =
          typeof payload.detail === "string"
            ? payload.detail
            : JSON.stringify(payload.detail);
      }
    } catch {
      // Keep the status-based message if the response isn't JSON.
    }

    const error = new Error(detail) as ApiError;
    error.status = response.status;
    error.path = path;
    if (typeof window !== "undefined") {
      console.error(`[api] ${path} failed with status ${response.status}`, {
        status: response.status,
        endpoint: path,
        detail
      });
    }
    throw error;
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}

export function buildApiUrl(path: string) {
  return `${API_BASE_URL}${path}`;
}

export const apiClient = {
  async login(payload: { email: string; password: string }) {
    const user = await request<unknown>({
      path: "/api/v1/auth/login",
      method: "POST",
      body: JSON.stringify(payload)
    });

    if (!isLoginUser(user)) {
      throw new Error("Login response is missing id, email, role, name, or status.");
    }

    return user;
  },
  registerTrial(payload: {
    name: string;
    email: string;
    password: string;
    organization_name: string;
    selected_package_id?: number;
    selected_package_slug?: string;
  }) {
    return request<TrialRegistrationResponse>({
      path: "/api/v1/auth/register",
      method: "POST",
      body: JSON.stringify(payload)
    });
  },
  listUsers() {
    return request<User[]>({ path: "/api/v1/users" });
  },
  createUser(payload: {
    name: string;
    email: string;
    password: string;
    role: string;
    organization_id?: number | null;
    status: string;
  }) {
    return request<User>({
      path: "/api/v1/users",
      method: "POST",
      body: JSON.stringify(payload)
    });
  },
  updateUser(
    userId: number,
    payload: {
      name?: string;
      email?: string;
      password?: string;
      role?: string;
      organization_id?: number | null;
      status?: string;
    }
  ) {
    return request<User>({
      path: `/api/v1/users/${userId}`,
      method: "PATCH",
      body: JSON.stringify(payload)
    });
  },
  deleteUser(userId: number) {
    return request<void>({
      path: `/api/v1/users/${userId}`,
      method: "DELETE"
    });
  },
  listOrganizations() {
    return request<Organization[]>({ path: "/api/v1/organizations" });
  },
  createOrganization(payload: {
    name: string;
    slug: string;
    package_id?: number | null;
    status: string;
  }) {
    return request<Organization>({
      path: "/api/v1/organizations",
      method: "POST",
      body: JSON.stringify(payload)
    });
  },
  assignOrganizationPackage(organizationId: number, packageId: number | null) {
    return request<Organization>({
      path: `/api/v1/organizations/${organizationId}/package`,
      method: "PATCH",
      body: JSON.stringify({ package_id: packageId })
    });
  },
  updateOrganizationSubscription(
    organizationId: number,
    payload: {
      subscription_status: string;
      subscription_start?: string | null;
      subscription_end?: string | null;
      trial_ends_at?: string | null;
    }
  ) {
    return request<Organization>({
      path: `/api/v1/organizations/${organizationId}/subscription`,
      method: "PATCH",
      body: JSON.stringify(payload)
    });
  },
  startOrganizationTrial(organizationId: number, days: number) {
    return request<Organization>({
      path: `/api/v1/organizations/${organizationId}/start-trial`,
      method: "POST",
      body: JSON.stringify({ days })
    });
  },
  listPackages() {
    return request<Package[]>({ path: "/api/v1/packages" });
  },
  updatePackage(
    packageId: number,
    payload: {
      name?: string;
      slug?: string;
      scan_limit_per_week?: number;
      price_monthly?: string;
      status?: string;
    }
  ) {
    return request<Package>({
      path: `/api/v1/packages/${packageId}`,
      method: "PATCH",
      body: JSON.stringify(payload)
    });
  },
  listPaymentMethods() {
    return request<PaymentMethod[]>({ path: "/api/v1/payment-methods" });
  },
  updatePaymentMethod(
    paymentMethodId: number,
    payload: {
      is_active?: boolean;
      mode?: "test" | "live";
      description?: string | null;
      config_json?: Record<string, unknown> | null;
      public_key?: string | null;
      secret_key?: string | null;
      webhook_secret?: string | null;
      webhook_enabled?: boolean;
      clear_secret_key?: boolean;
      clear_webhook_secret?: boolean;
    }
  ) {
    return request<PaymentMethod>({
      path: `/api/v1/payment-methods/${paymentMethodId}`,
      method: "PATCH",
      body: JSON.stringify(payload)
    });
  },
  getMyUsage() {
    return request<Usage>({ path: "/api/v1/usage/me" });
  },
  listOrganizationUsage() {
    return request<Usage[]>({ path: "/api/v1/usage/organizations" });
  },
  listInvoices() {
    return request<Invoice[]>({ path: "/api/v1/invoices" });
  },
  getInvoice(invoiceId: number) {
    return request<Invoice>({ path: `/api/v1/invoices/${invoiceId}` });
  },
  markInvoicePaid(invoiceId: number) {
    return request<Invoice>({
      path: `/api/v1/invoices/${invoiceId}/mark-paid`,
      method: "PATCH"
    });
  },
  generateBillingInvoice(organizationId: number) {
    return request<Invoice>({
      path: `/api/v1/billing/generate/${organizationId}`,
      method: "POST"
    });
  },
  listTargets() {
    return request<Target[]>({ path: "/api/v1/targets" });
  },
  createTarget(payload: {
    user_id: number;
    base_url: string;
  }) {
    return request<Target>({
      path: "/api/v1/targets",
      method: "POST",
      body: JSON.stringify(payload)
    });
  },
  listScans() {
    return request<Scan[]>({ path: "/api/v1/scans" });
  },
  getScan(scanId: number) {
    return request<Scan>({ path: `/api/v1/scans/${scanId}` });
  },
  getScanDetails(scanId: number) {
    return request<ScanDetail>({ path: `/api/v1/scans/${scanId}` });
  },
  createScan(payload: {
    user_id: number;
    target_id: number;
    scan_type: string;
    max_depth?: number | null;
    max_pages?: number | null;
    timeout_seconds?: number | null;
  }) {
    return request<Scan>({
      path: "/api/v1/scans",
      method: "POST",
      body: JSON.stringify(payload)
    });
  },
  cancelScan(scanId: number) {
    return request<Scan>({
      path: `/api/v1/scans/${scanId}/cancel`,
      method: "POST"
    });
  },
  retestScan(scanId: number) {
    return request<Scan>({
      path: `/api/v1/scans/${scanId}/retest`,
      method: "POST"
    });
  },
  getScanComparison(scanId: number) {
    return request<ScanComparison>({
      path: `/api/v1/scans/${scanId}/compare`
    });
  },
  getScanPages(scanId: number) {
    return request<ScanPage[]>({ path: `/api/v1/scans/${scanId}/pages` });
  },
  getScanFindings(scanId: number) {
    return request<Finding[]>({ path: `/api/v1/scans/${scanId}/findings` });
  },
  getScanTechnologies(scanId: number) {
    return request<DetectedTechnology[]>({
      path: `/api/v1/scans/${scanId}/technologies`
    });
  },
  listScheduledScans() {
    return request<ScheduledScan[]>({ path: "/api/v1/scheduled-scans" });
  },
  getScheduledScan(scheduledScanId: number) {
    return request<ScheduledScan>({
      path: `/api/v1/scheduled-scans/${scheduledScanId}`
    });
  },
  createScheduledScan(payload: {
    target_id: number;
    scan_profile: string;
    frequency: string;
    next_run_at: string;
    is_active?: boolean;
  }) {
    return request<ScheduledScan>({
      path: "/api/v1/scheduled-scans",
      method: "POST",
      body: JSON.stringify(payload)
    });
  },
  updateScheduledScan(
    scheduledScanId: number,
    payload: {
      scan_profile?: string;
      frequency?: string;
      next_run_at?: string;
      is_active?: boolean;
    }
  ) {
    return request<ScheduledScan>({
      path: `/api/v1/scheduled-scans/${scheduledScanId}`,
      method: "PATCH",
      body: JSON.stringify(payload)
    });
  },
  disableScheduledScan(scheduledScanId: number) {
    return request<ScheduledScan>({
      path: `/api/v1/scheduled-scans/${scheduledScanId}/disable`,
      method: "POST"
    });
  }
};
