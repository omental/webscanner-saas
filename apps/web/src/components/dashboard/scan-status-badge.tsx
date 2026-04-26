import { Badge } from "@/components/ui/badge";

type ScanStatusBadgeProps = {
  status: string;
};

export function ScanStatusBadge({ status }: ScanStatusBadgeProps) {
  const s = status.toLowerCase();

  if (s === "completed") {
    return <Badge variant="success">Completed</Badge>;
  }
  if (s === "failed") {
    return <Badge variant="error">Failed</Badge>;
  }
  if (s === "running") {
    return <Badge variant="info">Running</Badge>;
  }
  if (s === "pending" || s === "queued") {
    return <Badge variant="warning">{status}</Badge>;
  }
  if (s === "cancelled") {
    return <Badge variant="neutral">Cancelled</Badge>;
  }

  return <Badge variant="neutral">{status}</Badge>;
}
