import { Badge } from "@/components/ui/badge";

type SeverityBadgeProps = {
  severity: string;
};

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  const normalized = severity.toLowerCase();
  const tone =
    normalized === "critical" || normalized === "high"
      ? "danger"
      : normalized === "medium"
        ? "warning"
        : normalized === "low"
          ? "info"
          : "neutral";

  return <Badge tone={tone}>{severity}</Badge>;
}

