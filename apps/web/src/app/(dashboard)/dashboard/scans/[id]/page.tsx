import { ScanDetailPageClient } from "@/components/dashboard/scan-detail-page-client";

type ScanDetailPageProps = {
  params: Promise<{ id: string }>;
};

export default async function ScanDetailPage({ params }: ScanDetailPageProps) {
  const { id } = await params;

  return <ScanDetailPageClient scanId={Number(id)} />;
}
