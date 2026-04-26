import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";

import { AppProviders } from "@/components/ui/app-providers";
import "./globals.css";

export const metadata: Metadata = {
  title: "Web Scanner Dashboard",
  description:
    "Starter dashboard shell for the Web Vulnerability Scanner SaaS."
};

export default function RootLayout({
  children
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={GeistSans.className} suppressHydrationWarning>
        <AppProviders>{children}</AppProviders>
      </body>
    </html>
  );
}
