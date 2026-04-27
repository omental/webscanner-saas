"use client";

import Image from "next/image";
import Link from "next/link";
import {
  AnimatePresence,
  motion,
  useMotionValueEvent,
  useReducedMotion,
  useScroll,
  useTransform,
  type TargetAndTransition,
  type Variants
} from "framer-motion";
import { MouseEvent, ReactNode, useEffect, useState } from "react";
import { apiClient } from "@/lib/api-client";
import { Package } from "@/lib/types";

const easeOut = [0.16, 1, 0.3, 1] as const;
const easeInOut = [0.42, 0, 0.58, 1] as const;

export const fadeUp: Variants = {
  hidden: { opacity: 0, y: 28 },
  show: { opacity: 1, y: 0, transition: { duration: 0.7, ease: easeOut } }
};

export const staggerContainer: Variants = {
  hidden: {},
  show: { transition: { staggerChildren: 0.09, delayChildren: 0.08 } }
};

export const cardHover = {
  y: -6,
  scale: 1.015,
  transition: { duration: 0.24, ease: easeOut }
} satisfies TargetAndTransition;

export const buttonHover = {
  scale: 1.035,
  transition: { duration: 0.22, ease: easeOut }
} satisfies TargetAndTransition;

export const floating = {
  y: [0, -12, 0],
  transition: { duration: 6, repeat: Infinity, ease: easeInOut }
} satisfies TargetAndTransition;

export const glowPulse = {
  opacity: [0.38, 0.72, 0.38],
  scale: [1, 1.07, 1],
  transition: { duration: 4.5, repeat: Infinity, ease: easeInOut }
} satisfies TargetAndTransition;

type AnimatedSectionProps = {
  children: ReactNode;
  className?: string;
  id?: string;
};

export function AnimatedSection({
  children,
  className = "",
  id
}: AnimatedSectionProps) {
  return (
    <motion.section
      id={id}
      variants={fadeUp}
      initial="hidden"
      whileInView="show"
      viewport={{ once: true, margin: "-120px" }}
      className={className}
    >
      {children}
    </motion.section>
  );
}

type GradientButtonProps = {
  children: ReactNode;
  href: string;
  variant?: "primary" | "secondary";
};

export function GradientButton({
  children,
  href,
  variant = "primary"
}: GradientButtonProps) {
  const primary =
    "border-transparent bg-[linear-gradient(110deg,#60a5fa,#a855f7,#22d3ee,#60a5fa)] bg-[length:220%_100%] text-white shadow-lg shadow-cyan-500/20";
  const secondary =
    "border-white/15 bg-white/5 text-white backdrop-blur-xl hover:bg-white/10";

  return (
    <motion.div whileHover={buttonHover} whileTap={{ scale: 0.98 }} className="group">
      <Link
        href={href}
        className={`relative inline-flex items-center justify-center overflow-hidden rounded-full border px-6 py-3 text-sm font-semibold transition duration-300 ${variant === "primary" ? primary : secondary}`}
      >
        <motion.span
          aria-hidden
          className="absolute inset-0 opacity-0 blur-xl transition-opacity duration-300 group-hover:opacity-70"
          style={{
            background:
              "linear-gradient(110deg,rgba(96,165,250,.32),rgba(168,85,247,.32),rgba(34,211,238,.32))"
          }}
        />
        <motion.span
          aria-hidden
          animate={{ x: ["-130%", "130%"] }}
          transition={{ duration: 2.4, repeat: Infinity, ease: "linear" }}
          className="absolute inset-y-0 w-16 -skew-x-12 bg-white/20 opacity-0 group-hover:opacity-100"
        />
        <motion.span
          aria-hidden
          animate={variant === "primary" ? { backgroundPosition: ["0% 50%", "100% 50%"] } : {}}
          transition={{ duration: 3, repeat: Infinity, repeatType: "reverse" }}
          className="absolute inset-0"
        />
        <span className="relative">{children}</span>
        <motion.span
          aria-hidden
          className="relative ml-2"
          initial={{ x: 0 }}
          whileHover={{ x: 4 }}
        >
          →
        </motion.span>
      </Link>
    </motion.div>
  );
}

type GlowCardProps = {
  children: ReactNode;
  className?: string;
};

export function GlowCard({ children, className = "" }: GlowCardProps) {
  return (
    <motion.div
      whileHover={cardHover}
      className={`group relative overflow-hidden rounded-lg border border-white/10 bg-white/[0.055] p-px shadow-xl shadow-black/25 backdrop-blur-xl transition-shadow duration-300 hover:shadow-cyan-500/15 ${className}`.trim()}
    >
      <motion.div
        aria-hidden
        className="absolute inset-0 opacity-0 transition-opacity duration-500 group-hover:opacity-100"
        style={{
          background:
            "radial-gradient(180px circle at var(--mx,50%) var(--my,0%),rgba(34,211,238,.34),transparent 42%)"
        }}
      />
      <div
        onMouseMove={(event) => {
          const rect = event.currentTarget.getBoundingClientRect();
          event.currentTarget.parentElement?.style.setProperty(
            "--mx",
            `${event.clientX - rect.left}px`
          );
          event.currentTarget.parentElement?.style.setProperty(
            "--my",
            `${event.clientY - rect.top}px`
          );
        }}
        className="relative h-full rounded-lg bg-[#0b0f19]/88 p-6"
      >
        {children}
      </div>
    </motion.div>
  );
}

type FeatureCardProps = {
  title: string;
  description: string;
  index: number;
};

export function FeatureCard({ title, description, index }: FeatureCardProps) {
  return (
    <GlowCard>
      <motion.div
        whileHover={{ rotate: 7, scale: 1.08 }}
        animate={{ boxShadow: ["0 0 0 rgba(34,211,238,0)", "0 0 28px rgba(34,211,238,.22)", "0 0 0 rgba(34,211,238,0)"] }}
        transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
        className="mb-5 flex h-12 w-12 items-center justify-center rounded-lg border border-cyan-300/20 bg-cyan-300/10"
      >
        <span className="h-5 w-5 rounded-full border border-cyan-200/80 shadow-[0_0_22px_rgba(34,211,238,0.55)]" />
      </motion.div>
      <p className="text-xs uppercase tracking-[0.3em] text-cyan-200">
        Feature {index + 1}
      </p>
      <h3 className="mt-3 text-xl font-semibold text-white">{title}</h3>
      <p className="mt-3 text-sm leading-7 text-slate-300">{description}</p>
    </GlowCard>
  );
}

type PricingCardProps = {
  name: string;
  price: string;
  scans: string;
  highlighted?: boolean;
};

const includedItems = [
  "Weekly scan allowance",
  "Multi-tenant dashboard",
  "PDF reports and billing records"
];

export function PricingCard({
  name,
  price,
  scans,
  highlighted = false
}: PricingCardProps) {
  const reducedMotion = useReducedMotion();
  return (
    <motion.div
      whileHover={{ y: -8, scale: 1.02 }}
      transition={{ duration: 0.25 }}
      className={`relative rounded-lg p-px ${highlighted ? "bg-[linear-gradient(135deg,#60a5fa,#a855f7,#22d3ee,#60a5fa)] bg-[length:240%_240%]" : "bg-white/10"}`}
      animate={
        highlighted && !reducedMotion
          ? { backgroundPosition: ["0% 50%", "100% 50%", "0% 50%"] }
          : undefined
      }
      style={{
        backgroundImage: highlighted
          ? "linear-gradient(135deg,#60a5fa,#a855f7,#22d3ee,#60a5fa)"
          : undefined
      }}
    >
      <div className="relative h-full overflow-hidden rounded-lg bg-[#0b0f19]/95 p-7 backdrop-blur-xl">
        {highlighted ? (
          <span className="rounded-full bg-cyan-300/15 px-3 py-1 text-xs font-semibold text-cyan-100">
            Most popular
          </span>
        ) : null}
        <h3 className="mt-5 text-2xl font-semibold text-white">{name}</h3>
        <p className="mt-4 text-4xl font-semibold text-white">{price}</p>
        <p className="mt-3 text-sm text-slate-300">{scans}</p>
        <motion.div
          variants={staggerContainer}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true }}
          className="mt-6 space-y-3 text-sm text-slate-300"
        >
          {includedItems.map((item) => (
            <motion.p key={item} variants={fadeUp} className="flex items-center gap-3">
              <motion.span
                className="flex h-5 w-5 items-center justify-center rounded-full bg-cyan-300/15 text-xs text-cyan-100"
                initial={{ scale: 0.6, opacity: 0 }}
                whileInView={{ scale: 1, opacity: 1 }}
                viewport={{ once: true }}
              >
                ✓
              </motion.span>
              {item}
            </motion.p>
          ))}
        </motion.div>
        <div className="mt-7">
          <GradientButton href="/register" variant={highlighted ? "primary" : "secondary"}>
            Start trial
          </GradientButton>
        </div>
      </div>
    </motion.div>
  );
}

const features = [
  ["Tenant-ready scanning", "Keep organizations, users, targets, and scan history cleanly separated."],
  ["Trial-aware limits", "Free trials get one focused scan before package limits begin."],
  ["Actionable findings", "Surface pages, technologies, references, severity, and remediation in one place."],
  ["Admin workflows", "Manage users, subscriptions, packages, and billing from a single control panel."],
  ["PDF deliverables", "Create readable scan reports and invoice PDFs without leaving the app."],
  ["Billing-ready foundation", "Prepare payment settings now while keeping checkout safely disabled."]
];

const faqs = [
  ["Do I need a credit card?", "No. The trial registration flow starts a 14-day trial without card details."],
  ["Is payment processing live?", "No. Billing records and invoices are generated, but checkout and charging are not connected yet."],
  ["How many trial scans are included?", "Each trial organization can create one scan total during the trial period."],
  ["Can admins download invoices?", "Admins can download invoices for their own organization. Super admins can access every invoice."]
];

const navItems = [
  ["Problem", "#problem"],
  ["Features", "#features"],
  ["How it works", "#how-it-works"],
  ["Pricing", "#pricing"],
  ["FAQ", "#faq"]
];

function LandingHeader() {
  const { scrollY } = useScroll();
  const [scrolled, setScrolled] = useState(false);

  useMotionValueEvent(scrollY, "change", (value) => {
    setScrolled(value > 20);
  });

  return (
    <motion.header
      animate={{
        y: scrolled ? 10 : 0,
      }}
      className="fixed inset-x-0 top-0 z-50 px-4 py-4 lg:px-8"
    >
      <motion.nav
        animate={{
          backgroundColor: scrolled
            ? "rgba(8,13,24,0.72)"
            : "rgba(8,13,24,0.35)",
          borderColor: scrolled
            ? "rgba(255,255,255,0.14)"
            : "rgba(255,255,255,0.08)",
          boxShadow: scrolled
            ? "0 24px 80px rgba(0,0,0,0.28)"
            : "0 0 0 rgba(0,0,0,0)",
        }}
        className="mx-auto flex max-w-7xl items-center justify-between rounded-full border px-5 py-3 backdrop-blur-2xl"
      >
        <Link href="/" className="flex items-center gap-3">
          <span className="flex h-8 w-8 items-center justify-center rounded-full bg-white text-xs font-black text-[#080d18]">
            W
          </span>
          <span className="text-sm font-semibold text-white">WebScanner</span>
        </Link>

        <div className="hidden items-center gap-1 rounded-full border border-white/10 bg-white/[0.04] p-1 md:flex">
          {navItems.map(([label, href]) => (
            <Link
              key={href}
              href={href}
              className="rounded-full px-4 py-2 text-xs font-medium text-slate-300 transition hover:bg-white/10 hover:text-white"
            >
              {label}
            </Link>
          ))}
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/login"
            className="hidden text-sm font-medium text-slate-300 hover:text-white sm:inline"
          >
            Login
          </Link>

          <motion.div whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.98 }}>
            <Link
              href="/register"
              className="inline-flex items-center rounded-full bg-white px-5 py-2.5 text-sm font-semibold text-[#080d18] shadow-xl shadow-cyan-500/20 transition hover:bg-cyan-100"
            >
              Start trial
              <span className="ml-2">→</span>
            </Link>
          </motion.div>
        </div>
      </motion.nav>
    </motion.header>
  );
}

function HeroSection() {
  const reducedMotion = useReducedMotion();
  const { scrollY } = useScroll();

  const heroY = useTransform(scrollY, [0, 700], [0, reducedMotion ? 0 : 120]);
  const imageY = useTransform(scrollY, [0, 700], [0, reducedMotion ? 0 : -80]);
  const glowY = useTransform(scrollY, [0, 700], [0, reducedMotion ? 0 : 180]);

  return (
    <section className="relative min-h-screen overflow-hidden bg-[#080d18] px-4 pt-32 text-white sm:px-6 lg:px-8">
      <motion.div
        aria-hidden
        style={{ y: glowY }}
        className="absolute left-1/2 top-[-220px] h-[520px] w-[920px] -translate-x-1/2 rounded-full bg-[radial-gradient(circle,rgba(96,165,250,0.36),rgba(168,85,247,0.24),transparent_68%)] blur-3xl"
      />

      <motion.div
        aria-hidden
        animate={
          reducedMotion
            ? undefined
            : {
                backgroundPosition: ["0% 50%", "100% 50%", "0% 50%"],
              }
        }
        transition={{ duration: 18, repeat: Infinity, ease: "linear" }}
        className="absolute inset-0 bg-[linear-gradient(115deg,rgba(34,211,238,0.12),transparent_24%,rgba(168,85,247,0.14)_48%,transparent_72%,rgba(96,165,250,0.12))] bg-[length:220%_220%]"
      />

      <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.035)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.035)_1px,transparent_1px)] bg-[size:72px_72px] [mask-image:radial-gradient(circle_at_top,black,transparent_72%)]" />

      <motion.div
        style={{ y: heroY }}
        className="relative mx-auto max-w-7xl"
      >
        <div className="mx-auto max-w-5xl text-center">
          <motion.div
            initial={{ opacity: 0, y: 18, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ duration: 0.65, ease: easeOut }}
            className="mx-auto inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.06] px-4 py-2 text-xs font-medium text-cyan-100 shadow-2xl shadow-cyan-500/10 backdrop-blur-xl"
          >
            <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_20px_rgba(52,211,153,0.8)]" />
            Multi-tenant vulnerability scanner SaaS
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 26 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.78, delay: 0.08, ease: easeOut }}
            className="mt-8 text-5xl font-semibold leading-[0.95] tracking-[-0.06em] text-white sm:text-7xl lg:text-[104px]"
          >
            Scan faster.
            <br />
            Report cleaner.
            <br />
            Bill smarter.
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 22 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.18, ease: easeOut }}
            className="mx-auto mt-7 max-w-2xl text-base leading-8 text-slate-300 sm:text-lg"
          >
            A premium security scanner platform with targets, scans, reports,
            organizations, trial limits, invoices, and SaaS billing workflows
            in one clean operating system.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 22 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.28, ease: easeOut }}
            className="mt-9 flex flex-wrap justify-center gap-4"
          >
            <GradientButton href="/register">Start free trial</GradientButton>
            <GradientButton href="/login" variant="secondary">
              Open dashboard
            </GradientButton>
          </motion.div>
        </div>

        <motion.div
          style={{ y: imageY }}
          initial={{ opacity: 0, y: 60, scale: 0.96 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ duration: 1, delay: 0.35, ease: easeOut }}
          className="relative mx-auto mt-20 max-w-6xl"
        >
          <div className="absolute -inset-8 rounded-[2rem] bg-[radial-gradient(circle_at_50%_0%,rgba(34,211,238,0.28),rgba(168,85,247,0.18),transparent_62%)] blur-2xl" />

          <motion.div
            whileHover={
              reducedMotion
                ? undefined
                : {
                    rotateX: 2,
                    rotateY: -2,
                    scale: 1.01,
                  }
            }
            transition={{ duration: 0.3 }}
            className="relative overflow-hidden rounded-[2rem] border border-white/12 bg-white/[0.06] p-3 shadow-2xl shadow-black/50 backdrop-blur-2xl"
          >
            <div className="relative min-h-[320px] overflow-hidden rounded-[1.4rem] border border-white/10 bg-[#0b0f19] sm:min-h-[520px]">
              <LandingImage
                src="/landing/dashboard-previews.png"
                alt="WebScanner dashboard preview"
                priority
              />

              <div className="absolute inset-0 bg-[linear-gradient(to_bottom,transparent,rgba(8,13,24,0.45))]" />

              <FloatingCard className="left-5 top-5 sm:left-8 sm:top-8" delay={0.2}>
                Scan completed
              </FloatingCard>

              <FloatingCard className="right-5 top-24 sm:right-10 sm:top-28" delay={0.8}>
                128 findings
              </FloatingCard>

              <FloatingCard className="bottom-5 left-6 sm:bottom-8 sm:left-10" delay={1.2}>
                PDF report ready
              </FloatingCard>
            </div>
          </motion.div>
        </motion.div>
      </motion.div>
    </section>
  );
}

function TrustBar() {
  const logos = [
    "SECURITY OPS",
    "FASTAPI",
    "NEXT.JS",
    "POSTGRES",
    "OPENROUTER",
    "PDF REPORTS",
    "BILLING",
  ];

  return (
    <div className="relative overflow-hidden border-y border-white/10 bg-[#080d18] py-5">
      <div className="pointer-events-none absolute inset-y-0 left-0 z-10 w-32 bg-gradient-to-r from-[#080d18] to-transparent" />
      <div className="pointer-events-none absolute inset-y-0 right-0 z-10 w-32 bg-gradient-to-l from-[#080d18] to-transparent" />

      <div className="flex w-max gap-4 px-4 [animation:landing-marquee_28s_linear_infinite]">
        {[...logos, ...logos, ...logos].map((logo, index) => (
          <div
            key={`${logo}-${index}`}
            className="rounded-full border border-white/10 bg-white/[0.035] px-6 py-2 text-xs font-semibold uppercase tracking-[0.25em] text-slate-400"
          >
            {logo}
          </div>
        ))}
      </div>
    </div>
  );
}
function LandingImage({
  src,
  alt,
  priority = false,
  className = ""
}: {
  src: string;
  alt: string;
  priority?: boolean;
  className?: string;
}) {
  return (
    <Image
      src={src}
      alt={alt}
      fill
      priority={priority}
      sizes="(min-width: 1024px) 50vw, 100vw"
      className={`object-cover ${className}`.trim()}
    />
  );
}

function FloatingCard({
  className,
  children,
  delay = 0
}: {
  className: string;
  children: ReactNode;
  delay?: number;
}) {
  const reducedMotion = useReducedMotion();
  return (
    <motion.div
      animate={reducedMotion ? undefined : { y: [0, -14, 0], opacity: [0.86, 1, 0.86] }}
      transition={{ duration: 6, delay, repeat: Infinity, ease: "easeInOut" }}
      className={`absolute rounded-lg border border-white/10 bg-white/10 p-4 text-sm text-slate-100 shadow-2xl shadow-cyan-950/30 backdrop-blur-xl ${className}`}
    >
      {children}
    </motion.div>
  );
}
function ProblemSection() {
  const reducedMotion = useReducedMotion();

  const painPoints = [
    "Scans scattered across clients",
    "No clean usage visibility",
    "Reports buried in raw findings",
    "Billing disconnected from activity",
  ];

  return (
    <AnimatedSection
      id="problem"
      className="relative overflow-hidden bg-[#080d18] px-4 py-28 sm:px-6 lg:px-8"
    >
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_20%,rgba(96,165,250,0.12),transparent_34%),radial-gradient(circle_at_80%_70%,rgba(168,85,247,0.12),transparent_36%)]" />

      <div className="relative mx-auto grid max-w-7xl gap-12 lg:grid-cols-[0.9fr_1.1fr] lg:items-center">
        <motion.div
          variants={staggerContainer}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, margin: "-120px" }}
        >
          <motion.p
            variants={fadeUp}
            className="text-sm uppercase tracking-[0.38em] text-cyan-200"
          >
            The Problem
          </motion.p>

          <motion.h2
            variants={fadeUp}
            className="mt-6 max-w-3xl text-4xl font-semibold leading-tight tracking-[-0.04em] text-white sm:text-5xl lg:text-6xl"
          >
            Security work moves fast. Scanner operations usually don’t.
          </motion.h2>

          <motion.p
            variants={fadeUp}
            className="mt-6 max-w-2xl text-base leading-8 text-slate-300 sm:text-lg"
          >
            Teams need a cleaner way to move from target setup to scan execution,
            finding review, PDF reporting, tenant usage, and billing — without
            stitching together five separate tools.
          </motion.p>

          <motion.div variants={fadeUp} className="mt-8 grid gap-3 sm:grid-cols-2">
            {painPoints.map((item) => (
              <div
                key={item}
                className="rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm font-medium text-slate-200 backdrop-blur-xl"
              >
                <span className="mr-2 text-cyan-300">✦</span>
                {item}
              </div>
            ))}
          </motion.div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 42, scale: 0.96 }}
          whileInView={{ opacity: 1, y: 0, scale: 1 }}
          viewport={{ once: true, margin: "-120px" }}
          transition={{ duration: 0.8, ease: easeOut }}
          className="relative"
        >
          <motion.div
            animate={
              reducedMotion
                ? undefined
                : {
                    rotate: [0, 1.2, -1.2, 0],
                    y: [0, -12, 0],
                  }
            }
            transition={{ duration: 7, repeat: Infinity, ease: "easeInOut" }}
            className="relative overflow-hidden rounded-[2rem] border border-white/10 bg-white/[0.055] p-3 shadow-2xl shadow-cyan-500/10 backdrop-blur-xl"
          >
            <div className="relative min-h-[440px] overflow-hidden rounded-[1.4rem] bg-[#0b0f19]">
              <LandingImage
                src="/landing/problem-section.png"
                alt="Security operations command center"
              />
              <div className="absolute inset-0 bg-[linear-gradient(to_top,rgba(8,13,24,0.72),transparent_55%)]" />

              <div className="absolute bottom-5 left-5 right-5 grid gap-3 sm:grid-cols-2">
                <div className="rounded-2xl border border-white/10 bg-black/30 p-4 backdrop-blur-xl">
                  <p className="text-xs uppercase tracking-[0.25em] text-slate-400">
                    Signal
                  </p>
                  <p className="mt-2 text-2xl font-semibold text-white">1,616</p>
                  <p className="mt-1 text-xs text-slate-300">Findings indexed</p>
                </div>

                <div className="rounded-2xl border border-white/10 bg-black/30 p-4 backdrop-blur-xl">
                  <p className="text-xs uppercase tracking-[0.25em] text-slate-400">
                    Output
                  </p>
                  <p className="mt-2 text-2xl font-semibold text-white">PDF</p>
                  <p className="mt-1 text-xs text-slate-300">Reports generated</p>
                </div>
              </div>
            </div>
          </motion.div>
        </motion.div>
      </div>
    </AnimatedSection>
  );
}

function FeaturesGrid() {
  const featureBlocks = [
    {
      title: "Tenant-aware workspaces",
      description:
        "Keep organizations, users, targets, scans, invoices, and package limits separated cleanly.",
      size: "lg:col-span-2",
    },
    {
      title: "Real-time scan flow",
      description:
        "Send users to the scan detail page instantly and stream progress through polling updates.",
      size: "",
    },
    {
      title: "AI-assisted reports",
      description:
        "Generate cleaner security reports with previous report history and PDF download support.",
      size: "",
    },
    {
      title: "Subscription control",
      description:
        "Bronze, Silver, and Gold packages with scan quotas, trial rules, and billing records.",
      size: "lg:col-span-2",
    },
    {
      title: "Admin-ready analytics",
      description:
        "Super admins get platform charts, package adoption, usage limits, and revenue visibility.",
      size: "lg:col-span-3",
    },
  ];

  return (
    <AnimatedSection
      id="features"
      className="relative overflow-hidden bg-[#080d18] px-4 py-28 sm:px-6 lg:px-8"
    >
      <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.025)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.025)_1px,transparent_1px)] bg-[size:80px_80px] [mask-image:radial-gradient(circle_at_center,black,transparent_72%)]" />

      <div className="relative mx-auto max-w-7xl">
        <div className="grid gap-10 lg:grid-cols-[0.82fr_1.18fr] lg:items-end">
          <div>
            <p className="text-sm uppercase tracking-[0.38em] text-cyan-200">
              Features
            </p>
            <h2 className="mt-6 text-4xl font-semibold leading-tight tracking-[-0.04em] text-white sm:text-5xl lg:text-6xl">
              Built like a SaaS product, not a scanner script.
            </h2>
          </div>

          <p className="max-w-2xl text-base leading-8 text-slate-300 sm:text-lg">
            The platform connects scanning, reporting, users, organizations,
            package limits, invoices, and AI-generated reports into one animated
            operational workspace.
          </p>
        </div>

        <motion.div
          variants={staggerContainer}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, margin: "-120px" }}
          className="mt-14 grid gap-5 lg:grid-cols-3"
        >
          {featureBlocks.map((feature, index) => (
            <motion.div
              key={feature.title}
              variants={fadeUp}
              whileHover={{
                y: -8,
                scale: 1.01,
                transition: { duration: 0.25, ease: easeOut },
              }}
              className={`group relative min-h-[260px] overflow-hidden rounded-[1.75rem] border border-white/10 bg-white/[0.045] p-6 shadow-xl shadow-black/20 backdrop-blur-xl ${feature.size}`}
            >
              <div className="absolute inset-0 opacity-0 transition duration-500 group-hover:opacity-100">
                <div className="absolute -right-20 -top-20 h-64 w-64 rounded-full bg-cyan-400/20 blur-3xl" />
                <div className="absolute -bottom-20 -left-20 h-64 w-64 rounded-full bg-purple-500/20 blur-3xl" />
              </div>

              <div className="relative">
                <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-white/10 bg-white/10 text-sm font-semibold text-cyan-100">
                  {String(index + 1).padStart(2, "0")}
                </div>

                <h3 className="mt-8 max-w-xl text-2xl font-semibold tracking-[-0.03em] text-white">
                  {feature.title}
                </h3>

                <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-300">
                  {feature.description}
                </p>
              </div>

              <motion.div
                aria-hidden
                className="absolute bottom-5 right-5 h-20 w-20 rounded-full border border-white/10"
                animate={{
                  scale: [1, 1.12, 1],
                  opacity: [0.18, 0.45, 0.18],
                }}
                transition={{ duration: 4 + index * 0.35, repeat: Infinity }}
              />
            </motion.div>
          ))}
        </motion.div>
      </div>
    </AnimatedSection>
  );
}

function HowItWorks() {
  const steps = [
    {
      title: "Create workspace",
      description:
        "Register a trial organization, invite users, and prepare the first scan environment.",
    },
    {
      title: "Add targets",
      description:
        "Store domains, normalize targets, and keep scan history attached to the right tenant.",
    },
    {
      title: "Run scans",
      description:
        "Launch quick or full scans with progress tracking, crawled pages, technologies, and findings.",
    },
    {
      title: "Report and bill",
      description:
        "Generate AI-assisted reports, download PDFs, manage package limits, and issue invoices.",
    },
  ];

  return (
    <AnimatedSection
      id="how-it-works"
      className="relative overflow-hidden bg-[#080d18] px-4 py-28 sm:px-6 lg:px-8"
    >
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_0%,rgba(34,211,238,0.14),transparent_38%),radial-gradient(circle_at_90%_75%,rgba(168,85,247,0.12),transparent_32%)]" />

      <div className="relative mx-auto max-w-7xl">
        <div className="mx-auto max-w-4xl text-center">
          <p className="text-sm uppercase tracking-[0.38em] text-cyan-200">
            How it works
          </p>
          <h2 className="mt-6 text-4xl font-semibold leading-tight tracking-[-0.04em] text-white sm:text-5xl lg:text-6xl">
            From trial signup to operational security workflow.
          </h2>
          <p className="mx-auto mt-6 max-w-2xl text-base leading-8 text-slate-300 sm:text-lg">
            The scanner experience is designed as one smooth path: workspace,
            targets, scans, reports, limits, and billing.
          </p>
        </div>

        <div className="relative mt-20">
          <motion.div
            initial={{ scaleX: 0 }}
            whileInView={{ scaleX: 1 }}
            viewport={{ once: true, margin: "-120px" }}
            transition={{ duration: 1.1, ease: easeOut }}
            className="absolute left-0 top-[42px] hidden h-px w-full origin-left bg-[linear-gradient(90deg,transparent,#22d3ee,#a855f7,#60a5fa,transparent)] lg:block"
          />

          <motion.div
            variants={staggerContainer}
            initial="hidden"
            whileInView="show"
            viewport={{ once: true, margin: "-120px" }}
            className="grid gap-5 lg:grid-cols-4"
          >
            {steps.map((step, index) => (
              <motion.div
                key={step.title}
                variants={fadeUp}
                whileHover={{
                  y: -8,
                  transition: { duration: 0.25, ease: easeOut },
                }}
                className="group relative rounded-[1.75rem] border border-white/10 bg-white/[0.045] p-6 shadow-xl shadow-black/20 backdrop-blur-xl"
              >
                <div className="absolute inset-0 rounded-[1.75rem] opacity-0 transition duration-500 group-hover:opacity-100">
                  <div className="absolute inset-x-8 top-0 h-px bg-[linear-gradient(90deg,transparent,#22d3ee,transparent)]" />
                  <div className="absolute -top-24 left-1/2 h-40 w-40 -translate-x-1/2 rounded-full bg-cyan-400/20 blur-3xl" />
                </div>

                <div className="relative">
                  <motion.div
                    initial={{ scale: 0.75, opacity: 0 }}
                    whileInView={{ scale: 1, opacity: 1 }}
                    viewport={{ once: true }}
                    transition={{ delay: index * 0.08, duration: 0.35 }}
                    className="flex h-14 w-14 items-center justify-center rounded-2xl border border-white/10 bg-white text-sm font-black text-[#080d18] shadow-lg shadow-cyan-500/10"
                  >
                    {index + 1}
                  </motion.div>

                  <h3 className="mt-8 text-2xl font-semibold tracking-[-0.03em] text-white">
                    {step.title}
                  </h3>

                  <p className="mt-4 text-sm leading-7 text-slate-300">
                    {step.description}
                  </p>
                </div>
              </motion.div>
            ))}
          </motion.div>
        </div>

        <motion.div
          initial={{ opacity: 0, y: 50, scale: 0.96 }}
          whileInView={{ opacity: 1, y: 0, scale: 1 }}
          viewport={{ once: true, margin: "-120px" }}
          transition={{ duration: 0.8, ease: easeOut }}
          className="relative mt-16 overflow-hidden rounded-[2rem] border border-white/10 bg-white/[0.045] p-3 shadow-2xl shadow-purple-500/10 backdrop-blur-xl"
        >
          <div className="relative min-h-[340px] overflow-hidden rounded-[1.4rem] bg-[#0b0f19]">
            <LandingImage
              src="/landing/how-it-works.png"
              alt="Workflow automation visual"
            />
            <div className="absolute inset-0 bg-[linear-gradient(90deg,rgba(8,13,24,0.75),transparent_55%,rgba(8,13,24,0.42))]" />

            <div className="absolute bottom-6 left-6 right-6 grid gap-4 md:grid-cols-3">
              {["Trial created", "Target added", "Invoice prepared"].map(
                (item, index) => (
                  <motion.div
                    key={item}
                    animate={{
                      y: [0, -8, 0],
                      opacity: [0.82, 1, 0.82],
                    }}
                    transition={{
                      duration: 4.5,
                      repeat: Infinity,
                      delay: index * 0.45,
                    }}
                    className="rounded-2xl border border-white/10 bg-black/30 p-4 backdrop-blur-xl"
                  >
                    <p className="text-xs uppercase tracking-[0.24em] text-cyan-200">
                      Step {index + 1}
                    </p>
                    <p className="mt-2 text-sm font-semibold text-white">
                      {item}
                    </p>
                  </motion.div>
                )
              )}
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatedSection>
  );
}

function PricingSection() {
  const [packages, setPackages] = useState<Package[]>([]);

  useEffect(() => {
    void apiClient
      .listPackages()
      .then(setPackages)
      .catch(() => setPackages([]));
  }, []);

  const visiblePackages =
    packages.length > 0
      ? packages.filter((item) => item.status === "active")
      : [
          {
            id: 1,
            name: "Bronze",
            price_monthly: "9.99",
            scan_limit_per_week: 1,
          },
          {
            id: 2,
            name: "Silver",
            price_monthly: "25.00",
            scan_limit_per_week: 10,
          },
          {
            id: 3,
            name: "Gold",
            price_monthly: "100.00",
            scan_limit_per_week: 100,
          },
        ];

  return (
    <AnimatedSection
      id="pricing"
      className="relative overflow-hidden bg-[#080d18] px-4 py-28 sm:px-6 lg:px-8"
    >
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_20%,rgba(96,165,250,0.18),transparent_34%),radial-gradient(circle_at_20%_80%,rgba(34,211,238,0.1),transparent_28%),radial-gradient(circle_at_80%_80%,rgba(168,85,247,0.14),transparent_32%)]" />

      <div className="relative mx-auto max-w-7xl">
        <div className="mx-auto max-w-4xl text-center">
          <p className="text-sm uppercase tracking-[0.38em] text-cyan-200">
            Pricing
          </p>
          <h2 className="mt-6 text-4xl font-semibold leading-tight tracking-[-0.04em] text-white sm:text-5xl lg:text-6xl">
            Simple packages for scanning teams.
          </h2>
          <p className="mx-auto mt-6 max-w-2xl text-base leading-8 text-slate-300 sm:text-lg">
            Start with a trial, then move into weekly scan allowances with
            admin billing and invoice records built in.
          </p>
        </div>

        <motion.div
          variants={staggerContainer}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, margin: "-120px" }}
          className="relative mt-16 grid gap-6 lg:grid-cols-3"
        >
          {visiblePackages.map((item, index) => {
            const highlighted =
              item.name.toLowerCase().includes("silver") || index === 1;

            return (
              <motion.div
                key={item.id}
                variants={fadeUp}
                whileHover={{
                  y: -10,
                  scale: highlighted ? 1.025 : 1.015,
                  transition: { duration: 0.25, ease: easeOut },
                }}
                className={[
                  "relative rounded-[2rem] p-px",
                  highlighted
                    ? "bg-[linear-gradient(135deg,#60a5fa,#a855f7,#22d3ee,#60a5fa)] bg-[length:220%_220%]"
                    : "bg-white/10",
                ].join(" ")}
              >
                <motion.div
                  animate={
                    highlighted
                      ? {
                          backgroundPosition: [
                            "0% 50%",
                            "100% 50%",
                            "0% 50%",
                          ],
                        }
                      : undefined
                  }
                  transition={{
                    duration: 7,
                    repeat: Infinity,
                    ease: "linear",
                  }}
                  className={[
                    "relative h-full overflow-hidden rounded-[2rem] border border-white/10 bg-[#0b0f19]/95 p-7 shadow-2xl shadow-black/20 backdrop-blur-xl",
                    highlighted ? "shadow-cyan-500/20" : "",
                  ].join(" ")}
                >
                  {highlighted ? (
                    <span className="inline-flex rounded-full bg-white px-3 py-1 text-xs font-bold text-[#080d18]">
                      Most popular
                    </span>
                  ) : null}

                  <div className="mt-7">
                    <h3 className="text-2xl font-semibold text-white">
                      {item.name}
                    </h3>

                    <div className="mt-5 flex items-end gap-2">
                      <p className="text-5xl font-semibold tracking-[-0.05em] text-white">
                        ${item.price_monthly}
                      </p>
                      <p className="pb-2 text-sm text-slate-400">/ month</p>
                    </div>

                    <p className="mt-4 text-sm text-slate-300">
                      {item.scan_limit_per_week} scans per week
                    </p>
                  </div>

                  <div className="mt-8 space-y-3">
                    {includedItems.map((included) => (
                      <div
                        key={included}
                        className="flex items-center gap-3 text-sm text-slate-300"
                      >
                        <span className="flex h-5 w-5 items-center justify-center rounded-full bg-cyan-300/15 text-xs text-cyan-100">
                          ✓
                        </span>
                        {included}
                      </div>
                    ))}
                  </div>

                  <div className="mt-8">
                    <GradientButton
                      href="/register"
                      variant={highlighted ? "primary" : "secondary"}
                    >
                      Start trial
                    </GradientButton>
                  </div>

                  <motion.div
                    aria-hidden
                    animate={{
                      opacity: highlighted ? [0.22, 0.45, 0.22] : [0.08, 0.18, 0.08],
                      scale: [1, 1.12, 1],
                    }}
                    transition={{ duration: 5, repeat: Infinity }}
                    className="absolute -right-24 -top-24 h-56 w-56 rounded-full bg-cyan-400/20 blur-3xl"
                  />
                </motion.div>
              </motion.div>
            );
          })}
        </motion.div>
      </div>
    </AnimatedSection>
  );
}

function DashboardPreview() {
  const reducedMotion = useReducedMotion();
  const { scrollYProgress } = useScroll();

  const y = useTransform(
    scrollYProgress,
    [0.45, 0.9],
    [reducedMotion ? 0 : 80, reducedMotion ? 0 : -80]
  );

  const [tilt, setTilt] = useState({ rotateX: 0, rotateY: 0 });

  function handleMouseMove(event: MouseEvent<HTMLDivElement>) {
    if (reducedMotion) return;

    const rect = event.currentTarget.getBoundingClientRect();
    const x = (event.clientX - rect.left) / rect.width - 0.5;
    const yPos = (event.clientY - rect.top) / rect.height - 0.5;

    setTilt({
      rotateX: yPos * -5,
      rotateY: x * 6,
    });
  }

  return (
    <AnimatedSection className="relative overflow-hidden bg-[#080d18] px-4 py-28 sm:px-6 lg:px-8">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_20%,rgba(34,211,238,0.14),transparent_34%),radial-gradient(circle_at_80%_75%,rgba(168,85,247,0.13),transparent_34%)]" />

      <div className="relative mx-auto max-w-7xl">
        <div className="mx-auto max-w-4xl text-center">
          <p className="text-sm uppercase tracking-[0.38em] text-cyan-200">
            Dashboard preview
          </p>

          <h2 className="mt-6 text-4xl font-semibold leading-tight tracking-[-0.04em] text-white sm:text-5xl lg:text-6xl">
            A control center for scans, reports, billing, and tenants.
          </h2>

          <p className="mx-auto mt-6 max-w-2xl text-base leading-8 text-slate-300 sm:text-lg">
            The admin workspace brings together scan execution, real-time
            progress, report history, SaaS packages, usage limits, invoices, and
            organization management.
          </p>
        </div>

        <motion.div
          style={{ y, rotateX: tilt.rotateX, rotateY: tilt.rotateY }}
          onMouseMove={handleMouseMove}
          onMouseLeave={() => setTilt({ rotateX: 0, rotateY: 0 })}
          initial={{ opacity: 0, y: 70, scale: 0.94 }}
          whileInView={{ opacity: 1, y: 0, scale: 1 }}
          viewport={{ once: true, margin: "-120px" }}
          transition={{ duration: 0.9, ease: easeOut }}
          className="relative mt-16 [transform-style:preserve-3d]"
        >
          <div className="absolute -inset-10 rounded-[2.5rem] bg-[radial-gradient(circle_at_50%_0%,rgba(96,165,250,0.28),rgba(168,85,247,0.18),transparent_68%)] blur-3xl" />

          <div className="relative rounded-[2.25rem] bg-[linear-gradient(135deg,rgba(96,165,250,0.72),rgba(168,85,247,0.58),rgba(34,211,238,0.72))] p-px shadow-2xl shadow-cyan-500/20">
            <div className="relative min-h-[360px] overflow-hidden rounded-[2.25rem] border border-white/10 bg-[#0b0f19]/95 p-3 backdrop-blur-xl sm:min-h-[620px]">
              <div className="relative h-full min-h-[340px] overflow-hidden rounded-[1.55rem] bg-[#080d18] sm:min-h-[590px]">
                <LandingImage
                  src="/landing/dashboard-previews.png"
                  alt="Dashboard preview visual"
                />

                <div className="absolute inset-0 bg-[linear-gradient(to_bottom,rgba(8,13,24,0.05),rgba(8,13,24,0.55))]" />

                <FloatingCard className="left-5 top-5 sm:left-8 sm:top-8" delay={0.2}>
                  Scan completed
                </FloatingCard>

                <FloatingCard className="right-5 top-24 sm:right-10 sm:top-28" delay={0.8}>
                  7 findings queued
                </FloatingCard>

                <FloatingCard className="bottom-5 left-5 sm:bottom-8 sm:left-8" delay={1.2}>
                  Invoice generated
                </FloatingCard>

                <FloatingCard className="bottom-5 right-5 sm:bottom-8 sm:right-8" delay={1.6}>
                  AI report ready
                </FloatingCard>
              </div>
            </div>
          </div>
        </motion.div>

        <motion.div
          variants={staggerContainer}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, margin: "-120px" }}
          className="mt-12 grid gap-4 md:grid-cols-3"
        >
          {[
            ["Live scan status", "Track running scans, progress, pages, and findings."],
            ["Billing control", "Generate invoices and manage subscription state."],
            ["Tenant analytics", "Monitor usage, package adoption, and scan limits."],
          ].map(([title, desc]) => (
            <motion.div
              key={title}
              variants={fadeUp}
              className="rounded-[1.5rem] border border-white/10 bg-white/[0.045] p-5 backdrop-blur-xl"
            >
              <h3 className="text-lg font-semibold text-white">{title}</h3>
              <p className="mt-2 text-sm leading-7 text-slate-300">{desc}</p>
            </motion.div>
          ))}
        </motion.div>
      </div>
    </AnimatedSection>
  );
}

function FAQSection() {
  const [open, setOpen] = useState(0);

  return (
    <AnimatedSection
      id="faq"
      className="relative overflow-hidden bg-[#080d18] px-4 py-28 sm:px-6 lg:px-8"
    >
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_20%,rgba(96,165,250,0.12),transparent_30%),radial-gradient(circle_at_80%_80%,rgba(168,85,247,0.12),transparent_34%)]" />

      <div className="relative mx-auto grid max-w-7xl gap-12 lg:grid-cols-[0.8fr_1.2fr] lg:items-start">
        <div>
          <p className="text-sm uppercase tracking-[0.38em] text-cyan-200">
            FAQ
          </p>

          <h2 className="mt-6 text-4xl font-semibold leading-tight tracking-[-0.04em] text-white sm:text-5xl">
            Answers before launch.
          </h2>

          <p className="mt-6 max-w-xl text-base leading-8 text-slate-300">
            The product is built for trial-first SaaS operations. Payments can
            be connected next, while invoices and billing records already work
            inside the platform.
          </p>

          <div className="mt-8">
            <GradientButton href="/register">Start free trial</GradientButton>
          </div>
        </div>

        <div className="space-y-4">
          {faqs.map(([question, answer], index) => {
            const active = open === index;

            return (
              <motion.div
                key={question}
                whileHover={{ y: -3 }}
                className={[
                  "overflow-hidden rounded-[1.5rem] border backdrop-blur-xl transition",
                  active
                    ? "border-cyan-300/30 bg-white/[0.075]"
                    : "border-white/10 bg-white/[0.04]",
                ].join(" ")}
              >
                <button
                  type="button"
                  onClick={() => setOpen(active ? -1 : index)}
                  className="flex w-full items-center justify-between gap-5 px-6 py-5 text-left"
                >
                  <span className="text-lg font-semibold text-white">
                    {question}
                  </span>

                  <motion.span
                    aria-hidden
                    animate={{ rotate: active ? 45 : 0 }}
                    transition={{ duration: 0.2 }}
                    className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-white/10 bg-white/10 text-xl text-cyan-100"
                  >
                    +
                  </motion.span>
                </button>

                <AnimatePresence initial={false}>
                  {active ? (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.25, ease: "easeOut" }}
                      className="overflow-hidden"
                    >
                      <p className="px-6 pb-6 text-sm leading-7 text-slate-300">
                        {answer}
                      </p>
                    </motion.div>
                  ) : null}
                </AnimatePresence>
              </motion.div>
            );
          })}
        </div>
      </div>
    </AnimatedSection>
  );
}

function FinalCTA() {
  const reducedMotion = useReducedMotion();

  return (
    <AnimatedSection className="relative overflow-hidden bg-[#080d18] px-4 py-28 sm:px-6 lg:px-8">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_30%,rgba(96,165,250,0.18),transparent_32%),radial-gradient(circle_at_65%_70%,rgba(168,85,247,0.18),transparent_34%)]" />

      <motion.div
        aria-hidden
        animate={
          reducedMotion
            ? undefined
            : {
                backgroundPosition: ["0% 50%", "100% 50%", "0% 50%"],
              }
        }
        transition={{ duration: 16, repeat: Infinity, ease: "linear" }}
        className="absolute inset-x-10 top-20 h-72 rounded-[3rem] bg-[linear-gradient(120deg,rgba(96,165,250,0.26),rgba(168,85,247,0.22),rgba(34,211,238,0.22),rgba(96,165,250,0.26))] bg-[length:220%_220%] blur-3xl"
      />

      <div className="relative mx-auto max-w-6xl overflow-hidden rounded-[2.5rem] border border-white/10 bg-white/[0.055] p-px shadow-2xl shadow-cyan-500/20 backdrop-blur-xl">
        <div className="relative overflow-hidden rounded-[2.5rem] bg-[#0b0f19]/90 px-6 py-16 text-center sm:px-10 sm:py-20">
          <LandingImage
            src="/landing/final-cta.png"
            alt=""
            className="opacity-30"
          />

          <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(37,99,235,0.50),rgba(147,51,234,0.42),rgba(34,211,238,0.28))]" />

          <motion.div
            aria-hidden
            animate={
              reducedMotion
                ? undefined
                : {
                    opacity: [0.22, 0.52, 0.22],
                    scale: [1, 1.08, 1],
                  }
            }
            transition={{ duration: 5, repeat: Infinity }}
            className="absolute left-1/2 top-1/2 h-80 w-80 -translate-x-1/2 -translate-y-1/2 rounded-full bg-white/20 blur-3xl"
          />

          <div className="relative">
            <p className="text-sm uppercase tracking-[0.38em] text-cyan-100">
              Ready to launch
            </p>

            <h2 className="mx-auto mt-6 max-w-4xl text-4xl font-semibold leading-tight tracking-[-0.05em] text-white sm:text-6xl">
              Start scanning, reporting, and billing from one premium workspace.
            </h2>

            <p className="mx-auto mt-6 max-w-2xl text-base leading-8 text-slate-100 sm:text-lg">
              Launch a trial, add your first target, run the first scan, and
              move into a paid package when ready.
            </p>

            <div className="mt-10 flex flex-wrap justify-center gap-4">
              <GradientButton href="/register">Start free trial</GradientButton>
              <GradientButton href="/login" variant="secondary">
                Open dashboard
              </GradientButton>
            </div>
          </div>
        </div>
      </div>
    </AnimatedSection>
  );
}



export function LandingPage() {
  return (
    <main className="min-h-screen overflow-hidden bg-[#0b0f19] text-slate-50">
      <LandingHeader />
      <HeroSection />
      <TrustBar />
      <ProblemSection />
      <FeaturesGrid />
      <HowItWorks />
      <PricingSection />
      <DashboardPreview />
      <FAQSection />
      <FinalCTA />
    </main>
  );
}
