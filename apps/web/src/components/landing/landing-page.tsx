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
    setScrolled(value > 24);
  });

  return (
    <motion.header
      animate={{
        backgroundColor: scrolled ? "rgba(11,15,25,0.72)" : "rgba(11,15,25,0)",
        borderColor: scrolled ? "rgba(255,255,255,0.10)" : "rgba(255,255,255,0)"
      }}
      className="fixed inset-x-0 top-0 z-50 border-b px-6 py-4 backdrop-blur-xl transition lg:px-10"
    >
      <nav className="mx-auto flex max-w-7xl items-center justify-between gap-6">
        <Link href="/" className="font-semibold text-white">
          Web Scanner
        </Link>
        <div className="hidden items-center gap-7 md:flex">
          {navItems.map(([label, href]) => (
            <Link
              key={href}
              href={href}
              className="group relative text-sm text-slate-300 transition hover:text-white"
            >
              {label}
              <motion.span
                aria-hidden
                className="absolute -bottom-2 left-0 h-px w-full origin-left bg-cyan-300"
                initial={{ scaleX: 0 }}
                whileHover={{ scaleX: 1 }}
                transition={{ duration: 0.22 }}
              />
            </Link>
          ))}
        </div>
        <div className="flex items-center gap-3">
          <Link
            href="/login"
            className="hidden text-sm text-slate-300 transition hover:text-white sm:inline"
          >
            Login
          </Link>
          <GradientButton href="/register">Start trial</GradientButton>
        </div>
      </nav>
    </motion.header>
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

function HeroSection() {
  const reducedMotion = useReducedMotion();
  const { scrollY } = useScroll();
  const y = useTransform(scrollY, [0, 700], [0, reducedMotion ? 0 : 90]);

  return (
    <section className="relative flex min-h-screen overflow-hidden bg-[#0b0f19] px-6 py-28 text-white lg:px-10">
      <motion.div
        aria-hidden
        animate={
          reducedMotion
            ? undefined
            : { backgroundPosition: ["0% 50%", "100% 50%", "0% 50%"] }
        }
        transition={{ duration: 18, repeat: Infinity, ease: "linear" }}
        className="absolute inset-0 hidden bg-[linear-gradient(120deg,rgba(37,99,235,0.26),rgba(147,51,234,0.20),rgba(34,211,238,0.18),transparent_68%)] bg-[length:220%_220%] md:block"
      />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,rgba(96,165,250,0.22),transparent_28%),radial-gradient(circle_at_70%_30%,rgba(168,85,247,0.18),transparent_30%),radial-gradient(circle_at_55%_80%,rgba(34,211,238,0.14),transparent_34%)]" />
      <motion.div
        aria-hidden
        animate={reducedMotion ? undefined : glowPulse}
        className="absolute right-10 top-24 hidden h-72 w-72 rounded-full bg-cyan-400/20 blur-3xl md:block"
      />
      <motion.div
        style={{ y }}
        className="absolute inset-x-8 top-28 h-72 rounded-lg border border-white/5 bg-white/[0.025] blur-3xl"
      />

      <div className="relative mx-auto grid w-full max-w-7xl items-center gap-12 lg:grid-cols-[1fr_0.86fr]">
        <motion.div
          variants={staggerContainer}
          initial="hidden"
          animate="show"
          className="mx-auto max-w-4xl text-center lg:mx-0 lg:text-left"
        >
          <motion.p
            variants={fadeUp}
            className="text-sm uppercase tracking-[0.35em] text-cyan-200"
          >
            Web Scanner SaaS
          </motion.p>
          <motion.h1
            variants={fadeUp}
            className="mt-6 text-5xl font-semibold leading-[1.02] tracking-normal text-white sm:text-6xl lg:text-7xl"
          >
            Premium vulnerability scanning for teams that move fast.
          </motion.h1>
          <motion.p
            variants={fadeUp}
            className="mx-auto mt-6 max-w-2xl text-lg leading-8 text-slate-300 lg:mx-0"
          >
            Launch trials, manage tenants, track usage, and generate clean billing
            records while your scanner keeps the security signal sharp.
          </motion.p>
          <motion.div
            variants={fadeUp}
            className="mt-10 flex flex-wrap justify-center gap-4 lg:justify-start"
          >
            <GradientButton href="/register">Start free trial</GradientButton>
            <GradientButton href="/login" variant="secondary">
              Open dashboard
            </GradientButton>
          </motion.div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 42 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.8, ease: easeOut, delay: 0.25 }}
          className="relative min-h-[430px]"
        >
          <motion.div
            animate={reducedMotion ? undefined : floating}
            className="absolute inset-0 overflow-hidden rounded-lg border border-white/10 bg-white/[0.045] shadow-2xl shadow-cyan-500/10 backdrop-blur-2xl"
          >
            <LandingImage src="/landing/hero.png" alt="Animated scanner dashboard preview" priority />
          </motion.div>
          <FloatingCard className="left-0 top-10" delay={0.1}>
            Live scan queue
          </FloatingCard>
          <FloatingCard className="right-0 top-36" delay={0.8}>
            Invoice ready
          </FloatingCard>
          <FloatingCard className="bottom-12 left-12" delay={1.4}>
            Trial usage 0 / 1
          </FloatingCard>
        </motion.div>
      </div>
    </section>
  );
}

function TrustBar() {
  const logos = ["NOVA", "LUMEN", "VECTOR", "ATLAS", "CIPHER", "ORBIT"];
  return (
    <div className="group overflow-hidden border-y border-white/10 bg-[#0b0f19] py-6">
      <div className="flex w-max gap-12 px-8 [animation:landing-marquee_24s_linear_infinite] group-hover:[animation-play-state:paused]">
        {[...logos, ...logos].map((logo, index) => (
          <motion.div
            key={`${logo}-${index}`}
            variants={fadeUp}
            initial="hidden"
            whileInView="show"
            viewport={{ once: true }}
            className="w-36 text-center text-sm font-semibold tracking-[0.35em] text-slate-500 grayscale transition hover:text-slate-300"
          >
            {logo}
          </motion.div>
        ))}
      </div>
    </div>
  );
}

function ProblemSection() {
  return (
    <AnimatedSection
      id="problem"
      className="mx-auto grid max-w-7xl gap-10 px-6 py-28 lg:grid-cols-2 lg:px-10"
    >
      <div>
        <p className="text-sm uppercase tracking-[0.35em] text-cyan-200">The problem</p>
        <h2 className="mt-5 text-4xl font-semibold tracking-normal text-white">
          Security teams need speed without losing control.
        </h2>
        <p className="mt-5 text-lg leading-8 text-slate-300">
          Scanner operations often scatter across tenants, targets, subscriptions,
          usage limits, and billing. This experience brings those threads into one
          calm, animated workspace.
        </p>
      </div>
      <motion.div
        whileInView={{ opacity: 1, x: 0 }}
        initial={{ opacity: 0, x: 40 }}
        viewport={{ once: true }}
        transition={{ duration: 0.75, ease: easeOut }}
        className="relative min-h-[360px] overflow-hidden rounded-lg border border-white/10 bg-white/[0.045] p-2 shadow-2xl shadow-purple-500/10 backdrop-blur-xl"
      >
        <div className="relative h-full min-h-[340px] overflow-hidden rounded-lg">
          <LandingImage src="/landing/problem-section.png" alt="Problem section visual" />
        </div>
      </motion.div>
    </AnimatedSection>
  );
}

function FeaturesGrid() {
  return (
    <AnimatedSection id="features" className="mx-auto max-w-7xl px-6 py-24 lg:px-10">
      <div className="grid gap-8 lg:grid-cols-[0.9fr_1.1fr] lg:items-end">
        <div className="max-w-3xl">
          <p className="text-sm uppercase tracking-[0.35em] text-cyan-200">Features</p>
          <h2 className="mt-5 text-4xl font-semibold text-white">
            Everything needed for the SaaS scanner foundation.
          </h2>
        </div>
        <div className="relative min-h-[220px] overflow-hidden rounded-lg border border-white/10 bg-white/[0.045]">
          <LandingImage src="/landing/feature-section.png" alt="Feature section visual" />
        </div>
      </div>
      <motion.div
        variants={staggerContainer}
        initial="hidden"
        whileInView="show"
        viewport={{ once: true, margin: "-120px" }}
        className="mt-12 grid gap-5 md:grid-cols-2 xl:grid-cols-3"
      >
        {features.map(([title, description], index) => (
          <motion.div key={title} variants={fadeUp}>
            <FeatureCard title={title} description={description} index={index} />
          </motion.div>
        ))}
      </motion.div>
    </AnimatedSection>
  );
}

function HowItWorks() {
  const steps = ["Register trial", "Add targets", "Run one trial scan", "Upgrade when ready"];
  return (
    <AnimatedSection id="how-it-works" className="mx-auto max-w-7xl px-6 py-24 lg:px-10">
      <div className="grid gap-8 lg:grid-cols-[0.9fr_1.1fr] lg:items-center">
        <div className="max-w-3xl">
          <p className="text-sm uppercase tracking-[0.35em] text-cyan-200">How it works</p>
          <h2 className="mt-5 text-4xl font-semibold text-white">
            A clean path from trial to paid operations.
          </h2>
        </div>
        <div className="relative min-h-[240px] overflow-hidden rounded-lg border border-white/10 bg-white/[0.045]">
          <LandingImage src="/landing/how-it-works.png" alt="How it works visual" />
        </div>
      </div>
      <div className="relative mt-14 grid gap-5 md:grid-cols-4">
        <motion.div
          initial={{ scaleX: 0 }}
          whileInView={{ scaleX: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 1.1, ease: easeOut }}
          className="absolute left-0 top-10 hidden h-px w-full origin-left bg-[linear-gradient(90deg,#60a5fa,#a855f7,#22d3ee)] md:block"
        />
        {steps.map((step, index) => (
          <GlowCard key={step} className="relative">
            <motion.div
              initial={{ scale: 0.8, opacity: 0 }}
              whileInView={{ scale: 1, opacity: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.35, delay: index * 0.08 }}
              className="flex h-12 w-12 items-center justify-center rounded-full bg-white text-sm font-bold text-[#0b0f19]"
            >
              {index + 1}
            </motion.div>
            <h3 className="mt-5 text-xl font-semibold text-white">{step}</h3>
            <p className="mt-3 text-sm leading-7 text-slate-300">
              Move through the product without payment processing, checkout, or card
              collection in this phase.
            </p>
          </GlowCard>
        ))}
      </div>
    </AnimatedSection>
  );
}

function PricingSection() {
  const [packages, setPackages] = useState<Package[]>([]);

  useEffect(() => {
    void apiClient.listPackages().then(setPackages).catch(() => setPackages([]));
  }, []);

  const visiblePackages =
    packages.length > 0
      ? packages.filter((item) => item.status === "active")
      : [
          {
            id: 1,
            name: "Bronze",
            price_monthly: "0",
            scan_limit_per_week: 1
          },
          {
            id: 2,
            name: "Silver",
            price_monthly: "19",
            scan_limit_per_week: 10
          },
          {
            id: 3,
            name: "Gold",
            price_monthly: "49",
            scan_limit_per_week: 100
          }
        ];

  return (
    <AnimatedSection id="pricing" className="relative mx-auto max-w-7xl px-6 py-24 lg:px-10">
      <div className="absolute inset-x-6 top-12 h-72 overflow-hidden rounded-lg opacity-25 lg:inset-x-10">
        <LandingImage src="/landing/pricing-bg.png" alt="" />
      </div>
      <div className="relative text-center">
        <p className="text-sm uppercase tracking-[0.35em] text-cyan-200">Pricing</p>
        <h2 className="mt-5 text-4xl font-semibold text-white">
          Packages ready for trial billing.
        </h2>
      </div>
      <div className="relative mt-12 grid gap-6 lg:grid-cols-3">
        {visiblePackages.map((item, index) => (
          <PricingCard
            key={item.id}
            name={item.name}
            price={`$${item.price_monthly}`}
            scans={`${item.scan_limit_per_week} scans per week`}
            highlighted={index === 1}
          />
        ))}
      </div>
    </AnimatedSection>
  );
}

function DashboardPreview() {
  const reducedMotion = useReducedMotion();
  const { scrollYProgress } = useScroll();
  const y = useTransform(scrollYProgress, [0.45, 0.9], [reducedMotion ? 0 : 42, reducedMotion ? 0 : -42]);
  const [tilt, setTilt] = useState({ rotateX: 0, rotateY: 0 });

  function handleMouseMove(event: MouseEvent<HTMLDivElement>) {
    if (reducedMotion) {
      return;
    }
    const rect = event.currentTarget.getBoundingClientRect();
    const x = (event.clientX - rect.left) / rect.width - 0.5;
    const yPos = (event.clientY - rect.top) / rect.height - 0.5;
    setTilt({ rotateX: yPos * -4, rotateY: x * 5 });
  }

  return (
    <AnimatedSection className="mx-auto max-w-7xl px-6 py-24 lg:px-10">
      <div className="text-center">
        <p className="text-sm uppercase tracking-[0.35em] text-cyan-200">Dashboard preview</p>
        <h2 className="mt-5 text-4xl font-semibold text-white">
          A premium shell for operational scan work.
        </h2>
      </div>
      <motion.div
        style={{ y, rotateX: tilt.rotateX, rotateY: tilt.rotateY }}
        onMouseMove={handleMouseMove}
        onMouseLeave={() => setTilt({ rotateX: 0, rotateY: 0 })}
        animate={
          reducedMotion
            ? undefined
            : { backgroundPosition: ["0% 50%", "100% 50%", "0% 50%"] }
        }
        transition={{ duration: 8, repeat: Infinity, ease: "linear" }}
        className="relative mt-12 rounded-lg bg-[linear-gradient(135deg,rgba(96,165,250,0.75),rgba(168,85,247,0.65),rgba(34,211,238,0.7),rgba(96,165,250,0.75))] bg-[length:220%_220%] p-px shadow-2xl shadow-cyan-500/20 [transform-style:preserve-3d]"
      >
        <div className="relative min-h-[520px] overflow-hidden rounded-lg border border-white/10 bg-[#0b0f19]/95 p-4">
          <LandingImage src="/landing/dashboard-previews.png" alt="Dashboard preview visual" />
          <FloatingCard className="left-8 top-8" delay={0.2}>
            Scan completed
          </FloatingCard>
          <FloatingCard className="bottom-8 right-8" delay={1}>
            7 findings queued
          </FloatingCard>
        </div>
      </motion.div>
    </AnimatedSection>
  );
}

function FAQSection() {
  const [open, setOpen] = useState(0);
  return (
    <AnimatedSection id="faq" className="mx-auto max-w-4xl px-6 py-24 lg:px-10">
      <div className="text-center">
        <p className="text-sm uppercase tracking-[0.35em] text-cyan-200">FAQ</p>
        <h2 className="mt-5 text-4xl font-semibold text-white">Answers before launch.</h2>
      </div>
      <div className="mt-10 space-y-4">
        {faqs.map(([question, answer], index) => (
          <div key={question} className="rounded-lg border border-white/10 bg-white/[0.055] p-5">
            <button
              type="button"
              onClick={() => setOpen(open === index ? -1 : index)}
              className="flex w-full items-center justify-between gap-4 text-left text-lg font-semibold text-white"
            >
              {question}
              <motion.span
                aria-hidden
                animate={{ rotate: open === index ? 180 : 0 }}
                className="text-cyan-200"
              >
               ⌄
              </motion.span>
            </button>
            <AnimatePresence initial={false}>
              {open === index ? (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: "auto", opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.25, ease: "easeOut" }}
                  className="overflow-hidden"
                >
                  <motion.p
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 4 }}
                    className="pt-4 text-sm leading-7 text-slate-300"
                  >
                    {answer}
                  </motion.p>
                </motion.div>
              ) : null}
            </AnimatePresence>
          </div>
        ))}
      </div>
    </AnimatedSection>
  );
}

function FinalCTA() {
  const reducedMotion = useReducedMotion();
  return (
    <AnimatedSection className="px-6 py-24 lg:px-10">
      <div className="relative mx-auto max-w-6xl overflow-hidden rounded-lg border border-white/10 p-10 text-center shadow-2xl shadow-cyan-500/20">
        <LandingImage src="/landing/final-cta.png" alt="" className="opacity-55" />
        <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(37,99,235,0.68),rgba(147,51,234,0.62),rgba(34,211,238,0.44))]" />
        <motion.div
          aria-hidden
          animate={reducedMotion ? undefined : glowPulse}
          className="absolute inset-8 rounded-lg bg-white/10 blur-3xl"
        />
        {[0, 1, 2].map((item) => (
          <motion.span
            key={item}
            aria-hidden
            animate={
              reducedMotion
                ? undefined
                : { x: [0, 18, 0], y: [0, -22, 0], opacity: [0.2, 0.55, 0.2] }
            }
            transition={{ duration: 6 + item, repeat: Infinity, delay: item * 0.8 }}
            className="absolute h-24 w-24 rounded-full bg-white/10 blur-2xl"
            style={{ left: `${20 + item * 24}%`, top: `${18 + item * 12}%` }}
          />
        ))}
        <div className="relative">
          <h2 className="text-4xl font-semibold text-white md:text-5xl">
            Start your 14-day free trial.
          </h2>
          <p className="mx-auto mt-5 max-w-2xl text-lg leading-8 text-slate-100">
            No credit card required. One trial scan included. Invoice generated
            for after the trial.
          </p>
          <div className="mt-8 flex justify-center">
            <GradientButton href="/register">Start free trial</GradientButton>
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
