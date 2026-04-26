import { ButtonHTMLAttributes } from "react";

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost";
  fullWidth?: boolean;
};

const variants = {
  primary:
    "bg-cyan-400 text-slate-950 hover:bg-cyan-300 focus-visible:outline-cyan-300",
  secondary:
    "border border-white/10 bg-white/5 text-white hover:bg-white/10 focus-visible:outline-white/20",
  ghost:
    "text-slate-300 hover:bg-white/5 hover:text-white focus-visible:outline-white/20"
};

export function Button({
  className = "",
  variant = "primary",
  fullWidth = false,
  type = "button",
  ...props
}: ButtonProps) {
  return (
    <button
      type={type}
      className={`inline-flex items-center justify-center rounded-2xl px-4 py-3 text-sm font-semibold transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 ${variants[variant]} ${
        fullWidth ? "w-full" : ""
      } ${className}`.trim()}
      {...props}
    />
  );
}
