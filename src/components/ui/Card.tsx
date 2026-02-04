import type { ReactNode } from "react";

export function Card({
  title,
  subtitle,
  right,
  children,
  className = "",
}: {
  title?: string;
  subtitle?: string;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={[
        "rounded-2xl border card-surface",
        className,
      ].join(" ")}
    >
      {(title || subtitle || right) && (
        <div className="px-4 py-3 border-b border-app flex items-start justify-between gap-3">
          <div>
            {title && <div className="font-semibold">{title}</div>}
            {subtitle && <div className="text-sm muted">{subtitle}</div>}
          </div>
          {right}
        </div>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}
