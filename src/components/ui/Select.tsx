type SelectProps = React.SelectHTMLAttributes<HTMLSelectElement> & {
  label?: string;
};

export function Select({ label, className = "", children, ...props }: SelectProps) {
  return (
    <label className="block">
      {label && <div className="mb-1 text-sm muted">{label}</div>}
      <select
        className={[
          "w-full rounded-xl border px-3 py-2 text-sm outline-none",
          "bg-app text-app border-app focus:border-app",
          className,
        ].join(" ")}
        {...props}
      >
        {children}
      </select>
    </label>
  );
}
