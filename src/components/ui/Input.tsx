type InputProps = React.InputHTMLAttributes<HTMLInputElement> & {
  label?: string;
  error?: string;
};

export function Input({ label, error, className = "", ...props }: InputProps) {
  return (
    <label className="block">
      {label && (
        <div className="mb-1 text-sm muted">
          {label}
        </div>
      )}
      <input
        className={[
          "w-full rounded-xl border px-3 py-2 text-sm outline-none",
          "bg-app text-app",
          error ? "border-red-500" : "border-app focus:border-app",
          className,
        ].join(" ")}
        {...props}
      />
      {error && <div className="mt-1 text-xs text-red-400">{error}</div>}
    </label>
  );
}
