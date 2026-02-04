import { Outlet } from "react-router-dom";
import { useTheme } from "../app/useTheme";

export function AuthLayout() {
  const { mode, toggle } = useTheme();
  return (
    <div className="min-h-screen flex items-center justify-center bg-app text-app px-4">
      <div className="w-full max-w-md rounded-2xl border border-app card-surface p-6">
        <div className="mb-6 flex items-start justify-between gap-3">
          <div>
            <h1 className="text-xl font-semibold">ConsTrack</h1>
            <p className="text-sm muted">Sign in to continue</p>
          </div>
          <button
            onClick={toggle}
            className="rounded-lg border border-app px-3 py-2 text-sm bg-app"
            aria-label="Toggle theme"
            title="Toggle light/dark"
          >
            {mode === "light" ? "🌞" : "🌙"}
          </button>
        </div>

        <Outlet />
      </div>
    </div>
  );
}
