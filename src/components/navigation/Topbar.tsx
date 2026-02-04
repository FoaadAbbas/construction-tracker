// src/components/navigation/Topbar.tsx
import { useUi } from "../../app/useUi";
import { useAuth } from "../../app/auth/AuthProvider";
import { useAppData } from "../../app/data/useAppData";
import { useTheme } from "../../app/useTheme";

export function Topbar() {
  const { toggleNav } = useUi();
  const { user, logout } = useAuth();
  const { projects, data, setProjectId } = useAppData();
  const { mode, toggle } = useTheme();

  return (
    <header className="sticky top-0 z-10 border-b border-app bg-app backdrop-blur">
      <div className="px-4 md:px-6 h-16 flex items-center justify-between max-w-7xl mx-auto">
        {/* Left: Menu + title */}
        <div className="flex items-center gap-3">
          <button
            onClick={toggleNav}
            className="rounded-lg border border-app px-3 py-2 text-sm bg-app"
            aria-label="Open menu"
          >
            ☰
          </button>

          <div className="text-sm muted">
            Construction tracking
          </div>
        </div>

        {/* Right: Project selector + theme + user */}
        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-2">
            <label className="text-xs muted">Project</label>
            <select
              value={data.projectId || ""}
              onChange={(e) => setProjectId(e.target.value)}
              className="rounded-lg border border-app bg-app px-3 py-2 text-sm"
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={toggle}
            className="rounded-lg border border-app px-3 py-2 text-sm bg-app"
            aria-label="Toggle theme"
            title="Toggle light/dark"
          >
            {mode === "light" ? "🌞 Light" : "🌙 Dark"}
          </button>

          {user?.name && (
            <div className="text-xs muted hidden md:block">
              {user.name}
            </div>
          )}

          <button
            onClick={logout}
            className="rounded-lg border border-app px-3 py-2 text-sm bg-app"
          >
            Logout
          </button>
        </div>
      </div>
    </header>
  );
}
