// src/components/navigation/Sidebar.tsx
import { useEffect } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useUi } from "../../app/useUi";
import { useLockBodyScroll } from "../../app/useLockBodyScroll.ts";

const base = "block px-3 py-2 rounded-lg text-sm transition border";
const active = "bg-app border-app text-app";
const idle = "muted hover:bg-app";

export function Sidebar() {
  const { isNavOpen, closeNav } = useUi();
  const location = useLocation();

  // Lock scrolling when drawer is open
  useLockBodyScroll(isNavOpen);

  // Close drawer on route change
  useEffect(() => {
    closeNav();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname]);

  // Close drawer on ESC
  useEffect(() => {
    if (!isNavOpen) return;

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeNav();
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [isNavOpen, closeNav]);

  return (
    <>
      {/* Backdrop */}
      {isNavOpen && (
        <button
          onClick={closeNav}
          className="fixed inset-0 z-40 bg-black/50"
          aria-label="Close menu backdrop"
        />
      )}

      {/* Drawer */}
      <aside
        className={[
          "fixed z-50 top-0 left-0 h-full w-72",
          "border-r border-app bg-app text-app",
          "transform transition-transform duration-200",
          isNavOpen ? "translate-x-0" : "-translate-x-full",
        ].join(" ")}
        role="dialog"
        aria-modal="true"
        aria-label="Navigation menu"
      >
        <div className="p-4 border-b border-app flex items-center justify-between">
          <div>
            <div className="text-sm muted">Project</div>
            <div className="font-semibold">ConsTrack</div>
          </div>
          <button
            onClick={closeNav}
            className="muted text-sm"
            aria-label="Close menu"
          >
            Close
          </button>
        </div>

        <nav className="p-4 space-y-1">
          <NavLink
            to="/"
            end
            className={({ isActive }) => `${base} ${isActive ? active : idle}`}
          >
            Dashboard
          </NavLink>

          <NavLink
            to="/scans"
            className={({ isActive }) => `${base} ${isActive ? active : idle}`}
          >
            Scans
          </NavLink>

          <NavLink
            to="/schedule"
            className={({ isActive }) => `${base} ${isActive ? active : idle}`}
          >
            Schedule
          </NavLink>

          <NavLink to="/areas" className={({ isActive }) => `${base} ${isActive ? active : idle}`}>Zones</NavLink>

          <NavLink
            to="/compare"
            className={({ isActive }) => `${base} ${isActive ? active : idle}`}
          >
            Compare
          </NavLink>

          <NavLink
            to="/reports"
            className={({ isActive }) => `${base} ${isActive ? active : idle}`}
          >
            Reports
          </NavLink>

          <NavLink
            to="/chat"
            className={({ isActive }) => `${base} ${isActive ? active : idle}`}
          >
            Chatbot
          </NavLink>

          <NavLink
            to="/model"
            className={({ isActive }) => `${base} ${isActive ? active : idle}`}
          >
            3D Model
          </NavLink>
        </nav>
      </aside>
    </>
  );
}
