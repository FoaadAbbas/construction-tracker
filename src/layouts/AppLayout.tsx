import { Outlet } from "react-router-dom";
import { Sidebar } from "../components/navigation/Sidebar";
import { Topbar } from "../components/navigation/Topbar";
import { ChatWidget } from "../features/chat/components/ChatWidget";
import { useTheme } from "../app/useTheme";

export function AppLayout() {
  const { mode } = useTheme();
  return (
    <div className={`min-h-screen ${mode === "light" ? "theme-light" : "theme-dark"} bg-app text-app`}>
      <Topbar />

      {/* Drawer sidebar overlays the page */}
      <Sidebar />

      <main className="p-4 md:p-6 max-w-7xl mx-auto">
        <Outlet />
      </main>

      <ChatWidget />
    </div>
  );
}
