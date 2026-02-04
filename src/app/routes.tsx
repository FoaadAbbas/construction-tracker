import { createBrowserRouter } from "react-router-dom";
import { AppLayout } from "../layouts/AppLayout";
import { AuthLayout } from "../layouts/AuthLayout";
import { RequireAuth } from "./auth/RequireAuth";
import { AppDataProvider } from "./data/AppDataProvider";

import { LoginPage } from "../pages/auth/LoginPage";
import { RegisterPage } from "../pages/auth/RegisterPage";
import { ForgetPasswordPage } from "../pages/auth/ForgetPasswordPage";
import { ResetPasswordPage } from "../pages/auth/ResetPasswordPage";
import { DashboardPage } from "../pages/dashboard/DashboardPage";
import { UploadComparePage } from "../pages/scans/UploadComparePage";
import { AreasPage } from "../pages/areas/AreasPage";
import { ComparePage } from "../pages/compare/ComparePage";
import { ReportsPage } from "../pages/reports/ReportsPage";
import { ChatHistoryPage } from "../pages/chat/ChatHistoryPage";
import { SchedulePage } from "../pages/schedule/SchedulePage";
import { ModelPage } from "../pages/model/ModelPage";

export const router = createBrowserRouter([
  {
    element: <AuthLayout />,
    children: [
      { path: "/login", element: <LoginPage /> },
      { path: "/register", element: <RegisterPage /> },
      { path: "/forgot-password", element: <ForgetPasswordPage /> },
      { path: "/reset-password", element: <ResetPasswordPage /> },
    ],
  },
  {
    element: (
      <AppDataProvider>
        <RequireAuth />
      </AppDataProvider>
    ),
    children: [
      {
        element: <AppLayout />,
        children: [
          { path: "/", element: <DashboardPage /> },
          { path: "/scans", element: <UploadComparePage /> },
          { path: "/areas", element: <AreasPage /> },
          { path: "/schedule", element: <SchedulePage /> },
          { path: "/compare", element: <ComparePage /> },
          { path: "/reports", element: <ReportsPage /> },
          { path: "/chat", element: <ChatHistoryPage /> },
          { path: "/model", element: <ModelPage /> },
        ],
      },
    ],
  },
]);
