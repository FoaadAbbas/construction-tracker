import { RouterProvider } from "react-router-dom";
import { router } from "./app/routes";
import { UiProvider } from "./app/UiProvider";
import { AuthProvider } from "./app/auth/AuthProvider";
import { ThemeProvider } from "./app/ThemeProvider";

export default function App() {
  return (
    <AuthProvider>
      <ThemeProvider>
        <UiProvider>
          <RouterProvider router={router} />
        </UiProvider>
      </ThemeProvider>
    </AuthProvider>
  );
}
