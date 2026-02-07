import { useState } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { Input } from "../../components/ui/Input";
import { Button } from "../../components/ui/Button";
import { useAuth } from "../../app/auth/AuthProvider";

const API_BASE = import.meta.env.VITE_API_BASE || '';

export function LoginPage() {
  const nav = useNavigate();

  const { login, setAuth } = useAuth();
  const location = useLocation();
  const from = (location.state as any)?.from?.pathname || "/";

  const [emailOrUsername, setEmailOrUsername] = useState("");
  const [password, setPassword] = useState("");
  const [touched, setTouched] = useState(false);
  const [loading, setLoading] = useState(false);
  const [demoLoading, setDemoLoading] = useState(false);
  const [error, setError] = useState("");

  const emailOrUsernameError =
    touched && !emailOrUsername.trim() ? "Enter your email or username." : "";
  const passError =
    touched && password.length < 6
      ? "Password must be at least 6 characters."
      : "";

  const canSubmit = emailOrUsername.trim() && password.length >= 6;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (!canSubmit) return;

    setLoading(true);
    setError("");
    try {
      await login(emailOrUsername, password);
      nav(from, { replace: true });
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleDemoLogin() {
    setDemoLoading(true);
    setError("");
    try {
      const res = await fetch(`${API_BASE}/api/auth/demo-login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Demo login failed");

      // Store token and user info
      localStorage.setItem("constrack_token", data.token);
      localStorage.setItem("constrack_user", JSON.stringify(data.user));
      setAuth({ token: data.token, user: data.user });

      nav("/", { replace: true });
    } catch (err: any) {
      setError(err.message);
    } finally {
      setDemoLoading(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      {error && <div className="text-red-500 text-sm">{error}</div>}
      <Input
        label="Email or Username"
        placeholder="name@company.com or username"
        value={emailOrUsername}
        onChange={(e) => setEmailOrUsername(e.target.value)}
        error={emailOrUsernameError}
        autoComplete="username"
      />
      <Input
        label="Password"
        placeholder="••••••••"
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        error={passError}
        autoComplete="current-password"
      />

      <Button type="submit" disabled={!canSubmit || loading}>
        {loading ? "Logging in..." : "Log in"}
      </Button>

      <div className="relative my-4">
        <div className="absolute inset-0 flex items-center">
          <div className="w-full border-t border-gray-600"></div>
        </div>
        <div className="relative flex justify-center text-xs">
          <span className="bg-gray-900 px-2 text-gray-400">or</span>
        </div>
      </div>

      <button
        type="button"
        onClick={handleDemoLogin}
        disabled={demoLoading}
        className="w-full py-2 px-4 rounded-md border-2 border-dashed border-blue-500/50 text-blue-400 hover:bg-blue-500/10 hover:border-blue-400 transition-colors disabled:opacity-50"
      >
        {demoLoading ? "Loading demo..." : "🎯 Try Demo Account"}
      </button>
      <p className="text-xs text-gray-500 text-center">
        Explore with sample construction data - no signup required
      </p>

      <div className="text-xs muted flex justify-between">
        <Link to="/forgot-password" className="underline">
          Forgot password?
        </Link>

        <Link to="/register" className="underline">
          Create account
        </Link>
      </div>
    </form>
  );
}
