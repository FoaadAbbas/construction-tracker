import { useState } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { Input } from "../../components/ui/Input";
import { Button } from "../../components/ui/Button";
import { useAuth } from "../../app/auth/AuthProvider";

export function LoginPage() {
  const nav = useNavigate();

  const { login } = useAuth();
  const location = useLocation();
  const from = (location.state as any)?.from?.pathname || "/";

  const [emailOrUsername, setEmailOrUsername] = useState("");
  const [password, setPassword] = useState("");
  const [touched, setTouched] = useState(false);
  const [loading, setLoading] = useState(false);
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
