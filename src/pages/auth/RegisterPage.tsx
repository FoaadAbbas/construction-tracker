import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Input } from "../../components/ui/Input";
import { Button } from "../../components/ui/Button";
import { useAuth } from "../../app/auth/AuthProvider";

export function RegisterPage() {
  const nav = useNavigate();
  const { register } = useAuth();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const [touched, setTouched] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const nameError = touched && name.trim().length < 2 ? "Enter your name." : "";
  const emailError = touched && !email.includes("@") ? "Enter a valid email." : "";
  const usernameError = touched && username.trim().length < 3 ? "Username must be at least 3 characters." : "";
  const passError =
    touched && password.length < 6 ? "Password must be at least 6 characters." : "";

  const canSubmit =
    name.trim().length >= 2 && email.includes("@") && username.trim().length >= 3 && password.length >= 6;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (!canSubmit) return;

    setLoading(true);
    setError("");
    try {
      await register(name, email, username, password);
      nav("/");
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
        label="Full name"
        placeholder="Michael Billan"
        value={name}
        onChange={(e) => setName(e.target.value)}
        error={nameError}
        autoComplete="name"
      />

      <Input
        label="Email"
        placeholder="name@company.com"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        error={emailError}
        autoComplete="email"
      />

      <Input
        label="Username"
        placeholder="michaelb"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        error={usernameError}
        autoComplete="username"
      />

      <Input
        label="Password"
        placeholder="Minimum 6 characters"
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        error={passError}
        autoComplete="new-password"
      />

      <Button type="submit" disabled={!canSubmit || loading}>
        {loading ? "Creating..." : "Create account"}
      </Button>

      <div className="text-xs muted">
        Already have an account?{" "}
        <Link to="/login" className="underline">
          Log in
        </Link>
      </div>
    </form>
  );
}
