import { useState } from "react";
import { Link } from "react-router-dom";
import { Input } from "../../components/ui/Input";
import { Button } from "../../components/ui/Button";

const API_BASE = import.meta.env.VITE_API_BASE || '';

export function ForgetPasswordPage() {
  const [email, setEmail] = useState("");
  const [touched, setTouched] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [isError, setIsError] = useState(false);

  const emailError = touched && !email.includes("@") ? "Enter a valid email." : "";

  const canSubmit = email.includes("@");

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (!canSubmit) return;

    setLoading(true);
    setMessage("");
    setIsError(false);
    try {
      const res = await fetch(`${API_BASE}/api/auth/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to send reset email");
      }
      setMessage(data.message || "If an account with that email exists, a reset link has been sent.");
    } catch (err: any) {
      setIsError(true);
      setMessage(err.message || "Failed to send reset email. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <h2 className="text-xl font-semibold">Forgot Password</h2>
      <p className="text-sm text-gray-600">Enter your email to receive a password reset link.</p>
      {message && <div className={`text-sm ${isError ? 'text-red-500' : 'text-green-500'}`}>{message}</div>}
      <Input
        label="Email"
        placeholder="name@company.com"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        error={emailError}
        autoComplete="email"
      />

      <Button type="submit" disabled={!canSubmit || loading}>
        {loading ? "Sending..." : "Send Reset Link"}
      </Button>

      <div className="text-xs">
        <Link to="/login" className="underline">Back to login</Link>
      </div>
    </form>
  );
}