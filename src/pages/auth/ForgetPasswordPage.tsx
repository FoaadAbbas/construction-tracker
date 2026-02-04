import { useState } from "react";
import { Link } from "react-router-dom";
import { Input } from "../../components/ui/Input";
import { Button } from "../../components/ui/Button";

export function ForgetPasswordPage() {
  const [email, setEmail] = useState("");
  const [touched, setTouched] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");

  const emailError = touched && !email.includes("@") ? "Enter a valid email." : "";

  const canSubmit = email.includes("@");

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (!canSubmit) return;

    setLoading(true);
    setMessage("");
    try {
      const res = await fetch("/api/auth/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Failed to send reset email");
      }
      setMessage("If an account with that email exists, a reset link has been sent.");
    } catch (err: any) {
      setMessage(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <h2 className="text-xl font-semibold">Forgot Password</h2>
      <p className="text-sm text-gray-600">Enter your email to receive a password reset link.</p>
      {message && <div className="text-sm">{message}</div>}
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