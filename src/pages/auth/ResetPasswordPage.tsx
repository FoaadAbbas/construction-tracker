import { useState, useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Input } from "../../components/ui/Input";
import { Button } from "../../components/ui/Button";

const API_BASE = import.meta.env.VITE_API_BASE || '';

export function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [touched, setTouched] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");

  const token = searchParams.get("token");

  useEffect(() => {
    if (!token) {
      setMessage("Invalid reset link.");
    }
  }, [token]);

  const passwordError = touched && newPassword.length < 6 ? "Password must be at least 6 characters." : "";
  const confirmError = touched && newPassword !== confirmPassword ? "Passwords do not match." : "";
  const canSubmit = newPassword.length >= 6 && newPassword === confirmPassword && token;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (!canSubmit) return;

    setLoading(true);
    setMessage("");
    try {
      const res = await fetch(`${API_BASE}/api/auth/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, newPassword }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Failed to reset password");
      }
      setMessage("Password reset successfully. Redirecting to login...");
      setTimeout(() => navigate("/login"), 2000);
    } catch (err: any) {
      setMessage(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <h2 className="text-xl font-semibold">Reset Password</h2>
      <p className="text-sm text-gray-600">Enter your new password.</p>
      {message && <div className="text-sm">{message}</div>}
      <Input
        label="New Password"
        type="password"
        placeholder="Enter new password"
        value={newPassword}
        onChange={(e) => setNewPassword(e.target.value)}
        error={passwordError}
        autoComplete="new-password"
      />
      <Input
        label="Confirm Password"
        type="password"
        placeholder="Confirm new password"
        value={confirmPassword}
        onChange={(e) => setConfirmPassword(e.target.value)}
        error={confirmError}
        autoComplete="new-password"
      />

      <Button type="submit" disabled={!canSubmit || loading}>
        {loading ? "Resetting..." : "Reset Password"}
      </Button>
    </form>
  );
}