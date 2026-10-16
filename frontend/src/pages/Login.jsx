import { useState } from "react";

import Icon from "../components/Icon";
import { useAuth } from "../lib/auth";

export default function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await login(username.trim(), password);
    } catch (err) {
      setError(err.status === 400 ? "Invalid username or password." : err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-page">
      <form className="card login-card stack" onSubmit={submit} aria-label="Sign in">
        <div className="brand" style={{ padding: 0 }}>
          <Icon name="shield" style={{ color: "var(--accent)" }} /> ThreatDashboard
        </div>
        <p className="muted" style={{ margin: 0 }}>Unified threat monitoring, detection and response.</p>
        <label className="field">Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required autoFocus />
        </label>
        <label className="field">Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password" required />
        </label>
        {error && <div className="error-text" role="alert">{error}</div>}
        <button className="btn primary" type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      </form>
    </div>
  );
}
