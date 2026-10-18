
import { useState } from "react";
import { loginUser, registerUser } from "../services/api";
import "./Auth.css";

export default function Auth({ onLogin }) {
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    setBusy(true);

    try {
      if (mode === "register") {
        await registerUser({ email, password });
        setMessage("Account created. You can now sign in.");
        setMode("login");
      } else {
        await loginUser({ email, password });
        const user = await onLogin();
        if (!user) setMessage("Signed in, but user details could not be loaded.");
      }
    } catch (err) {
      setError(err.message || "Authentication failed. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-page">
      <section className="auth-card">
        <a className="auth-brand" href="/">
          <span className="auth-brand-icon">◈</span>
          <span>qshare<span className="auth-brand-dot">.</span></span>
        </a>

        <div className="auth-eyebrow">YOUR PRIVATE CLOUD</div>
        <h1>{mode === "login" ? "Welcome back." : "Create your account."}</h1>
        <p className="auth-subtitle">
          {mode === "login"
            ? "Sign in to continue to your secure workspace."
            : "Create an account to get started with QShare."}
        </p>

        <form onSubmit={handleSubmit}>
          <label htmlFor="email">Email address</label>
          <input
            id="email"
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            required
          />

          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            autoComplete={mode === "login" ? "current-password" : "new-password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter your password"
            minLength={8}
            required
          />

          {error && <div className="auth-alert error" role="alert">{error}</div>}
          {message && <div className="auth-alert success" role="status">{message}</div>}

          <button className="auth-submit" type="submit" disabled={busy}>
            {busy ? "Please wait..." : mode === "login" ? "Sign in →" : "Create account →"}
          </button>
        </form>

        <div className="auth-switch">
          {mode === "login" ? "New to QShare?" : "Already have an account?"}
          {" "}
          <button type="button" onClick={() => {
            setMode(mode === "login" ? "register" : "login");
            setError("");
            setMessage("");
          }}>
            {mode === "login" ? "Create account" : "Sign in"}
          </button>
        </div>

        <div className="auth-security">
          <span>●</span> QShare research prototype · Not production-ready
        </div>
      </section>
    </main>
  );
}
