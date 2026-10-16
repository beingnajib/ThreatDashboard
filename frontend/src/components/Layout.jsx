import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";

import { useApi } from "../hooks/useApi";
import { useStoredState } from "../hooks/useStoredState";
import { useAuth } from "../lib/auth";
import Icon from "./Icon";

const NAV = [
  { title: "Monitor", items: [
    { to: "/", label: "SOC overview", icon: "grid", end: true },
    { to: "/executive", label: "Executive view", icon: "briefcase" },
    { to: "/incidents", label: "Incidents", icon: "siren", badge: "incidents" },
    { to: "/alerts", label: "Alerts", icon: "bell", badge: "alerts" },
    { to: "/query", label: "Ask the data", icon: "message" },
  ] },
  { title: "Visibility", items: [
    { to: "/telemetry", label: "Telemetry", icon: "activity" },
    { to: "/assets", label: "Assets & shadow IT", icon: "server" },
  ] },
  { title: "Intelligence", items: [
    { to: "/indicators", label: "Indicators", icon: "target" },
    { to: "/actors", label: "Threat actors", icon: "user" },
    { to: "/exposure", label: "External risk", icon: "globe" },
    { to: "/feeds", label: "Feeds & connectors", icon: "rss" },
    { to: "/import", label: "Import", icon: "upload" },
  ] },
  { title: "Respond", items: [
    { to: "/response", label: "Response center", icon: "zap" },
    { to: "/rules", label: "Detection rules", icon: "sliders" },
  ] },
  { title: "Govern", items: [
    { to: "/compliance", label: "Compliance", icon: "check" },
    { to: "/reports", label: "Reports", icon: "file" },
  ] },
];

export default function Layout() {
  const { user, logout } = useAuth();
  const [theme, setTheme] = useStoredState("threatdash.theme", "dark");
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();
  const { data: incidents } = useApi("/incidents/", { open: true, severity_min: 3, page_size: 1 }, { pollMs: 60000 });
  const { data: alerts } = useApi("/alerts/", { status: "open", page_size: 1 }, { pollMs: 60000 });
  const counts = { incidents: incidents?.count, alerts: alerts?.count };

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);
  useEffect(() => setMenuOpen(false), [location.pathname]);

  return (
    <div className="app">
      <nav className={`sidebar${menuOpen ? " open" : ""}`} aria-label="Main navigation">
        <div className="brand"><Icon name="shield" style={{ color: "var(--accent)" }} />ThreatDashboard</div>
        {NAV.map((section) => (
          <div className="nav-section" key={section.title}>
            <div className="nav-section-title">{section.title}</div>
            {section.items.map((item) => (
              <NavLink key={item.to} to={item.to} end={item.end} className="nav-link">
                <Icon name={item.icon} />
                {item.label}
                {item.badge && counts[item.badge] > 0 && <span className="nav-count">{counts[item.badge]}</span>}
              </NavLink>
            ))}
          </div>
        ))}
        <div className="sidebar-footer">
          Signed in as <strong>{user?.username}</strong>
          {user?.is_staff && <span className="badge info" style={{ marginLeft: 6 }}>staff</span>}
        </div>
      </nav>
      <div className="main">
        <header className="topbar">
          <button className="btn ghost menu-button" aria-label="Open menu" onClick={() => setMenuOpen((o) => !o)}>
            <Icon name="menu" />
          </button>
          <span className="row muted small"><span className="live-dot" aria-hidden="true" />Live monitoring</span>
          <span className="spacer" />
          <button className="btn ghost" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}>
            <Icon name={theme === "dark" ? "sun" : "moon"} />
          </button>
          <button className="btn" onClick={logout}><Icon name="logout" />Sign out</button>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
      {menuOpen && <div className="overlay" style={{ zIndex: 55 }} onClick={() => setMenuOpen(false)} />}
    </div>
  );
}
