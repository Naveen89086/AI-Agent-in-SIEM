import type { ReactNode } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

const NAV = [
  { to: "/", label: "Dashboard", icon: "◈", exact: true },
  { to: "/search", label: "Search", icon: "⌕", exact: true },
  { to: "/alerts", label: "Alerts", icon: "⚠" },
  { to: "/cases", label: "Cases", icon: "▣" },
  { to: "/rules", label: "Rules", icon: "≣" },
  { to: "/sources", label: "Sources", icon: "⇄" },
  { to: "/soar", label: "SOAR", icon: "⚙" },
  { to: "/reports", label: "Reports", icon: "▤" },
];

export function Layout({ children, title }: { children: ReactNode; title: string }) {
  const { logout } = useAuth();
  const navigate = useNavigate();

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="logo-mark">S</div>
          <div>SIEM Platform</div>
        </div>
        <nav className="nav">
          <div className="nav-section">Analyze</div>
          {NAV.slice(0, 4).map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.exact}
              className={({ isActive }) => `nav-item${isActive ? " active" : ""}`}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
          <div className="nav-section">Configure</div>
          {NAV.slice(4).map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => `nav-item${isActive ? " active" : ""}`}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="topbar-title">{title}</div>
          <div className="topbar-right">
            <span className="badge-live">● LIVE</span>
            <span style={{ color: "var(--text-dim)", fontSize: 13 }}>analyst</span>
            <button
              className="btn btn-sm"
              onClick={() => {
                logout();
                navigate("/login");
              }}
            >
              Logout
            </button>
          </div>
        </header>
        <div className="content">{children}</div>
      </div>
    </div>
  );
}
