import { useState } from "react";
import { useNavigate } from "react-router-dom";
import type { ReactNode } from "react";
import { useAuth } from "../auth/AuthContext";
import { Icon } from "./icons";
import { Sidebar } from "./Sidebar";

export function Layout({ children, title }: { children: ReactNode; title: string }) {
  const { logout } = useAuth();
  const navigate = useNavigate();
  const [navOpen, setNavOpen] = useState(false);

  function handleLogout() {
    logout();
    navigate("/login");
  }

  return (
    <div className="shell">
      <Sidebar open={navOpen} onClose={() => setNavOpen(false)} />
      {navOpen && <div className="sidebar-backdrop" onClick={() => setNavOpen(false)} />}
      <div className="main">
        <header className="topbar">
          <div className="topbar-left">
            <button
              type="button"
              className="hamburger"
              aria-label="Toggle navigation"
              onClick={() => setNavOpen((v) => !v)}
            >
              <Icon name="list" size={18} />
            </button>
            <div className="topbar-title">{title}</div>
          </div>
          <div className="topbar-right">
            <span className="badge-live">● LIVE</span>
            <span className="topbar-user">analyst</span>
            <button type="button" className="topbar-logout" title="Logout" onClick={handleLogout}>
              <Icon name="external" size={15} />
            </button>
          </div>
        </header>
        <div className="content">{children}</div>
      </div>
    </div>
  );
}
