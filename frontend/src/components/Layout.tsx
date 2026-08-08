import { useNavigate } from "react-router-dom";
import type { ReactNode } from "react";
import { useAuth } from "../auth/AuthContext";
import { Icon } from "./icons";

export function Layout({ children, title }: { children: ReactNode; title: string }) {
  const { logout } = useAuth();
  const navigate = useNavigate();

  function handleLogout() {
    logout();
    navigate("/login");
  }

  return (
    <div className="shell">
      <div className="main">
        <header className="topbar">
          <div className="topbar-left">
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
