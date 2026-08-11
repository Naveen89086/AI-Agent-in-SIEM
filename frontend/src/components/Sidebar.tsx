import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import type { IconName } from "./icons";
import { Icon } from "./icons";

export interface SidebarNavItem {
  label: string;
  icon: IconName;
  to: string;
  end?: boolean;
}

export const SIDEBAR_NAV: SidebarNavItem[] = [
  { label: "Home / Overview", icon: "home", to: "/", end: true },
  { label: "Configuration Assessment", icon: "shieldCheck", to: "/endpoint/config" },
  { label: "File Integrity Monitoring", icon: "fileSearch", to: "/endpoint/fim" },
  { label: "Malware Detection", icon: "bug", to: "/endpoint/malware" },
  { label: "IOC Lookup", icon: "fingerprint", to: "/search" },
  { label: "Threat Hunting", icon: "crosshair", to: "/search" },
  { label: "Vulnerability Detection", icon: "target", to: "/search" },
  { label: "Security Logs / Event Monitoring", icon: "scrollText", to: "/search" },
  { label: "Network Monitoring", icon: "network", to: "/sources" },
  { label: "Process & Service Monitoring", icon: "activity", to: "/search" },
  { label: "User & Login Monitoring", icon: "userRound", to: "/search" },
  { label: "Alerts & Incidents", icon: "alert", to: "/alerts" },
  { label: "AI Security Analyst", icon: "brainCircuit", to: "/alerts" },
  { label: "Settings", icon: "settings", to: "/", end: true },
];

function matches(to: string, end: boolean | undefined, pathname: string): boolean {
  if (end) return pathname === to;
  return pathname === to || pathname.startsWith(to.endsWith("/") ? to : `${to}/`);
}

export function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  const activeItem = SIDEBAR_NAV.find((item) => matches(item.to, item.end, pathname));

  function handleLogout() {
    logout();
    navigate("/login");
  }

  return (
    <aside className={`sidebar${open ? " open" : ""}`}>
      <div className="sidebar-header">
        <div className="logo-mark">
          <Icon name="shield" size={18} />
        </div>
        <div className="logo-text">
          <div className="logo-name">SIEM Platform</div>
          <div className="logo-version">SECURITY OPERATIONS</div>
        </div>
      </div>

      <nav className="nav nav-flat">
        {SIDEBAR_NAV.map((item) => (
          <NavLink
            key={item.label}
            to={item.to}
            end={item.end}
            onClick={onClose}
            className={item === activeItem ? "nav-item active" : "nav-item"}
          >
            <Icon name={item.icon} size={16} className="nav-item-icon" />
            <span className="nav-item-label">{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-user">
          <div className="avatar">{(user?.username ?? "a").slice(0, 1).toUpperCase()}</div>
          <div className="sidebar-user-meta">
            <div className="sidebar-user-name">{user?.username ?? "analyst"}</div>
            <div className="sidebar-user-role">{user?.role ?? "Security Analyst"}</div>
          </div>
          <button type="button" className="sidebar-logout" title="Logout" onClick={handleLogout}>
            <Icon name="external" size={15} />
          </button>
        </div>
      </div>
    </aside>
  );
}
