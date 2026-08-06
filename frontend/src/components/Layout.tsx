import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { Icon } from "./icons";
import type { IconName } from "./icons";
import { DEFAULT_OPEN_GROUPS, SIDEBAR_GROUPS } from "../sidebarNav";

function GroupHeader({
  title,
  open,
  onToggle,
}: {
  title: string;
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <button type="button" className="nav-group-head" onClick={onToggle}>
      <span className="nav-group-dot" />
      <span className="nav-group-title">{title}</span>
      <Icon name="chevron" size={14} className={`nav-group-chevron${open ? " open" : ""}`} />
    </button>
  );
}

function SidebarContent({ openGroups, onToggleGroup }: { openGroups: string[]; onToggleGroup: (g: string) => void }) {
  const { logout } = useAuth();
  const navigate = useNavigate();
  return (
    <>
      <div className="sidebar-header">
        <div className="logo-mark">S</div>
        <div className="logo-text">
          <div className="logo-name">AI SIEM Platform</div>
          <div className="logo-version">v1.0</div>
        </div>
      </div>

      <nav className="nav">
        {SIDEBAR_GROUPS.map((group) => {
          const open = openGroups.includes(group.title);
          return (
            <div key={group.title} className="nav-group">
              <GroupHeader
                title={group.title}
                open={open}
                onToggle={() => onToggleGroup(group.title)}
              />
              {open ? (
                <div className="nav-group-items">
                  {group.items.map((item) => (
                    <NavLink
                      key={`${group.title}-${item.label}`}
                      to={item.to}
                      end={item.end}
                      className={({ isActive }) => `nav-item${isActive ? " active" : ""}`}
                    >
                      <Icon name={item.icon as IconName} size={16} className="nav-item-icon" />
                      <span className="nav-item-label">{item.label}</span>
                    </NavLink>
                  ))}
                </div>
              ) : null}
            </div>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-user">
          <div className="avatar">A</div>
          <div className="sidebar-user-meta">
            <div className="sidebar-user-name">analyst</div>
            <div className="sidebar-user-role">Security Analyst</div>
          </div>
          <button
            type="button"
            className="sidebar-logout"
            title="Logout"
            onClick={() => {
              logout();
              navigate("/login");
            }}
          >
            <Icon name="external" size={16} />
          </button>
        </div>
      </div>
    </>
  );
}

export function Layout({ children, title }: { children: ReactNode; title: string }) {
  const { pathname } = useLocation();
  const [openGroups, setOpenGroups] = useState<string[]>(DEFAULT_OPEN_GROUPS);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => {
    const group = SIDEBAR_GROUPS.find((g) => g.items.some((i) => (i.end ? pathname === i.to : pathname.startsWith(i.to))));
    if (group && !openGroups.includes(group.title)) {
      setOpenGroups((prev) => [...prev, group.title]);
    }
    setSidebarOpen(false);
  }, [pathname]);

  function toggleGroup(group: string) {
    setOpenGroups((prev) => (prev.includes(group) ? prev.filter((g) => g !== group) : [...prev, group]));
  }

  return (
    <div className="shell">
      {sidebarOpen ? <div className="sidebar-backdrop" onClick={() => setSidebarOpen(false)} /> : null}
      <aside className={`sidebar${sidebarOpen ? " open" : ""}`}>
        <SidebarContent openGroups={openGroups} onToggleGroup={toggleGroup} />
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="topbar-left">
            <button type="button" className="hamburger" onClick={() => setSidebarOpen((o) => !o)} aria-label="Toggle navigation">
              <Icon name="list" size={18} />
            </button>
            <div className="topbar-title">{title}</div>
          </div>
          <div className="topbar-right">
            <span className="badge-live">● LIVE</span>
            <span className="topbar-user">analyst</span>
          </div>
        </header>
        <div className="content">{children}</div>
      </div>
    </div>
  );
}
