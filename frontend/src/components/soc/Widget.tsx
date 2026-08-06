import type { ReactNode } from "react";
import type { AsyncStatus } from "../../hooks/useAsync";
import { Icon, type IconName } from "../icons";

interface WidgetProps {
  title: string;
  icon?: IconName;
  actions?: ReactNode;
  status?: AsyncStatus;
  error?: string | null;
  empty?: boolean;
  emptyMessage?: string;
  children?: ReactNode;
  className?: string;
  onClick?: () => void;
  hover?: boolean;
}

export function Widget({
  title,
  icon,
  actions,
  status = "success",
  error = null,
  empty = false,
  emptyMessage = "No data available",
  children,
  className = "",
  onClick,
  hover = false,
}: WidgetProps) {
  const clickable = typeof onClick === "function";
  return (
    <section
      className={`soc-widget ${hover ? "soc-widget-hover" : ""} ${clickable ? "soc-widget-clickable" : ""} ${className}`}
      onClick={onClick}
    >
      <header className="soc-widget-head">
        <div className="soc-widget-title">
          {icon ? <Icon name={icon} size={15} /> : null}
          <span>{title}</span>
        </div>
        {actions}
      </header>
      <div className="soc-widget-body">
        {status === "loading" ? (
          <div className="soc-state">
            <span className="spinner" />
            <span className="soc-state-text">Loading…</span>
          </div>
        ) : status === "error" ? (
          <div className="soc-state soc-state-error">
            <Icon name="warn" size={18} />
            <span>{error ?? "Failed to load data"}</span>
          </div>
        ) : empty ? (
          <div className="soc-state">
            <Icon name="search" size={18} />
            <span className="soc-state-text">{emptyMessage}</span>
          </div>
        ) : (
          children
        )}
      </div>
    </section>
  );
}

export function Section({
  icon,
  title,
  subtitle,
  action,
  onAction,
  children,
}: {
  icon?: IconName;
  title: string;
  subtitle?: string;
  action?: ReactNode;
  onAction?: () => void;
  children: ReactNode;
}) {
  return (
    <section className="soc-section">
      <header className="soc-section-head">
        <div className="soc-section-title">
          {icon ? <Icon name={icon} size={17} /> : null}
          <h2>{title}</h2>
        </div>
        <div className="soc-section-right">
          {subtitle ? <span className="soc-section-sub">{subtitle}</span> : null}
          {action ? (
            <button className="soc-section-action" onClick={onAction}>
              {action}
            </button>
          ) : null}
        </div>
      </header>
      {children}
    </section>
  );
}
