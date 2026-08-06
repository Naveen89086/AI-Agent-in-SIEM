import type { ReactNode } from "react";
import { Icon, type IconName } from "../icons";

export type KpiTone = "accent" | "ok" | "warn" | "crit" | "muted";

interface KpiProps {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  icon?: IconName;
  tone?: KpiTone;
  onClick?: () => void;
}

export function Kpi({ label, value, sub, icon, tone = "accent", onClick }: KpiProps) {
  return (
    <div
      className={`soc-kpi soc-kpi-${tone}${onClick ? " is-clickable" : ""}`}
      onClick={onClick}
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? (e) => e.key === "Enter" && onClick() : undefined}
    >
      <div className="soc-kpi-top">
        {icon ? <Icon name={icon} size={14} /> : null}
        <span className="soc-kpi-label">{label}</span>
      </div>
      <div className="soc-kpi-value">{value}</div>
      {sub ? <div className="soc-kpi-sub">{sub}</div> : null}
    </div>
  );
}
