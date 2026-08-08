import { useNavigate } from "react-router-dom";
import type { AsyncStatus } from "../../hooks/useAsync";
import { Icon, type IconName } from "../icons";
import { Widget } from "./Widget";

export interface ModuleRow {
  id: string;
  icon: IconName;
  name: string;
  description: string;
  to: string;
}

export function ModulePanel({
  title,
  icon,
  status,
  error,
  rows,
  emptyMessage = "No modules available",
}: {
  title: string;
  icon?: IconName;
  status: AsyncStatus;
  error?: string | null;
  rows: ModuleRow[] | null;
  emptyMessage?: string;
}) {
  const navigate = useNavigate();

  return (
    <Widget
      title={title}
      icon={icon}
      status={status}
      error={error}
      empty={!rows || rows.length === 0}
      emptyMessage={emptyMessage}
    >
      {rows ? (
        <div className="soc-module-rows">
          {rows.map((row) => (
            <button key={row.id} type="button" className="soc-module-row" onClick={() => navigate(row.to)}>
              <span className="soc-module-row-icon">
                <Icon name={row.icon} size={18} />
              </span>
              <span className="soc-module-row-body">
                <span className="soc-module-row-name">{row.name}</span>
                <span className="soc-module-row-desc">{row.description}</span>
              </span>
              <Icon name="chevron" size={15} className="soc-module-row-arrow" />
            </button>
          ))}
        </div>
      ) : null}
    </Widget>
  );
}
