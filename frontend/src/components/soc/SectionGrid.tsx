import type { ReactNode } from "react";
import { Icon } from "../icons";

export function SectionGrid({
  status,
  error,
  columns = "3",
  skeletonCount = 6,
  children,
}: {
  status: "loading" | "success" | "error";
  error?: string | null;
  columns?: "2" | "3";
  skeletonCount?: number;
  children: ReactNode;
}) {
  if (status === "loading") {
    return (
      <div className={`soc-grid soc-grid-${columns}`}>
        {Array.from({ length: skeletonCount }).map((_, i) => (
          <div key={i} className="soc-widget soc-widget-skeleton">
            <span className="spinner" />
          </div>
        ))}
      </div>
    );
  }
  if (status === "error") {
    return (
      <div className="soc-state soc-state-error">
        <Icon name="warn" size={18} />
        <span>{error ?? "Failed to load"}</span>
      </div>
    );
  }
  return <div className={`soc-grid soc-grid-${columns}`}>{children}</div>;
}
