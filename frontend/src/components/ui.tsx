import type { ReactNode } from "react";

export function Spinner() {
  return (
    <div className="loading">
      <span className="spinner" /> Loading…
    </div>
  );
}

export function Empty({ message }: { message: string }) {
  return <div className="empty">{message}</div>;
}

export function Card({ title, children, style }: { title?: string; children: ReactNode; style?: React.CSSProperties }) {
  return (
    <div className="card" style={style}>
      {title ? <div className="card-title">{title}</div> : null}
      {children}
    </div>
  );
}
