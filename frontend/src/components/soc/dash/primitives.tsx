import type { ReactNode } from "react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, XAxis, YAxis } from "recharts";
import { Icon, type IconName } from "../../icons";

/* --------------------------------------------------------------------------
   Shared building blocks for the dense dashboard panels.
   -------------------------------------------------------------------------- */

export function DashPanel({
  title,
  icon,
  badge,
  children,
  className = "",
}: {
  title: string;
  icon?: IconName;
  badge?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`dash-panel ${className}`}>
      <header className="dash-panel-head">
        <div className="dash-panel-title">
          {icon ? <Icon name={icon} size={13} /> : null}
          <span>{title}</span>
        </div>
        {badge ? <div className="dash-panel-badge">{badge}</div> : null}
      </header>
      <div className="dash-panel-body">{children}</div>
    </section>
  );
}

export function StatusPill({ text, tone }: { text: string; tone: "ok" | "warn" | "crit" }) {
  return <span className={`dash-pill dash-pill-${tone}`}>{text}</span>;
}

export function gaugeColor(v: number): string {
  if (v >= 80) return "var(--red)";
  if (v >= 65) return "var(--orange)";
  if (v >= 45) return "var(--amber)";
  return "var(--green)";
}

/* --------------------------------------------------------------------------
   Polar helpers for circular gauges
   -------------------------------------------------------------------------- */

function polar(cx: number, cy: number, r: number, angleDeg: number) {
  const rad = ((angleDeg - 90) * Math.PI) / 180;
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

function arcPath(cx: number, cy: number, r: number, a0: number, a1: number) {
  const p0 = polar(cx, cy, r, a0);
  const p1 = polar(cx, cy, r, a1);
  const large = a1 - a0 > 180 ? 1 : 0;
  return `M ${p0.x.toFixed(2)} ${p0.y.toFixed(2)} A ${r} ${r} 0 ${large} 1 ${p1.x.toFixed(2)} ${p1.y.toFixed(2)}`;
}

const DIAL_BANDS = [
  { to: 0.28, color: "var(--green)" },
  { to: 0.56, color: "var(--amber)" },
  { to: 0.78, color: "var(--orange)" },
  { to: 1, color: "var(--red)" },
];

/* --------------------------------------------------------------------------
   Circular speedometer with colored arc bands + needle
   -------------------------------------------------------------------------- */

export function RadialNeedle({
  value,
  max,
  label,
  size = 150,
  bands = DIAL_BANDS,
}: {
  value: number;
  max: number;
  label?: string;
  size?: number;
  bands?: { to: number; color: string }[];
}) {
  const cx = 100;
  const cy = 100;
  const r = 80;
  const startAngle = 135;
  const sweep = 270;
  const v = Math.max(0, Math.min(max, value));
  const frac = max ? v / max : 0;
  const needleAngle = startAngle + frac * sweep;
  const tip = polar(cx, cy, 70, needleAngle);
  const tail = polar(cx, cy, -8, needleAngle);

  let prev = startAngle;
  const arcs = bands.map((b) => {
    const a0 = prev;
    const a1 = startAngle + b.to * sweep;
    prev = a1;
    return { d: arcPath(cx, cy, r, a0, a1), color: b.color };
  });

  return (
    <div className="dash-dial" style={{ width: size }}>
      <svg width={size} height={size} viewBox="0 0 200 200" role="img" aria-label={`${v} ${label ?? ""}`}>
        <path
          d={arcPath(cx, cy, r, startAngle, startAngle + sweep)}
          fill="none"
          stroke="var(--border)"
          strokeWidth={13}
        />
        {arcs.map((a, i) => (
          <path key={i} d={a.d} fill="none" stroke={a.color} strokeWidth={11} opacity={0.85} />
        ))}
        <line x1={tail.x} y1={tail.y} x2={tip.x} y2={tip.y} stroke="#dfe6f2" strokeWidth={3} strokeLinecap="round" />
        <circle cx={cx} cy={cy} r={7} fill="#dfe6f2" />
        <circle cx={cx} cy={cy} r={3} fill="#0d1420" />
        <text x={cx} y={134} textAnchor="middle" className="dash-dial-value">
          {Math.round(v)}
        </text>
        {label ? (
          <text x={cx} y={151} textAnchor="middle" className="dash-dial-label">
            {label}
          </text>
        ) : null}
      </svg>
    </div>
  );
}

/* --------------------------------------------------------------------------
   Battery-style segmented bar (disk space, % filled)
   -------------------------------------------------------------------------- */

export function BatteryBar({
  pct,
  segs = 28,
  rows = 2,
  color,
  trackClass = "",
}: {
  pct: number;
  segs?: number;
  rows?: number;
  color?: string;
  trackClass?: string;
}) {
  const filled = Math.round((pct / 100) * segs);
  return (
    <div className={`dash-battery ${trackClass}`}>
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="dash-battery-row">
          {Array.from({ length: segs }, (_, i) => (
            <span
              key={i}
              className={`dash-battery-cell ${i < filled ? "on" : ""}`}
              style={i < filled && color ? { background: color } : undefined}
            />
          ))}
        </div>
      ))}
    </div>
  );
}

/* --------------------------------------------------------------------------
   Vertical category bars with y-axis ticks (storage breakdown)
   -------------------------------------------------------------------------- */

export function CategoryBars({
  data,
  max,
  height = 70,
}: {
  data: { label: string; value: number; color: string }[];
  max: number;
  height?: number;
}) {
  const rows = data.map((d) => ({ ...d }));
  return (
    <div style={{ width: "100%", height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} margin={{ top: 4, right: 4, left: 0, bottom: 0 }} barCategoryGap={4}>
          <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="3 3" />
          <YAxis
            domain={[0, max]}
            ticks={[0, max / 4, max / 2, (max * 3) / 4, max]}
            tickFormatter={(n: number) => String(Math.round(n))}
            tick={{ fill: "var(--text-dim)", fontSize: 9 }}
            axisLine={false}
            tickLine={false}
            width={26}
          />
          <XAxis
            dataKey="label"
            tick={{ fill: "var(--text-dim)", fontSize: 9 }}
            axisLine={false}
            tickLine={false}
            interval={0}
          />
          <Bar dataKey="value" radius={[1, 1, 0, 0]} isAnimationActive={false}>
            {rows.map((d, i) => (
              <Cell key={i} fill={d.color} opacity={0.92} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/* --------------------------------------------------------------------------
   Minimal SVG line chart with gridlines (CPU load / RAM trend)
   -------------------------------------------------------------------------- */

export function MiniLineChart({
  data,
  color,
  height = 40,
  fillOpacity = 0.25,
  strokeWidth = 1.5,
}: {
  data: number[];
  color: string;
  height?: number;
  fillOpacity?: number;
  strokeWidth?: number;
}) {
  const w = 100;
  const max = Math.max(...data) || 1;
  const min = Math.min(...data);
  const span = max - min || 1;
  const step = w / (data.length - 1);
  const pts = data.map(
    (v, i) =>
      `${(i * step).toFixed(2)},${(height - 2 - ((v - min) / span) * (height - 8)).toFixed(2)}`
  );
  const line = pts.join(" ");
  const area = `0,${height} ${line} ${w},${height}`;

  return (
    <svg
      className="dash-miniline"
      viewBox={`0 0 ${w} ${height}`}
      preserveAspectRatio="none"
      width="100%"
      height={height}
    >
      {[0.25, 0.5, 0.75].map((g) => (
        <line key={g} x1={0} y1={height * g} x2={w} y2={height * g} stroke="var(--border)" strokeDasharray="2 3" strokeWidth={0.5} />
      ))}
      <polygon points={area} fill={color} opacity={fillOpacity} />
      <polyline points={line} fill="none" stroke={color} strokeWidth={strokeWidth} vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

/* --------------------------------------------------------------------------
   Multi-line trend (network inbound/outbound, optional log scale + gridlines)
   -------------------------------------------------------------------------- */

export function MultiTrend({
  data,
  colors,
  labels,
  height = 44,
  grid = false,
}: {
  data: number[][];
  colors: string[];
  labels: string[];
  height?: number;
  grid?: boolean;
}) {
  const w = 100;
  const all = data.flat();
  const max = Math.max(...all) || 1;
  const min = Math.min(...all);
  const span = max - min || 1;
  const step = w / ((data[0]?.length ?? 1) - 1);

  return (
    <div className="dash-multitrend">
      <div>
        <svg
          className="dash-spark"
          viewBox={`0 0 ${w} ${height}`}
          preserveAspectRatio="none"
          width="100%"
          height={height}
        >
          {grid
            ? [0.25, 0.5, 0.75].map((g) => (
                <line key={g} x1={0} y1={height * g} x2={w} y2={height * g} stroke="var(--border)" strokeDasharray="2 3" strokeWidth={0.5} />
              ))
            : null}
          {data.map((series, si) => {
            const pts = series.map(
              (v, i) =>
                `${(i * step).toFixed(1)},${(height - 2 - ((v - min) / span) * (height - 6)).toFixed(1)}`
            );
            return (
              <polyline
                key={si}
                points={pts.join(" ")}
                fill="none"
                stroke={colors[si]}
                strokeWidth={1.4}
                vectorEffect="non-scaling-stroke"
              />
            );
          })}
        </svg>
      </div>
      <div className="dash-multitrend-legend">
        {labels.map((l, i) => (
          <div key={l} className="dash-multitrend-item">
            <span className="dash-seg-dot" style={{ background: colors[i] }} />
            <span>{l}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* --------------------------------------------------------------------------
   Multi-series area chart (FIM modified / created / deleted)
   -------------------------------------------------------------------------- */

export function MultiArea({
  series,
  height = 40,
}: {
  series: { data: number[]; color: string }[];
  height?: number;
}) {
  const w = 100;
  const all = series.flatMap((s) => s.data);
  const max = Math.max(...all) || 1;
  const min = Math.min(...all);
  const span = max - min || 1;

  return (
    <svg
      className="dash-multiarea"
      viewBox={`0 0 ${w} ${height}`}
      preserveAspectRatio="none"
      width="100%"
      height={height}
    >
      {series.map((s, si) => {
        const step = w / (s.data.length - 1);
        const pts = s.data.map(
          (v, i) =>
            `${(i * step).toFixed(2)},${(height - 2 - ((v - min) / span) * (height - 8)).toFixed(2)}`
        );
        const line = pts.join(" ");
        return (
          <g key={si}>
            <polygon points={`0,${height} ${line} ${w},${height}`} fill={s.color} opacity={0.12} />
            <polyline points={line} fill="none" stroke={s.color} strokeWidth={1.4} vectorEffect="non-scaling-stroke" />
          </g>
        );
      })}
    </svg>
  );
}
