import type { ReactNode } from "react";

function gaugeColor(value: number): string {
  if (value >= 80) return "var(--green)";
  if (value >= 60) return "var(--amber)";
  return "var(--red)";
}

export function ScoreGauge({
  value,
  size = 132,
  caption,
  footer,
}: {
  value: number;
  size?: number;
  caption?: ReactNode;
  footer?: ReactNode;
}) {
  const clamped = Math.max(0, Math.min(100, Math.round(value)));
  const radius = size / 2 - 11;
  const circumference = 2 * Math.PI * radius;
  const dash = (clamped / 100) * circumference;
  const color = gaugeColor(clamped);

  return (
    <div className="soc-gauge" style={{ width: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--border)"
          strokeWidth={11}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={11}
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circumference}`}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
        <text
          x="50%"
          y="46%"
          textAnchor="middle"
          dominantBaseline="central"
          className="soc-gauge-value"
          fill="var(--text)"
        >
          {clamped}
        </text>
        <text
          x="50%"
          y="62%"
          textAnchor="middle"
          dominantBaseline="central"
          className="soc-gauge-unit"
          fill="var(--text-faint)"
        >
          / 100
        </text>
      </svg>
      {caption ? <div className="soc-gauge-caption">{caption}</div> : null}
      {footer}
    </div>
  );
}
