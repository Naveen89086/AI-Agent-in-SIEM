export function Sparkline({
  data,
  color,
  width = 120,
  height = 36,
}: {
  data: number[];
  color?: string;
  width?: number;
  height?: number;
}) {
  if (!data || data.length < 2) return null;
  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;
  const points = data
    .map(
      (v, i) =>
        `${((i / (data.length - 1)) * width).toFixed(1)},${(
          height -
          ((v - min) / range) * (height - 6) -
          3
        ).toFixed(1)}`
    )
    .join(" ");

  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className="soc-spark"
      aria-hidden="true"
    >
      <polyline
        points={points}
        fill="none"
        stroke={color ?? "var(--accent)"}
        strokeWidth={2}
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}
