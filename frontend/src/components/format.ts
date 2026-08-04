export function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatDuration(totalSeconds: number | null | undefined): string {
  if (!totalSeconds) return "—";
  if (totalSeconds >= 86400) return `${Math.round(totalSeconds / 86400)}d`;
  if (totalSeconds >= 3600) return `${Math.round(totalSeconds / 3600)}h`;
  if (totalSeconds >= 60) return `${Math.round(totalSeconds / 60)}m`;
  return `${totalSeconds}s`;
}
