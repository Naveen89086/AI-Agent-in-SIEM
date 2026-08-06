export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

export function severityRank(severity?: string | null): number {
  return SEVERITY_ORDER[severity ?? "informational"] ?? 5;
}
