import { api } from "./client";
import {
  benchmarkSummary as mockBenchmarkSummary,
  configChecks as mockConfigChecks,
  configPolicies as mockConfigPolicies,
  scaMockAgents,
  scaMockAnalyses,
  scaMockDashboard,
  scaMockDrifts,
  scaMockEvents,
  scaMockRemediations,
  scaMockScanResults,
  scaMockScans,
  type BenchmarkSummary,
  type CheckResult,
  type ConfigCheck,
  type ConfigChecksResult,
  type ConfigPolicy,
  type ScaAgent,
  type ScaAnalysis,
  type ScaDashboard,
  type ScaDriftsResult,
  type ScaEventsResult,
  type ScaRemediation,
  type ScaRemediationsResult,
  type ScaResultsResult,
  type ScaResult,
  type ScaScan,
  type ScaScansResult,
} from "../mocks/soc";
import {
  fimAgents as mockFimAgents,
  fimEvents as mockFimEvents,
  fimFiles as mockFimFiles,
  fimSummary as mockFimSummary,
  fimTimeline as mockFimTimeline,
  type FimDonutDatum,
  type FimAgentRow,
  type FimEventRow,
  type FimEventsResult,
  type FimFileRow,
  type FimSummary,
  type FimTimelinePoint,
} from "../mocks/fim";

export type {
  BenchmarkSummary,
  CheckResult,
  ConfigCheck,
  ConfigChecksResult,
  ConfigPolicy,
  FimAgentRow,
  FimDonutDatum,
  FimEventRow,
  FimEventsResult,
  FimFileRow,
  FimSummary,
  FimTimelinePoint,
  ScaAgent,
  ScaAnalysis,
  ScaDashboard,
  ScaDriftsResult,
  ScaEventsResult,
  ScaRemediation,
  ScaRemediationsResult,
  ScaResultsResult,
  ScaResult,
  ScaScan,
  ScaScansResult,
};

/** Every SCA payload carries `demo` so the UI can badge seeded/fallback data. */
export type WithDemo<T> = T & { demo: boolean };

async function withFallback<T>(primary: () => Promise<T>, fallback: () => Promise<T>): Promise<T> {
  try {
    return await primary();
  } catch {
    return fallback();
  }
}

async function withFallbackDemo<T>(primary: () => Promise<T>, fallback: () => Promise<T>): Promise<WithDemo<T>> {
  try {
    const value = await primary();
    // Prefer the backend's own `demo` flag: seeded/demo-mode data is labeled by
    // the server (SCA_DEMO_MODE), not inferred from connectivity alone.
    const demo =
      value !== null && typeof value === "object" && "demo" in value
        ? Boolean((value as { demo?: unknown }).demo)
        : false;
    return { ...value, demo };
  } catch {
    return { ...(await fallback()), demo: true };
  }
}

/** Resolve the CIS Windows 11 benchmark policy by slug (falls back to the first policy). */
async function defaultPolicy(): Promise<{ id: string; slug: string; name: string; rows_per_page: number }> {
  const policies = await api.policies();
  return policies.find((p) => p.slug === "cis-win11") ?? policies[0];
}

/* --------------------------------------------------------------------------
   Configuration Assessment
   -------------------------------------------------------------------------- */

export function benchmarkSummary(): Promise<BenchmarkSummary> {
  return withFallback(
    async () => api.policySummary((await defaultPolicy()).id, "001"),
    mockBenchmarkSummary
  );
}

export function configPolicies(): Promise<ConfigPolicy[]> {
  return withFallback(
    async () => {
      const rows = await api.policies();
      return rows.map((p) => ({ id: p.id, name: p.name, rowsPerPage: p.rows_per_page }));
    },
    mockConfigPolicies
  );
}

export function configChecks(page: number, perPage: number, search = ""): Promise<ConfigChecksResult> {
  return withFallback(
    async () => api.policyChecks((await defaultPolicy()).id, { page, perPage, search }),
    () => mockConfigChecks(page, perPage, search)
  );
}

/* --------------------------------------------------------------------------
   File Integrity Monitoring
   -------------------------------------------------------------------------- */

export function fimSummary(agentCode = "001"): Promise<FimSummary> {
  return withFallback(() => api.fimSummary(agentCode), mockFimSummary);
}

export function fimAgents(): Promise<FimAgentRow[]> {
  return withFallback(async () => api.fimAgents(), mockFimAgents);
}

export function fimTimeline(hours = 24, bucketMinutes = 30, agentCode = "001"): Promise<FimTimelinePoint[]> {
  return withFallback(
    async () => (await api.fimTimeline(hours, bucketMinutes, agentCode)).points,
    () => mockFimTimeline(hours, bucketMinutes)
  );
}

export function fimFiles(agentCode = "001"): Promise<FimFileRow[]> {
  return withFallback(
    async () => {
      const rows = await api.fimFiles("", agentCode);
      return rows.map((f) => ({
        file: f.file,
        lastModified: f.last_modified,
        user: f.user,
        userId: f.user_id,
        size: f.size,
        sha256: f.sha256,
        status: f.status,
        demo: f.demo,
      }));
    },
    mockFimFiles
  );
}

export function fimEvents(
  page: number,
  perPage: number,
  search = "",
  agentCode = "001"
): Promise<FimEventsResult> {
  return withFallback(
    async () => {
      const res = await api.fimEvents({ page, perPage, search, agentCode });
      return {
        ...res,
        demo: res.items[0]?.demo ?? false,
        items: res.items.map((e) => ({
          timestamp: e.timestamp,
          agent: e.agent,
          path: e.path,
          event: e.event as FimEventRow["event"],
          eventType: e.event_type ?? e.event,
          rule: e.rule,
          level: e.level,
          ruleId: e.rule_id,
          severity: e.severity,
          sha256: e.sha256,
          newSha256: e.new_sha256,
          oldSha256: e.old_sha256,
          oldPath: e.old_path,
          demo: e.demo,
        })),
      };
    },
    () => mockFimEvents(page, perPage, search)
  );
}

/* --------------------------------------------------------------------------
   Security Configuration Assessment (SCA)
   -------------------------------------------------------------------------- */

export function scaDashboard(): Promise<WithDemo<ScaDashboard>> {
  return withFallbackDemo(() => api.scaDashboard(), scaMockDashboard);
}

export function scaAgents(): Promise<WithDemo<ScaAgent[]>> {
  return withFallbackDemo(() => api.scaAgents(), scaMockAgents);
}

export function scaScans(
  page: number,
  perPage: number,
  status?: string
): Promise<WithDemo<ScaScansResult>> {
  return withFallbackDemo(
    () => api.scaScans({ page, perPage, status }),
    () => scaMockScans({ page, perPage, status })
  );
}

export function scaScanResults(
  scanId: string,
  page: number,
  perPage: number,
  result?: string,
  search = ""
): Promise<WithDemo<ScaResultsResult>> {
  return withFallbackDemo(
    () => api.scaScanResults(scanId, { page, perPage, result, search }),
    () => scaMockScanResults(scanId, { page, perPage, result, search })
  );
}

export function scaEvents(
  page: number,
  perPage: number,
  eventType?: string
): Promise<WithDemo<ScaEventsResult>> {
  return withFallbackDemo(
    () => api.scaEvents({ page, perPage, eventType }),
    () => scaMockEvents({ page, perPage })
  );
}

export function scaDrifts(
  page: number,
  perPage: number
): Promise<WithDemo<ScaDriftsResult>> {
  return withFallbackDemo(
    () => api.scaDrifts({ page, perPage }),
    () => scaMockDrifts({ page, perPage })
  );
}

export function scaAnalyses(): Promise<WithDemo<ScaAnalysis[]>> {
  return withFallbackDemo(() => api.scaAnalyses(), scaMockAnalyses);
}

export function scaRemediations(
  page: number,
  perPage: number,
  status?: string
): Promise<WithDemo<ScaRemediationsResult>> {
  return withFallbackDemo(
    () => api.scaRemediations({ page, perPage, status }),
    () => scaMockRemediations({ page, perPage, status })
  );
}

export function scaCreateScan(policyId: string, agentId: string): Promise<ScaScan> {
  return api.scaCreateScan(policyId, agentId);
}

export function scaAnalyzeCheck(checkResultId: string, force = false): Promise<ScaAnalysis> {
  return api.scaAnalyzeCheck(checkResultId, force);
}

export function scaRequestRemediation(checkResultId: string, description?: string): Promise<ScaRemediation> {
  return api.scaRequestRemediation(checkResultId, description);
}

export function scaApproveRemediation(id: string): Promise<ScaRemediation> {
  return api.scaApproveRemediation(id);
}

export function scaRejectRemediation(id: string): Promise<ScaRemediation> {
  return api.scaRejectRemediation(id);
}

export function scaExecuteRemediation(id: string): Promise<ScaRemediation> {
  return api.scaExecuteRemediation(id);
}
