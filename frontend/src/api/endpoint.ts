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
    return withDemo(value, demo);
  } catch {
    return withDemo(await fallback(), true);
  }
}

/**
 * Attach the `demo` flag without destroying the payload shape. Array payloads
 * (e.g. scaAgents) must stay arrays so consumers can still call `.map`.
 */
function withDemo<T>(value: T, demo: boolean): WithDemo<T> {
  if (Array.isArray(value)) {
    return Object.assign([], value, { demo }) as WithDemo<T>;
  }
  if (value !== null && typeof value === "object") {
    return { ...(value as Record<string, unknown>), demo } as WithDemo<T>;
  }
  return { demo } as WithDemo<T>;
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

/* --------------------------------------------------------------------------
   Threat Intelligence (IOC)
   -------------------------------------------------------------------------- */

export type IocDashboard = {
  agents_total: number;
  indicators_total: number;
  indicators_by_type: Record<string, number>;
  observations_total: number;
  matches_total: number;
  matches_verdicts: Record<string, number>;
  enabled: boolean;
  demo?: boolean;
};

export type IocAgentRow = {
  id: string;
  code: string;
  name: string;
  enabled: boolean;
  source_label: string;
  demo?: boolean;
};

export type IocIndicatorRow = {
  id: string;
  indicator_type: string;
  value: string;
  verdict: string;
  confidence: number;
  source: string;
  tags: string[];
  created_at: string;
  expires_at: string | null;
};

export type IocLookupResult = {
  value: string;
  indicator_type: string;
  verdict: string;
  confidence: number;
  reasons: string[];
  matches: IocIndicatorRow[];
  demo?: boolean;
};

export type IocMatchRow = {
  id: string;
  observation_id: string;
  indicator_id: string;
  indicator_type: string;
  value: string;
  verdict: string;
  confidence: number;
  source_label: string;
  matched_at: string;
  agent_code?: string;
};

export type IocObservationRow = {
  id: string;
  agent_code: string;
  observation_type: string;
  value: string;
  verdict: string;
  confidence: number;
  observed_at: string;
  source_label: string;
};

export type IocPageResult<T> = {
  items: T[];
  total: number;
  page: number;
  per_page: number;
};

export function iocDashboard(): Promise<WithDemo<IocDashboard>> {
  return withFallbackDemo(
    () => api.iocDashboard() as Promise<IocDashboard>,
    async () => ({
      agents_total: 0,
      indicators_total: 0,
      indicators_by_type: {},
      observations_total: 0,
      matches_total: 0,
      matches_verdicts: {},
      enabled: false,
    })
  );
}

export function iocAgents(): Promise<WithDemo<IocAgentRow[]>> {
  return withFallbackDemo(
    () => api.iocAgents() as Promise<IocAgentRow[]>,
    async () => [] as IocAgentRow[]
  );
}

export function iocIndicators(
  page: number,
  perPage: number,
  indicatorType?: string,
  search = ""
): Promise<WithDemo<IocPageResult<IocIndicatorRow>>> {
  return withFallbackDemo(
    async () => {
      const res = await api.iocIndicators({ page, perPage, indicatorType, search });
      return {
        items: (res.items as IocIndicatorRow[]) ?? [],
        total: res.total as number,
        page: res.page as number,
        per_page: res.per_page as number,
      };
    },
    async () => ({ items: [], total: 0, page, per_page: perPage })
  );
}

export function iocLookup(type: string, value: string): Promise<WithDemo<IocLookupResult>> {
  return withFallbackDemo(
    async () => {
      const res = await api.iocLookup(type, value);
      return {
        value: res.value as string,
        indicator_type: res.indicator_type as string,
        verdict: res.verdict as string,
        confidence: res.confidence as number,
        reasons: (res.reasons as string[]) ?? [],
        matches: (res.matches as IocIndicatorRow[]) ?? [],
      };
    },
    async () => ({
      value,
      indicator_type: type,
      verdict: "unknown",
      confidence: 0,
      reasons: ["No threat intel provider reachable (offline mode)"],
      matches: [],
    })
  );
}

export function iocMatches(
  page: number,
  perPage: number,
  verdict?: string,
  agentId?: string
): Promise<WithDemo<IocPageResult<IocMatchRow>>> {
  return withFallbackDemo(
    async () => {
      const res = await api.iocMatches({ page, perPage, verdict, agentId });
      return {
        items: (res.items as IocMatchRow[]) ?? [],
        total: res.total as number,
        page: res.page as number,
        per_page: res.per_page as number,
      };
    },
    async () => ({ items: [], total: 0, page, per_page: perPage })
  );
}

export function iocObservations(
  page: number,
  perPage: number,
  verdict?: string,
  agentId?: string
): Promise<WithDemo<IocPageResult<IocObservationRow>>> {
  return withFallbackDemo(
    async () => {
      const res = await api.iocObservations({ page, perPage, verdict, agentId });
      return {
        items: (res.items as IocObservationRow[]) ?? [],
        total: res.total as number,
        page: res.page as number,
        per_page: res.per_page as number,
      };
    },
    async () => ({ items: [], total: 0, page, per_page: perPage })
  );
}

/* --------------------------------------------------------------------------
   Threat Hunting
   -------------------------------------------------------------------------- */

export type HuntDefinition = {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: string;
  tactic: string | null;
  technique: string | null;
  queries: string[];
};

export type HuntQuery = {
  id: string;
  hunt_id: string;
  name: string;
  description: string;
  status: string;
  created_by: string;
  created_at: string;
  matched: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  analysis: Record<string, unknown> | null;
};

export type HuntMatchRow = {
  id: string;
  observation_type: string;
  value: string;
  verdict: string;
  severity: string;
  confidence: number;
  reasons: string[];
  matched_at: string;
};

export function huntDefinitions(): Promise<WithDemo<HuntDefinition[]>> {
  return withFallbackDemo(
    async () => (await api.huntDefinitions()) as HuntDefinition[],
    async () => [] as HuntDefinition[]
  );
}

export function huntQueries(
  page: number,
  perPage: number,
  huntId?: string
): Promise<WithDemo<IocPageResult<HuntQuery>>> {
  return withFallbackDemo(
    async () => {
      const res = await api.huntQueries({ page, perPage, huntId });
      return {
        items: (res.items as HuntQuery[]) ?? [],
        total: res.total as number,
        page: res.page as number,
        per_page: res.per_page as number,
      };
    },
    async () => ({ items: [], total: 0, page, per_page: perPage })
  );
}

export function huntQueryResults(
  queryId: string,
  page: number,
  perPage: number
): Promise<WithDemo<IocPageResult<HuntMatchRow>>> {
  return withFallbackDemo(
    async () => {
      const res = await api.huntQueryResults(queryId, { page, perPage });
      return {
        items: (res.items as HuntMatchRow[]) ?? [],
        total: res.total as number,
        page: res.page as number,
        per_page: res.per_page as number,
      };
    },
    async () => ({ items: [], total: 0, page, per_page: perPage })
  );
}

export function huntRun(huntId: string): Promise<HuntQuery> {
  return api.huntRun(huntId) as Promise<HuntQuery>;
}

export function huntAnalyze(queryId: string, force = false): Promise<HuntQuery> {
  return api.huntAnalyze(queryId, force) as Promise<HuntQuery>;
}

/* --------------------------------------------------------------------------
   Vulnerability Detection
   -------------------------------------------------------------------------- */

export type VulnDashboard = {
  agents_total: number;
  inventory_total: number;
  findings_total: number;
  findings_by_severity: Record<string, number>;
  findings_by_status: Record<string, number>;
  scans_total: number;
  scans_pending: number;
  cve_database: boolean;
  enabled: boolean;
  demo?: boolean;
};

export type VulnAgentRow = {
  id: string;
  code: string;
  name: string;
  platform: string;
  enabled: boolean;
  source_label: string;
  demo?: boolean;
};

export type VulnInventoryItem = {
  id: string;
  agent_id: string;
  vendor: string;
  product: string;
  version: string;
  status: string;
  cve_ids: string[];
  severity: string;
  score: number;
  demo?: boolean;
};

export type VulnScanRow = {
  id: string;
  agent_id: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  findings_total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  demo?: boolean;
};

export type VulnFindingRow = {
  id: string;
  inventory_id: string;
  cve_id: string;
  severity: string;
  score: number;
  status: string;
  description: string | null;
};

export function vulnDashboard(): Promise<WithDemo<VulnDashboard>> {
  return withFallbackDemo(
    () => api.vulnDashboard() as Promise<VulnDashboard>,
    async () => ({
      agents_total: 0,
      inventory_total: 0,
      findings_total: 0,
      findings_by_severity: {},
      findings_by_status: {},
      scans_total: 0,
      scans_pending: 0,
      cve_database: false,
      enabled: false,
    })
  );
}

export function vulnAgents(): Promise<WithDemo<VulnAgentRow[]>> {
  return withFallbackDemo(
    () => api.vulnAgents() as Promise<VulnAgentRow[]>,
    async () => [] as VulnAgentRow[]
  );
}

export function vulnInventory(agentId?: string): Promise<WithDemo<VulnInventoryItem[]>> {
  return withFallbackDemo(
    async () => (await api.vulnInventory({ agentId })) as VulnInventoryItem[],
    async () => [] as VulnInventoryItem[]
  );
}

export function vulnScans(
  page: number,
  perPage: number,
  agentId?: string
): Promise<WithDemo<IocPageResult<VulnScanRow>>> {
  return withFallbackDemo(
    async () => {
      const res = await api.vulnScans({ page, perPage, agentId });
      return {
        items: (res.items as VulnScanRow[]) ?? [],
        total: res.total as number,
        page: res.page as number,
        per_page: res.per_page as number,
      };
    },
    async () => ({ items: [], total: 0, page, per_page: perPage })
  );
}

export function vulnScanFindings(
  scanId: string,
  page: number,
  perPage: number
): Promise<WithDemo<IocPageResult<VulnFindingRow>>> {
  return withFallbackDemo(
    async () => {
      const res = await api.vulnScanFindings(scanId, { page, perPage });
      return {
        items: (res.items as VulnFindingRow[]) ?? [],
        total: res.total as number,
        page: res.page as number,
        per_page: res.per_page as number,
      };
    },
    async () => ({ items: [], total: 0, page, per_page: perPage })
  );
}

export function vulnRunScan(agentId: string): Promise<VulnScanRow> {
  return api.vulnRunScan(agentId) as Promise<VulnScanRow>;
}

/* --------------------------------------------------------------------------
   Network + Process/Service Monitoring (endpoint telemetry)
   -------------------------------------------------------------------------- */

export type TelemetryAgentRow = {
  id: string;
  agent_code: string;
  hostname: string;
  ip_address: string;
  operating_system: string;
  platform: string;
  version: string;
  status: string;
  last_seen: string | null;
  enabled: boolean;
  demo?: boolean;
};

export type NetworkConnectionRow = {
  id: string;
  agent_id: string;
  agent: string | null;
  proto: string;
  local_ip: string;
  local_port: number;
  foreign_ip: string;
  foreign_port: number;
  state: string;
  pid: number | null;
  process_name: string | null;
  user: string | null;
  executable: string | null;
  is_private: boolean;
  first_seen: string | null;
  last_seen: string | null;
  source_label: string;
  demo?: boolean;
};

export type NetworkListenerRow = {
  id: string;
  agent_id: string;
  agent: string | null;
  proto: string;
  ip: string;
  port: number;
  pid: number | null;
  process_name: string | null;
  user: string | null;
  executable: string | null;
  first_seen: string | null;
  last_seen: string | null;
  source_label: string;
  demo?: boolean;
};

export type NetworkInterfaceRow = {
  id: string;
  agent_id: string;
  agent: string | null;
  name: string;
  mac: string | null;
  addresses: string[];
  mtu: number | null;
  speed_mbps: number | null;
  status: string;
  first_seen: string | null;
  last_seen: string | null;
  source_label: string;
  demo?: boolean;
};

export type NetworkStatisticRow = {
  id: string;
  agent_id: string;
  agent: string | null;
  bytes_sent: number;
  bytes_recv: number;
  packets_sent: number;
  packets_recv: number;
  tx_kbps: number;
  rx_kbps: number;
  connections_total: number;
  listeners_total: number;
  observed_at: string | null;
  source_label: string;
  demo?: boolean;
};

export type NetworkDashboard = {
  agents_total: number;
  agents_online: number;
  connections_total: number;
  listeners_total: number;
  interfaces_total: number;
  tx_kbps: number;
  rx_kbps: number;
  bytes_sent: number;
  bytes_recv: number;
  top_processes: { name: string; count: number }[];
  interfaces: NetworkInterfaceRow[];
  demo?: boolean;
};

export type ProcessSummary = {
  agents_total: number;
  processes_running: number;
  services_total: number;
  services_running: number;
  service_changes: number;
  top_cpu: ProcessRow[];
  top_memory: ProcessRow[];
  demo?: boolean;
};

export type ProcessRow = {
  id: string;
  agent_id: string;
  agent: string | null;
  pid: number;
  name: string;
  executable: string | null;
  command_line: string | null;
  parent_pid: number | null;
  parent_name: string | null;
  user: string | null;
  cpu_percent: number;
  memory_rss_mb: number;
  threads: number | null;
  started_at: string | null;
  status: string;
  first_seen: string | null;
  last_seen: string | null;
  terminated_at: string | null;
  source_label: string;
  demo?: boolean;
  depth?: number;
};

export type ServiceRow = {
  id: string;
  agent_id: string;
  agent: string | null;
  name: string;
  display_name: string | null;
  state: string;
  start_type: string | null;
  account: string | null;
  binary_path: string | null;
  pid: number | null;
  last_event: string | null;
  first_seen: string | null;
  last_seen: string | null;
  changed_at: string | null;
  source_label: string;
  demo?: boolean;
};

const EMPTY_DASHBOARD: NetworkDashboard = {
  agents_total: 0,
  agents_online: 0,
  connections_total: 0,
  listeners_total: 0,
  interfaces_total: 0,
  tx_kbps: 0,
  rx_kbps: 0,
  bytes_sent: 0,
  bytes_recv: 0,
  top_processes: [],
  interfaces: [],
};

const EMPTY_PROCESS_SUMMARY: ProcessSummary = {
  agents_total: 0,
  processes_running: 0,
  services_total: 0,
  services_running: 0,
  service_changes: 0,
  top_cpu: [],
  top_memory: [],
};

export function telemetryAgents(): Promise<WithDemo<TelemetryAgentRow[]>> {
  return withFallbackDemo(
    () => api.telemetryAgents() as Promise<TelemetryAgentRow[]>,
    async () => [] as TelemetryAgentRow[]
  );
}

export function networkDashboard(): Promise<WithDemo<NetworkDashboard>> {
  return withFallbackDemo(
    () => api.networkDashboard() as Promise<NetworkDashboard>,
    async () => EMPTY_DASHBOARD
  );
}

export function networkConnections(
  agentId = "",
  state = "",
  search = ""
): Promise<WithDemo<NetworkConnectionRow[]>> {
  return withFallbackDemo(
    () =>
      api.networkConnections({ agentId: agentId || undefined, state: state || undefined, search }) as Promise<
        NetworkConnectionRow[]
      >,
    async () => [] as NetworkConnectionRow[]
  );
}

export function networkListening(agentId = "", search = ""): Promise<WithDemo<NetworkListenerRow[]>> {
  return withFallbackDemo(
    () => api.networkListening({ agentId: agentId || undefined, search }) as Promise<NetworkListenerRow[]>,
    async () => [] as NetworkListenerRow[]
  );
}

export function networkInterfaces(agentId = ""): Promise<WithDemo<NetworkInterfaceRow[]>> {
  return withFallbackDemo(
    () => api.networkInterfaces(agentId || undefined) as Promise<NetworkInterfaceRow[]>,
    async () => [] as NetworkInterfaceRow[]
  );
}

export function networkStatistics(agentId = ""): Promise<WithDemo<NetworkStatisticRow[]>> {
  return withFallbackDemo(
    () => api.networkStatistics(agentId || undefined) as Promise<NetworkStatisticRow[]>,
    async () => [] as NetworkStatisticRow[]
  );
}

export function processSummary(): Promise<WithDemo<ProcessSummary>> {
  return withFallbackDemo(
    () => api.processSummary() as Promise<ProcessSummary>,
    async () => EMPTY_PROCESS_SUMMARY
  );
}

export function processes(
  agentId = "",
  search = "",
  status = "running"
): Promise<WithDemo<ProcessRow[]>> {
  return withFallbackDemo(
    () => api.processes({ agentId: agentId || undefined, search, status }) as Promise<ProcessRow[]>,
    async () => [] as ProcessRow[]
  );
}

export function processTree(pid: number, agentId = ""): Promise<WithDemo<ProcessRow[]>> {
  return withFallbackDemo(
    () => api.processTree(pid, agentId || undefined) as Promise<ProcessRow[]>,
    async () => [] as ProcessRow[]
  );
}

export function services(
  agentId = "",
  search = "",
  state = ""
): Promise<WithDemo<ServiceRow[]>> {
  return withFallbackDemo(
    () => api.services({ agentId: agentId || undefined, search, state: state || undefined }) as Promise<ServiceRow[]>,
    async () => [] as ServiceRow[]
  );
}
