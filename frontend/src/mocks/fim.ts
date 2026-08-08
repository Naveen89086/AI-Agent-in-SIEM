function delay<T>(value: T, ms: number): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), ms));
}

function prng(seed: number): number {
  const x = Math.sin(seed * 127.1 + 311.7) * 43758.5453;
  return x - Math.floor(x);
}

export interface FimDonutDatum {
  name: string;
  value: number;
  color: string;
}

export interface FimTimelinePoint {
  label: string;
  deleted: number;
  added: number;
  modified: number;
}

export interface FimAgentRow {
  code: string;
  name: string;
  platform: string;
  os_name: string;
  status: string;
  registry_entries: number;
  agent_id: string;
  hostname: string | null;
  ip_address: string | null;
  version: string | null;
  last_seen: string | null;
  enabled: boolean;
  demo: boolean;
}

export interface FimFileRow {
  file: string;
  lastModified: string;
  user: string;
  userId: string;
  size: number;
  sha256?: string | null;
  status?: string | null;
  demo?: boolean;
}

export interface FimEventRow {
  timestamp: string;
  agent: string;
  path: string;
  event: "added" | "modified" | "deleted";
  rule: string;
  level: number;
  ruleId: number;
  eventType?: string;
  severity?: string | null;
  sha256?: string | null;
  newSha256?: string | null;
  oldSha256?: string | null;
  oldPath?: string | null;
  demo?: boolean;
}

const REGISTRY_PATHS = [
  "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Environment",
  "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
  "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer",
  "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer",
  "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
];

const USER_DATA: FimDonutDatum[] = [
  { name: "SYSTEM", value: 4050, color: "#1976D2" },
  { name: "Administrators", value: 3110, color: "#43A047" },
  { name: "LOCAL SERVICE", value: 506, color: "#FB8C00" },
  { name: "Others", value: 433, color: "#9E9E9E" },
];

const ACTION_DATA: FimDonutDatum[] = [
  { name: "deleted", value: 401, color: "#E53935" },
  { name: "added", value: 396, color: "#1976D2" },
  { name: "modified", value: 180, color: "#FB8C00" },
];

function fileBreakdown(event: "added" | "modified" | "deleted"): FimDonutDatum[] {
  const palette: Record<FimEventRow["event"], string[]> = {
    added: ["#1976D2", "#1E88E5", "#42A5F5", "#64B5F6", "#90CAF9"],
    modified: ["#FB8C00", "#F57C00", "#FFA726", "#FFB74D", "#FFCC80"],
    deleted: ["#E53935", "#D32F2F", "#EF5350", "#E57373", "#EF9A9A"],
  };
  const base: Record<FimEventRow["event"], number[]> = {
    added: [180, 96, 74, 40, 6],
    modified: [95, 58, 14, 8, 5],
    deleted: [210, 118, 47, 20, 6],
  };
  return REGISTRY_PATHS.map((p, i) => ({
    name: p,
    value: base[event][i],
    color: palette[event][i],
  }));
}

export interface FimSummary {
  users: FimDonutDatum[];
  actions: FimDonutDatum[];
  files: {
    added: FimDonutDatum[];
    modified: FimDonutDatum[];
    deleted: FimDonutDatum[];
  };
  agent: FimAgentRow | null;
  files_count: { total: number; active: number; deleted: number };
  events_total: number;
  severity: FimDonutDatum[];
}

const SEVERITY_DATA: FimDonutDatum[] = [
  { name: "critical", value: 1, color: "#B71C1C" },
  { name: "high", value: 8, color: "#E53935" },
  { name: "medium", value: 22, color: "#FB8C00" },
  { name: "low", value: 370, color: "#1976D2" },
  { name: "info", value: 4, color: "#43A047" },
];

export function fimSummary(): Promise<FimSummary> {
  return delay(
    {
      users: USER_DATA,
      actions: ACTION_DATA,
      files: {
        added: fileBreakdown("added"),
        modified: fileBreakdown("modified"),
        deleted: fileBreakdown("deleted"),
      },
      agent: {
        code: "fim-win-live",
        name: "BEAM",
        platform: "windows",
        os_name: "Windows 11",
        status: "online",
        registry_entries: 0,
        agent_id: "2",
        hostname: "WIN-DESK-001",
        ip_address: "192.168.1.50",
        version: "1.0.0",
        last_seen: new Date().toISOString(),
        enabled: true,
        demo: true,
      },
      files_count: { total: 13, active: 11, deleted: 2 },
      events_total: 977,
      severity: SEVERITY_DATA,
    },
    400
  );
}

const MOCK_AGENTS: FimAgentRow[] = [
  {
    code: "fim-win-live",
    name: "BEAM",
    platform: "windows",
    os_name: "Windows 11",
    status: "online",
    registry_entries: 0,
    agent_id: "2",
    hostname: "WIN-DESK-001",
    ip_address: "192.168.1.50",
    version: "1.0.0",
    last_seen: new Date().toISOString(),
    enabled: true,
    demo: true,
  },
  {
    code: "001",
    name: "BEAM (001)",
    platform: "windows",
    os_name: "Windows 11",
    status: "active",
    registry_entries: 9699,
    agent_id: "1",
    hostname: null,
    ip_address: null,
    version: null,
    last_seen: null,
    enabled: true,
    demo: true,
  },
];

export function fimAgents(): Promise<FimAgentRow[]> {
  return delay(MOCK_AGENTS, 300);
}

export function fimTimeline(hours = 24, bucketMinutes = 30): Promise<FimTimelinePoint[]> {
  const buckets = Math.round((hours * 60) / bucketMinutes);
  const now = new Date();
  now.setSeconds(0, 0);
  const points: FimTimelinePoint[] = [];
  for (let i = 0; i < buckets; i++) {
    const t = new Date(now.getTime() - (buckets - 1 - i) * bucketMinutes * 60_000);
    const factor = i >= buckets - 1 ? 42 : i >= buckets - 3 ? 12 : 1;
    const base = i < buckets - 6 ? 2 : 4;
    points.push({
      label: `${String(t.getHours()).padStart(2, "0")}:${String(t.getMinutes()).padStart(2, "0")}`,
      deleted: Math.round(prng(i * 7 + 1) * base + prng(i * 3) * 6 * factor),
      added: Math.round(prng(i * 7 + 2) * base + prng(i * 5) * 6 * factor),
      modified: Math.round(prng(i * 7 + 3) * base + prng(i * 9) * 4 * factor),
    });
  }
  return delay(points, 350);
}

const FILES: FimFileRow[] = [
  { file: "C:\\Windows\\regedit.exe", lastModified: "2026-07-29T07:40:00", user: "TrustedInstaller", userId: "S-1-5-80-...", size: 577536 },
  { file: "C:\\Windows\\system.ini", lastModified: "2022-05-07T10:52:00", user: "SYSTEM", userId: "S-1-5-18", size: 219 },
  { file: "C:\\Windows\\System32\\drivers\\etc\\hosts", lastModified: "2026-05-09T17:21:00", user: "SYSTEM", userId: "S-1-5-18", size: 2707 },
  { file: "C:\\Windows\\System32\\drivers\\etc\\hosts.backup", lastModified: "2026-04-12T14:07:00", user: "Administrators", userId: "S-1-5-32-544", size: 1054 },
  { file: "C:\\Windows\\System32\\drivers\\etc\\hosts.ics", lastModified: "2026-08-05T10:56:00", user: "SYSTEM", userId: "S-1-5-18", size: 621 },
  { file: "C:\\Windows\\System32\\drivers\\etc\\hosts.rollback", lastModified: "2026-05-09T17:21:00", user: "Administrators", userId: "S-1-5-32-544", size: 2635 },
  { file: "C:\\Windows\\System32\\drivers\\etc\\lmhosts.sam", lastModified: "2024-04-01T12:54:00", user: "SYSTEM", userId: "S-1-5-18", size: 3683 },
  { file: "C:\\Windows\\System32\\drivers\\etc\\networks", lastModified: "2022-05-07T10:52:00", user: "SYSTEM", userId: "S-1-5-18", size: 407 },
  { file: "C:\\Windows\\System32\\drivers\\etc\\protocol", lastModified: "2022-05-07T10:52:00", user: "SYSTEM", userId: "S-1-5-18", size: 1358 },
  { file: "C:\\Windows\\System32\\drivers\\etc\\services", lastModified: "2022-05-07T10:52:00", user: "SYSTEM", userId: "S-1-5-18", size: 17635 },
  { file: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\...", lastModified: "2026-07-15T15:23:00", user: "TrustedInstaller", userId: "S-1-5-80-...", size: 454656 },
  { file: "C:\\Windows\\System32\\winrm.vbs", lastModified: "2024-04-01T12:52:00", user: "TrustedInstaller", userId: "S-1-5-80-...", size: 204072 },
  { file: "C:\\Windows\\win.ini", lastModified: "2022-05-07T10:52:00", user: "SYSTEM", userId: "S-1-5-18", size: 92 },
];

export const fimFiles = () => delay(FILES.map((f) => ({ ...f, demo: true })), 350);

const EVENT_RULES: Record<FimEventRow["event"], { rule: string; level: number; ruleId: number }> = {
  deleted: { rule: "Registry Key Entry Deleted.", level: 5, ruleId: 597 },
  added: { rule: "Registry Key Entry Added.", level: 6, ruleId: 596 },
  modified: { rule: "Registry Key Entry Modified.", level: 4, ruleId: 599 },
};

function buildFimEvents(): FimEventRow[] {
  const total = 977;
  const now = new Date();
  now.setMilliseconds(0);
  const events: FimEventRow[] = [];
  for (let i = 0; i < total; i++) {
    const t = new Date(now.getTime() - i * 16);
    const kind: FimEventRow["event"] = i % 5 === 1 ? "added" : i % 5 === 4 ? "modified" : "deleted";
    events.push({
      timestamp: t.toISOString(),
      agent: "BEAM",
      path: REGISTRY_PATHS[i % REGISTRY_PATHS.length],
      event: kind,
      eventType: kind,
      rule: EVENT_RULES[kind].rule,
      level: EVENT_RULES[kind].level,
      ruleId: EVENT_RULES[kind].ruleId,
      demo: true,
    });
  }
  return events;
}

const FIM_EVENTS = buildFimEvents();
export const FIM_EVENTS_TOTAL = FIM_EVENTS.length;

export interface FimEventsResult {
  items: FimEventRow[];
  total: number;
  page: number;
  perPage: number;
  totalPages: number;
  demo?: boolean;
}

export function fimEvents(page: number, perPage: number, search = ""): Promise<FimEventsResult> {
  const q = search.trim().toLowerCase();
  const filtered = FIM_EVENTS.filter(
    (e) =>
      !q ||
      e.path.toLowerCase().includes(q) ||
      e.event.includes(q) ||
      e.rule.toLowerCase().includes(q) ||
      String(e.ruleId).includes(q)
  );
  const totalPages = Math.max(1, Math.ceil(filtered.length / perPage));
  const safePage = Math.min(Math.max(1, page), totalPages);
  const start = (safePage - 1) * perPage;
  return delay(
    {
      items: filtered.slice(start, start + perPage),
      total: filtered.length,
      page: safePage,
      perPage,
      totalPages,
      demo: true,
    },
    300
  );
}
