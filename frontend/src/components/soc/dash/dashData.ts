/* ==========================================================================
   Home dashboard (single-endpoint monitoring console) — data layer.
   Real API values are wired in DashboardPage via useAsync; everything here
   is a deterministic fallback so the dense console renders instantly and
   the numbers stay stable between reloads.
   ========================================================================== */

export const PALETTE = {
  blue: "#2F80ED",
  cyan: "#35C6E8",
  purple: "#A875FF",
  amber: "#F2C94C",
  green: "#27D17F",
  red: "#FF4D5F",
  orange: "#F2994A",
  teal: "#2DD4BF",
} as const;

function prng(seed: number): number {
  const x = Math.sin(seed * 127.1 + 311.7) * 43758.5453;
  return x - Math.floor(x);
}

/** Deterministic pseudo-random trend, 24 points by default ("multi-24"). */
export function genTrend(points = 24, base: number, variance: number, finalBump = 0): number[] {
  const out: number[] = [];
  for (let i = 0; i < points; i++) {
    let v = base + (prng(i * 7 + 3) - 0.5) * variance * 2;
    if (i === points - 1) v += finalBump;
    out.push(Math.max(0, Math.round(v)));
  }
  return out;
}

export function compact(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1).replace(/\.0$/, "")}K`;
  return String(n);
}

export function formatInt(n: number): string {
  return n.toLocaleString("en-US");
}

/* --------------------------------------------------------------------------
   Endpoint
   -------------------------------------------------------------------------- */

export interface EndpointInfo {
  name: string;
  os: string;
  status: string;
  code: string;
  ip: string | null;
}

export const FALLBACK_ENDPOINT: EndpointInfo = {
  name: "BEAM",
  os: "Windows 11",
  status: "online",
  code: "001",
  ip: "192.168.1.10",
};

/* --------------------------------------------------------------------------
   Risk
   -------------------------------------------------------------------------- */

export interface RiskBreakdownSegment {
  label: string;
  value: number;
  color: string;
}

export const FALLBACK_RISK_SCORE = 51;

export const FALLBACK_RISK_BREAKDOWN: RiskBreakdownSegment[] = [
  { label: "Endpoint", value: 30, color: PALETTE.blue },
  { label: "Network", value: 25, color: PALETTE.red },
  { label: "File Integrity", value: 15, color: PALETTE.orange },
  { label: "Configuration", value: 20, color: PALETTE.green },
  { label: "Identity", value: 10, color: PALETTE.cyan },
];

export function riskLabel(score: number): "LOW" | "MEDIUM" | "HIGH" {
  if (score >= 65) return "HIGH";
  if (score >= 35) return "MEDIUM";
  return "LOW";
}

/* --------------------------------------------------------------------------
   System performance
   -------------------------------------------------------------------------- */

export interface DiskCategory {
  label: string;
  value: number;
  color: string;
}

export interface SystemPerf {
  cpu: number;
  cpuMax: number;
  cpuTrend: number[];
  cpuLoadMax: number;
  diskPct: number;
  diskUsed: string;
  diskTotal: string;
  diskCategories: DiskCategory[];
  ram: number;
  ramTrend: number[];
  dial: number;
  dialMax: number;
}

export const FALLBACK_SYSTEM_PERF: SystemPerf = {
  cpu: 38,
  cpuMax: 140,
  cpuTrend: genTrend(24, 24, 6, 54),
  cpuLoadMax: 80,
  diskPct: 94,
  diskUsed: "2.1 TB",
  diskTotal: "2.2 TB",
  diskCategories: [
    { label: "DB", value: 900, color: PALETTE.red },
    { label: "DB", value: 620, color: PALETTE.teal },
    { label: "Logs", value: 430, color: PALETTE.teal },
    { label: "Media", value: 290, color: PALETTE.blue },
  ],
  ram: 87,
  ramTrend: [66, 68, 70, 72, 75, 77, 79, 81, 82, 84, 86, 87],
  dial: 160,
  dialMax: 200,
};

/* --------------------------------------------------------------------------
   Network activity
   -------------------------------------------------------------------------- */

export interface NetworkActivity {
  throughput: number;
  netMax: number;
  peak: number;
  utilPct: number;
  connections: number;
  inbound: number;
  outbound: number;
  trend: number[];
  inTrend: number[];
  outTrend: number[];
}

export const FALLBACK_NETWORK: NetworkActivity = {
  throughput: 32,
  netMax: 100,
  peak: 80,
  utilPct: 90,
  connections: 64,
  inbound: 24,
  outbound: 8,
  trend: genTrend(24, 26, 16, 6),
  inTrend: [24, 82, 45, 160, 96, 430, 210, 640, 90, 1200, 480, 260, 88, 190, 780, 1500, 360, 520, 110, 64, 420, 980, 240, 720],
  outTrend: genTrend(24, 6, 4, 2),
};

/* --------------------------------------------------------------------------
   Event ingestion
   -------------------------------------------------------------------------- */

export interface EventIngestion {
  eps: number;
  today: number;
  trend: number[];
}

export const FALLBACK_INGESTION: EventIngestion = {
  eps: 28,
  today: 1_100_000,
  trend: genTrend(24, 1200, 380, 90),
};

/* --------------------------------------------------------------------------
   Network connections table
   -------------------------------------------------------------------------- */

export interface NetworkConnRow {
  remote: string;
  destPort: number;
  state: "ESTABLISHED" | "BLOCKED";
  notes: string;
}

export const FALLBACK_CONNECTIONS: NetworkConnRow[] = [
  { remote: "20.52.76.89", destPort: 443, state: "ESTABLISHED", notes: "HTTPS" },
  { remote: "151.101.1.140", destPort: 443, state: "ESTABLISHED", notes: "HTTPS" },
  { remote: "192.168.1.53", destPort: 53, state: "ESTABLISHED", notes: "DNS" },
  { remote: "91.240.118.33", destPort: 445, state: "BLOCKED", notes: "SMB" },
];

/* --------------------------------------------------------------------------
   File integrity monitoring
   -------------------------------------------------------------------------- */

export interface FimState {
  monitored: number;
  modified: number;
  created: number;
  deleted: number;
  critical: number;
  modifiedTrend: number[];
  createdTrend: number[];
  deletedTrend: number[];
}

export const FALLBACK_FIM: FimState = {
  monitored: 1284,
  modified: 8,
  created: 5,
  deleted: 2,
  critical: 1,
  modifiedTrend: genTrend(24, 7, 7, 3),
  createdTrend: genTrend(24, 4, 4, 1),
  deletedTrend: genTrend(24, 2, 2, 1),
};

/* --------------------------------------------------------------------------
   Security posture
   -------------------------------------------------------------------------- */

export interface PostureScore {
  label: string;
  value: number;
}

export type PostureTone = "ok" | "warn" | "crit" | "info";

export interface PostureRow {
  label: string;
  value: string;
  tone: PostureTone;
}

export interface Posture {
  overall: string;
  rows: PostureRow[];
}

export const FALLBACK_POSTURE: Posture = {
  overall: "78%",
  rows: [
    { label: "Overall Score", value: "78%", tone: "ok" },
    { label: "Configuration", value: "82%", tone: "ok" },
    { label: "Patch", value: "94%", tone: "ok" },
    { label: "Vulnerabilities", value: "71%", tone: "warn" },
    { label: "Malware Protection", value: "86%", tone: "ok" },
    { label: "Failed Checks", value: "18", tone: "warn" },
    { label: "Critical CVEs", value: "2", tone: "crit" },
  ],
};

/* --------------------------------------------------------------------------
   User & login activity
   -------------------------------------------------------------------------- */

export interface UserLogin {
  user: string;
  lastLogin: string;
  outcome: "SUCCESS" | "FAILED";
  source: string;
  failed: number;
}

export const FALLBACK_LOGIN: UserLogin = {
  user: "BEAM\\User1",
  lastLogin: "12:45 PM",
  outcome: "SUCCESS",
  source: "192.168.1.10",
  failed: 3,
};

/* --------------------------------------------------------------------------
   Severity alert cards
   -------------------------------------------------------------------------- */

export interface SeverityCount {
  severity: "critical" | "high" | "medium" | "low";
  count: number;
  desc: string;
}

export const FALLBACK_SEVERITY: SeverityCount[] = [
  { severity: "critical", count: 11, desc: "Critical threats" },
  { severity: "high", count: 35, desc: "Immediate action" },
  { severity: "medium", count: 24, desc: "Medium risks" },
  { severity: "low", count: 7, desc: "Low-level risks" },
];

/* --------------------------------------------------------------------------
   AI security analyst
   -------------------------------------------------------------------------- */

export interface AiAnalyst {
  kind: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  confidence: number;
  summary: string;
  updatedAt: string;
}

export const FALLBACK_AI: AiAnalyst = {
  kind: "POWERSHELL · T1059.001",
  title: "Suspicious PowerShell Activity",
  severity: "HIGH",
  confidence: 91,
  summary: "Unusual PowerShell execution detected.",
  updatedAt: "UPDATED 2m AGO",
};

/* --------------------------------------------------------------------------
   Security activity timeline (last 24h, horizontal SIEM view)
   -------------------------------------------------------------------------- */

export type TimelineType = "critical" | "high" | "fim" | "network" | "auth" | "malware";

export interface TimelineEvent {
  hour: number;
  type: TimelineType;
  label: string;
}

export const TIMELINE_TYPES: { type: TimelineType; label: string; color: string }[] = [
  { type: "critical", label: "CRITICAL", color: PALETTE.red },
  { type: "high", label: "HIGH", color: PALETTE.orange },
  { type: "fim", label: "FIM", color: PALETTE.teal },
  { type: "network", label: "NETWORK", color: PALETTE.cyan },
  { type: "auth", label: "AUTH", color: PALETTE.blue },
  { type: "malware", label: "MALWARE", color: PALETTE.purple },
];

export const FALLBACK_TIMELINE: TimelineEvent[] = [
  { hour: 0.9, type: "auth", label: "BEAM\\User1 logon" },
  { hour: 1.3, type: "malware", label: "Emotet dropper signature hit" },
  { hour: 2.2, type: "fim", label: "Registry key modified" },
  { hour: 3.5, type: "malware", label: "YARA match: CobaltStrike.dll" },
  { hour: 4.6, type: "network", label: "Port scan across 1,024 ports" },
  { hour: 5.3, type: "high", label: "Privilege escalation attempt" },
  { hour: 5.9, type: "auth", label: "Brute-force on BEAM\\User1" },
  { hour: 6.8, type: "malware", label: "Process hollowing in svchost.exe" },
  { hour: 7.4, type: "fim", label: "Binary replaced: regedit.exe" },
  { hour: 8.2, type: "critical", label: "Ransomware encryption spike" },
  { hour: 9.2, type: "network", label: "Connection to suspicious host blu3s0ck" },
  { hour: 10.1, type: "high", label: "Lsass access via Mimikatz" },
  { hour: 11.2, type: "auth", label: "Failed logon ×3" },
  { hour: 12.0, type: "fim", label: "hosts file checksum change" },
  { hour: 13.4, type: "network", label: "Outbound beacon 45.155.205.44:4444" },
  { hour: 14.6, type: "high", label: "Unsigned driver load" },
  { hour: 15.7, type: "auth", label: "Admin logon from 192.168.1.10" },
  { hour: 16.8, type: "fim", label: "RunOnce autostart added" },
  { hour: 17.9, type: "network", label: "SMBv1 negotiation from 91.240.118.33" },
  { hour: 19.3, type: "high", label: "Encoded PowerShell download-cradle" },
  { hour: 20.4, type: "auth", label: "RDP logon success" },
  { hour: 21.5, type: "fim", label: "Service ImagePath rewritten" },
  { hour: 22.3, type: "network", label: "Blocked RDP brute-force attempt" },
  { hour: 23.6, type: "auth", label: "Password change audit" },
];
