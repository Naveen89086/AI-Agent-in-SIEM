/**
 * Mock data for the SOC dashboard sections that do not have a backend
 * endpoint yet (Endpoint Security, Threat Intelligence, Compliance,
 * MITRE heatmap, attack timeline). Each fetcher returns a Promise so the
 * widgets can render loading / empty / error states and later be swapped
 * for real `/api/v1` calls without changing their interface.
 */

import type { IconName } from "../components/icons";

export type Severity = "critical" | "high" | "medium" | "low" | "informational";

export type StatusTone = "ok" | "warn" | "crit";

export interface EndpointModule {
  id: string;
  name: string;
  description: string;
  status: StatusTone;
  protectedCount: number;
  totalCount: number;
  lastScan: string;
  severity: Severity;
  trend: number[];
}

export interface TiModule {
  id: string;
  name: string;
  description: string;
  stat: string;
  delta: string;
  deltaTone: "up" | "down" | "flat";
  trend: number[];
}

export interface ComplianceItem {
  id: string;
  name: string;
  status: "pass" | "warn" | "fail";
  score: number;
  checksPassed: number;
  totalChecks: number;
}

export interface MitreCell {
  tactic: string;
  count: number;
  intensity: 0 | 1 | 2 | 3 | 4;
}

export interface AttackEvent {
  time: string;
  title: string;
  severity: Severity;
  tactic: string;
  source: string;
}

export interface MetricNote {
  count: number;
  last24h: number;
  status: StatusTone;
  detail: string;
}

export interface SecurityOpsModule {
  id: string;
  name: string;
  description: string;
  icon: IconName;
}

export type ActivityOutcome =
  | "blocked"
  | "quarantined"
  | "detected"
  | "remediated"
  | "pending"
  | "cleared";

export interface ModuleActivity {
  id: string;
  time: string;
  title: string;
  message: string;
  asset: string;
  severity: Severity;
  outcome: ActivityOutcome;
  technique: string;
}

export interface ModuleActivitySeed {
  title: string;
  message: string;
  asset: string;
  severity: Severity;
  outcome: ActivityOutcome;
  technique: string;
  minutesAgo: number;
}

export const MODULE_ACTIVITIES: Record<string, ModuleActivitySeed[]> = {
  malware: [
    { title: "YARA match: CobaltStrike.dll", message: "In-memory beacon payload matched 3 YARA rules (MZ header + encrypted config).", asset: "DC-01", severity: "critical", outcome: "blocked", technique: "T1055", minutesAgo: 6 },
    { title: "Signature hit: Emotet dropper", message: "Email attachment md5 9f2a…c11 matched Emotet loader signature.", asset: "webmail01", severity: "critical", outcome: "quarantined", technique: "T1204", minutesAgo: 14 },
    { title: "Behavioral: process hollowing", message: "svchost.exe spawned unknown region with RWX memory protections.", asset: "DC-01", severity: "high", outcome: "blocked", technique: "T1055.012", minutesAgo: 31 },
    { title: "YARA match: Mimikatz strings", message: "lsass access + mimikatz import strings observed on workstation.", asset: "workstn-14", severity: "high", outcome: "detected", technique: "T1003.001", minutesAgo: 52 },
    { title: "Ransomware encryption spike", message: "1,200+ distinct file write operations with .locked extension in 60s.", asset: "workstn-14", severity: "critical", outcome: "blocked", technique: "T1486", minutesAgo: 78 },
    { title: "Beaconing: periodic C2 callbacks", message: "Identical 45s heartbeat to 45.155.205.44:443 over 4 hours.", asset: "DC-01", severity: "high", outcome: "detected", technique: "T1071.001", minutesAgo: 133 },
    { title: "Signed binary abuse: msiexec", message: "msiexec.exe /quiet dropped a temporary .dll under AppData.", asset: "workstn-07", severity: "medium", outcome: "detected", technique: "T1218.007", minutesAgo: 205 },
    { title: "Quarantine eviction complete", message: "Threat removed from 2 endpoints; scan re-run clean.", asset: "agent-group", severity: "low", outcome: "remediated", technique: "T1059", minutesAgo: 340 },
  ],
  config: [
    { title: "Policy drift: password aging", message: "MaximumPasswordAge changed to 999 against CIS baseline (max 60).", asset: "DC-01", severity: "high", outcome: "pending", technique: "T1548", minutesAgo: 11 },
    { title: "Insecure default: SMBv1 enabled", message: "SMBv1 still enabled on file-srv-03 despite hardening baseline.", asset: "file-srv-03", severity: "high", outcome: "detected", technique: "T1110", minutesAgo: 42 },
    { title: "Non-compliant firewall rule", message: "Windows firewall allows inbound RDP (3389) from any source.", asset: "workstn-21", severity: "medium", outcome: "pending", technique: "T1021.001", minutesAgo: 97 },
    { title: "Audit policy disabled", message: "Advanced audit for Logon/Logoff turned off on backup server.", asset: "backup-01", severity: "medium", outcome: "detected", technique: "T1562.002", minutesAgo: 156 },
    { title: "Baseline re-scan completed", message: "52 agents re-evaluated; 4 deviations remain (2 auto-remediated).", asset: "agent-group", severity: "low", outcome: "remediated", technique: "T1498", minutesAgo: 289 },
  ],
  fim: [
    { title: "Checksum change: sshd_config", message: "File modified; hash changed from sha256:41e… to sha256:9b3… .", asset: "webserver01", severity: "high", outcome: "pending", technique: "T1543", minutesAgo: 9 },
    { title: "New file: /etc/systemd/timers", message: "Untracked unit file created in systemd timer directory.", asset: "webserver01", severity: "high", outcome: "detected", technique: "T1053.003", minutesAgo: 38 },
    { title: "Binary replaced: /usr/bin/curl", message: "curl replaced; new binary unsigned and 2.1x larger.", asset: "webserver01", severity: "critical", outcome: "blocked", technique: "T1072", minutesAgo: 73 },
    { title: "Deleted file: shadow.tmp", message: "Shadow copy temp file removed from sensitive directory.", asset: "DC-01", severity: "medium", outcome: "detected", technique: "T1485", minutesAgo: 121 },
    { title: "Integrity restore: curl", message: "Baseline binary restored from vendor repository.", asset: "webserver01", severity: "low", outcome: "remediated", technique: "T1072", minutesAgo: 186 },
  ],
  process: [
    { title: "Anomalous child: cmd.exe → powershell", message: "Powershell started from cmd with encoded -EncodedCommand flag.", asset: "DC-01", severity: "high", outcome: "blocked", technique: "T1059.001", minutesAgo: 5 },
    { title: "LOLBins: wmic process call", message: "wmic.exe used to spawn a process remotely.", asset: "workstn-14", severity: "high", outcome: "detected", technique: "T1047", minutesAgo: 27 },
    { title: "Unsigned driver load", message: "Kernel driver with invalid signature loaded on endpoint.", asset: "workstn-21", severity: "critical", outcome: "blocked", technique: "T1543.003", minutesAgo: 66 },
    { title: "Run-as admin from browser", message: "Elevated token requested by browser child process.", asset: "workstn-07", severity: "medium", outcome: "detected", technique: "T1134", minutesAgo: 148 },
    { title: "Process list baseline drift", message: "3 new persistent processes observed vs 7-day baseline.", asset: "agent-group", severity: "low", outcome: "cleared", technique: "T1059", minutesAgo: 320 },
  ],
  registry: [
    { title: "Autostart added: HKLM RunOnce", message: "RunOnce entry pointing to %TEMP%\\svc.exe added.", asset: "workstn-14", severity: "critical", outcome: "blocked", technique: "T1547.001", minutesAgo: 16 },
    { title: "Service modified: EventLog", message: "EventLog service ImagePath rewritten to suspicious path.", asset: "DC-01", severity: "high", outcome: "detected", technique: "T1543.003", minutesAgo: 55 },
    { title: "Scheduled task created", message: "schtasks registered task 'Updater' running hourly.", asset: "workstn-07", severity: "high", outcome: "detected", technique: "T1053.005", minutesAgo: 104 },
    { title: "Debugger key set for svchost", message: "Image File Execution Options debugger value added.", asset: "workstn-21", severity: "medium", outcome: "pending", technique: "T1546.012", minutesAgo: 177 },
    { title: "Startup folder populated", message: "New .lnk shortcut in user Startup folder.", asset: "workstn-07", severity: "low", outcome: "cleared", technique: "T1547.001", minutesAgo: 262 },
  ],
  usb: [
    { title: "Mass storage connected", message: "Kingston 32GB (VID_0951) mounted; write access allowed by policy.", asset: "workstn-14", severity: "medium", outcome: "detected", technique: "T1091", minutesAgo: 22 },
    { title: "Unknown vendor device", message: "USB device with unsigned VID rejected per allowlist policy.", asset: "workstn-21", severity: "high", outcome: "blocked", technique: "T1091", minutesAgo: 69 },
    { title: "Bulk copy event", message: "3.8GB copied to removable media in under 2 minutes.", asset: "workstn-14", severity: "high", outcome: "detected", technique: "T1039", minutesAgo: 131 },
    { title: "Device removal without eject", message: "Storage device unplugged without safe-eject; audit flagged.", asset: "workstn-14", severity: "low", outcome: "cleared", technique: "T1091", minutesAgo: 240 },
  ],
};

export const ENDPOINT_MODULES: EndpointModule[] = [
  {
    id: "config",
    name: "Configuration Assessment",
    description: "Security policy checks against CIS baselines",
    status: "ok",
    protectedCount: 48,
    totalCount: 52,
    lastScan: "12 min ago",
    severity: "high",
    trend: [42, 45, 44, 47, 46, 48, 48],
  },
  {
    id: "malware",
    name: "Malware Detection",
    description: "Signature + behavioral detection across agents",
    status: "warn",
    protectedCount: 3,
    totalCount: 52,
    lastScan: "8 min ago",
    severity: "critical",
    trend: [1, 2, 1, 2, 3, 2, 3],
  },
  {
    id: "fim",
    name: "File Integrity Monitoring",
    description: "Real-time checksum verification on key paths",
    status: "ok",
    protectedCount: 1_284,
    totalCount: 1_412,
    lastScan: "5 min ago",
    severity: "medium",
    trend: [1180, 1205, 1222, 1240, 1255, 1271, 1284],
  },
  {
    id: "process",
    name: "Process Monitoring",
    description: "Anomalous process & binary execution events",
    status: "warn",
    protectedCount: 9,
    totalCount: 52,
    lastScan: "10 min ago",
    severity: "high",
    trend: [4, 5, 4, 6, 7, 6, 9],
  },
  {
    id: "registry",
    name: "Registry Monitoring",
    description: "Persistent key & autostart modification alerts",
    status: "ok",
    protectedCount: 6,
    totalCount: 52,
    lastScan: "11 min ago",
    severity: "medium",
    trend: [2, 2, 3, 2, 3, 4, 6],
  },
  {
    id: "usb",
    name: "USB Monitoring",
    description: "Removable media connect & copy events",
    status: "ok",
    protectedCount: 1,
    totalCount: 52,
    lastScan: "14 min ago",
    severity: "low",
    trend: [0, 0, 1, 0, 0, 1, 1],
  },
];

export const TI_MODULES: TiModule[] = [
  {
    id: "hunting",
    name: "Threat Hunting",
    description: "Proactive hunt queries over the last 7 days",
    stat: "1,284",
    delta: "+12% this week",
    deltaTone: "up",
    trend: [900, 980, 1020, 1090, 1140, 1210, 1284],
  },
  {
    id: "vuln",
    name: "Vulnerability Detection",
    description: "New CVEs mapped against running software",
    stat: "37",
    delta: "5 new CVEs",
    deltaTone: "up",
    trend: [20, 24, 22, 28, 30, 33, 37],
  },
  {
    id: "ioc",
    name: "IOC Lookup",
    description: "Indicator hits across all ingested events",
    stat: "96%",
    delta: "hit-rate 94→96%",
    deltaTone: "up",
    trend: [88, 89, 91, 90, 93, 95, 96],
  },
  {
    id: "mitre",
    name: "MITRE ATT&CK",
    description: "Techniques mapped across detection content",
    stat: "14",
    delta: "tactics covered",
    deltaTone: "flat",
    trend: [10, 11, 11, 12, 13, 13, 14],
  },
  {
    id: "feed",
    name: "Threat Feed",
    description: "IOCs ingested from external feeds",
    stat: "2,451",
    delta: "+340 today",
    deltaTone: "up",
    trend: [1500, 1650, 1780, 1920, 2100, 2240, 2451],
  },
  {
    id: "geo",
    name: "Geo Intelligence",
    description: "Countries with observed malicious activity",
    stat: "38",
    delta: "+3 countries",
    deltaTone: "up",
    trend: [30, 31, 31, 33, 34, 36, 38],
  },
];

export const COMPLIANCE: ComplianceItem[] = [
  { id: "nist", name: "NIST 800-53", status: "pass", score: 92, checksPassed: 184, totalChecks: 200 },
  { id: "pci", name: "PCI DSS", status: "warn", score: 84, checksPassed: 42, totalChecks: 50 },
  { id: "hipaa", name: "HIPAA", status: "warn", score: 78, checksPassed: 31, totalChecks: 40 },
  { id: "iso", name: "ISO 27001", status: "pass", score: 88, checksPassed: 114, totalChecks: 130 },
  { id: "gdpr", name: "GDPR", status: "warn", score: 81, checksPassed: 41, totalChecks: 51 },
  { id: "cis", name: "CIS Benchmark", status: "warn", score: 74, checksPassed: 192, totalChecks: 260 },
];

export const MITRE_HEATMAP: MitreCell[] = [
  { tactic: "Initial Access", count: 24, intensity: 3 },
  { tactic: "Execution", count: 11, intensity: 2 },
  { tactic: "Persistence", count: 8, intensity: 1 },
  { tactic: "Privilege Escalation", count: 31, intensity: 4 },
  { tactic: "Defense Evasion", count: 5, intensity: 1 },
  { tactic: "Credential Access", count: 42, intensity: 4 },
  { tactic: "Discovery", count: 17, intensity: 2 },
  { tactic: "Lateral Movement", count: 6, intensity: 1 },
  { tactic: "Collection", count: 3, intensity: 0 },
  { tactic: "Exfiltration", count: 2, intensity: 0 },
  { tactic: "C2", count: 9, intensity: 1 },
];

export const ATTACK_TIMELINE: AttackEvent[] = [
  { time: "14:32:01", title: "SSH brute-force from 185.220.101.7", severity: "high", tactic: "Credential Access", source: "185.220.101.7" },
  { time: "14:18:44", title: "Web admin brute-force on /admin/login", severity: "medium", tactic: "Initial Access", source: "91.240.118.33" },
  { time: "13:57:12", title: "Sudo privilege escalation by wheel group", severity: "critical", tactic: "Privilege Escalation", source: "10.0.0.17" },
  { time: "13:40:05", title: "Firewall port scan across 1,024 ports", severity: "medium", tactic: "Discovery", source: "45.155.205.44" },
  { time: "13:12:57", title: "New local user account created", severity: "low", tactic: "Persistence", source: "10.0.0.17" },
];

export const ML_ANOMALIES: MetricNote = {
  count: 3,
  last24h: 3,
  status: "warn",
  detail: "3 events exceeded Isolation Forest threshold (±2.5σ)",
};

export const TI_MATCHES: MetricNote = {
  count: 12,
  last24h: 12,
  status: "warn",
  detail: "12 events matched threat-intel feeds (4 sources)",
};

export const SAMPLE_RECOMMENDED_ACTIONS = [
  "Isolate the affected asset from the network.",
  "Rotate credentials for the compromised account.",
  "Block the source IP at the firewall edge.",
  "Collect full process tree and memory image for forensics.",
];

export const SECURITY_OPS_MODULES: SecurityOpsModule[] = [
  {
    id: "hygiene",
    name: "IT Hygiene",
    icon: "clipboardCheck",
    description:
      "Assess system, software, processes, and network layers to detect misconfigurations, unauthorized changes, and anomalies.",
  },
  {
    id: "pci",
    name: "PCI DSS",
    icon: "creditCard",
    description:
      "Global security standard for entities that process, store, or transmit payment cardholder data.",
  },
  {
    id: "gdpr",
    name: "GDPR",
    icon: "shieldCheck",
    description:
      "General Data Protection Regulation (GDPR) sets guidelines for processing of personal data.",
  },
  {
    id: "hipaa",
    name: "HIPAA",
    icon: "heartPulse",
    description:
      "Health Insurance Portability and Accountability Act of 1996 (HIPAA) provides data privacy and security provisions for safeguarding medical information.",
  },
  {
    id: "nist",
    name: "NIST 800-53",
    icon: "bookOpenCheck",
    description:
      "National Institute of Standards and Technology Special Publication 800-53 (NIST 800-53) sets guidelines for federal information systems.",
  },
  {
    id: "tsc",
    name: "TSC",
    icon: "scale",
    description:
      "Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy.",
  },
];

function delay<T>(data: T, ms = 400): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(data), ms));
}

export const endpointModules = () => delay(ENDPOINT_MODULES);
export const threatIntelModules = () => delay(TI_MODULES);
export const complianceItems = () => delay(COMPLIANCE);
export const mitreHeatmap = () => delay(MITRE_HEATMAP);
export const attackTimeline = () => delay(ATTACK_TIMELINE);
export const mlAnomalies = () => delay(ML_ANOMALIES);
export const tiMatches = () => delay(TI_MATCHES);
export const securityOpsModules = () => delay(SECURITY_OPS_MODULES);

export function moduleActivities(moduleId: string): Promise<ModuleActivity[]> {
  const seeds = MODULE_ACTIVITIES[moduleId];
  if (!seeds) return delay([]);
  const items: ModuleActivity[] = seeds.map((seed, i) => ({
    id: `${moduleId}-${i}`,
    time: new Date(Date.now() - seed.minutesAgo * 60_000).toISOString(),
    title: seed.title,
    message: seed.message,
    asset: seed.asset,
    severity: seed.severity,
    outcome: seed.outcome,
    technique: seed.technique,
  }));
  return delay(items, 500);
}

/* ==========================================================================
   Configuration Assessment (CIS benchmark dashboard)
   ========================================================================== */

export type CheckResult = "passed" | "failed" | "not_applicable";

export interface ConfigCheck {
  id: number;
  title: string;
  target: string;
  result: CheckResult;
  severity: string;
  category: string;
}

export interface ConfigPolicy {
  id: string;
  name: string;
  rowsPerPage: number;
}

export interface BenchmarkSummary {
  policy: string;
  passed: number;
  failed: number;
  not_applicable: number;
  score: number;
  end_scan: string;
  total_checks: number;
}

const CHECK_POOL: { title: string; target: string }[] = [
  { title: "Enforce password history", target: "net.exe accounts" },
  { title: "Maximum password age", target: "net.exe accounts" },
  { title: "Minimum password age", target: "net.exe accounts" },
  { title: "Minimum password length", target: "net.exe accounts" },
  { title: "Relax minimum password length limits", target: "Registry" },
  { title: "Account lockout duration", target: "net.exe accounts" },
  { title: "Account lockout threshold", target: "net.exe accounts" },
  { title: "Reset account lockout counter", target: "net.exe accounts" },
  { title: "Block Microsoft accounts", target: "Registry" },
  { title: "Guest account status", target: "net user guest" },
  { title: "Store passwords using reversible encryption", target: "net.exe accounts" },
  { title: "Do not allow anonymous enumeration of SAM accounts", target: "Registry" },
  { title: "Do not allow anonymous enumeration of SAM accounts and shares", target: "Registry" },
  { title: "Restrict anonymous access to named pipes and shares", target: "Registry" },
  { title: "Mapped drives are not shared to all sessions", target: "Registry" },
  { title: "Allow network access to the computer to be restricted", target: "Registry" },
  { title: "Administrator account status", target: "net user Administrator" },
  { title: "Audit account logon events", target: "Auditpol.exe" },
  { title: "Audit account management", target: "Auditpol.exe" },
  { title: "Audit detailed file share", target: "Auditpol.exe" },
  { title: "Audit file share", target: "Auditpol.exe" },
  { title: "Audit logoff", target: "Auditpol.exe" },
  { title: "Audit logon", target: "Auditpol.exe" },
  { title: "Audit policy change", target: "Auditpol.exe" },
  { title: "Audit privilege use", target: "Auditpol.exe" },
  { title: "Audit process creation", target: "Auditpol.exe" },
  { title: "Audit system events", target: "Auditpol.exe" },
  { title: "Network security: minimum session security for NTLM SSP", target: "Registry" },
  { title: "Network security: LAN Manager authentication level", target: "Registry" },
  { title: "Interactive logon: Do not display last user name", target: "Registry" },
  { title: "Interactive logon: Machine inactivity limit", target: "Registry" },
  { title: "Interactive logon: Message text for users attempting to log on", target: "Registry" },
  { title: "User Account Control: Admin Approval Mode", target: "Registry" },
  { title: "User Account Control: Run all administrators in Admin Approval Mode", target: "Registry" },
  { title: "User Account Control: Only elevate UIAccess applications", target: "Registry" },
  { title: "Windows Defender: Turn on real-time protection", target: "PowerShell" },
  { title: "Windows Defender: Turn on cloud-delivered protection", target: "PowerShell" },
  { title: "Windows Defender: Scan all downloaded files and attachments", target: "PowerShell" },
  { title: "Windows Firewall: Domain profile state", target: "Registry" },
  { title: "Windows Firewall: Private profile state", target: "Registry" },
  { title: "Windows Firewall: Public profile state", target: "Registry" },
  { title: "BitLocker: Require additional authentication at startup", target: "Registry" },
  { title: "BitLocker: Encrypt fixed data drives", target: "PowerShell" },
  { title: "Credential Guard: Enable virtualization-based security", target: "Registry" },
  { title: "Remote Desktop: Require Network Level Authentication", target: "Registry" },
  { title: "SMB: Configure SMB v1 client driver", target: "Registry" },
  { title: "SMB: Enable insecure guest logons", target: "Registry" },
  { title: "PowerShell: Enable script block logging", target: "Registry" },
  { title: "PowerShell: Enable transcription", target: "Registry" },
  { title: "Windows Update: Configure automatic updates", target: "Registry" },
  { title: "DNS Client: Configure DNS over HTTPS", target: "PowerShell" },
];

const SEVERITY_CYCLE = ["critical", "high", "medium", "low", "informational"];

function buildConfigChecks(): ConfigCheck[] {
  const checks: ConfigCheck[] = [];
  for (let i = 0; i < 481; i++) {
    const def = CHECK_POOL[i % CHECK_POOL.length];
    let result: CheckResult = i % 4 === 3 ? "passed" : "failed";
    if (i === 12 || i === 24 || i === 36 || i === 48 || i === 60 || i === 72) {
      result = "not_applicable";
    }
    checks.push({
      id: 26000 + i,
      title: def.title,
      target: def.target,
      result,
      severity: SEVERITY_CYCLE[i % SEVERITY_CYCLE.length],
      category: def.target.includes("Registry") ? "Registry" : "Security Option",
    });
  }
  return checks;
}

export const CONFIG_CHECKS: ConfigCheck[] = buildConfigChecks();

export const CONFIG_POLICIES: ConfigPolicy[] = [
  { id: "cis-win11", name: "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0", rowsPerPage: 15 },
  { id: "cis-win10", name: "CIS Microsoft Windows 10 Enterprise Benchmark v2.0.0", rowsPerPage: 15 },
  { id: "cis-ubuntu", name: "CIS Ubuntu 22.04 LTS Benchmark v2.0.0", rowsPerPage: 15 },
];

export function benchmarkSummary(): Promise<BenchmarkSummary> {
  const passed = CONFIG_CHECKS.filter((c) => c.result === "passed").length;
  const failed = CONFIG_CHECKS.filter((c) => c.result === "failed").length;
  const not_applicable = CONFIG_CHECKS.filter((c) => c.result === "not_applicable").length;
  const total = CONFIG_CHECKS.length;
  return delay(
    {
      policy: "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0",
      passed,
      failed,
      not_applicable,
      score: Math.round((passed / total) * 100),
      end_scan: new Date().toISOString(),
      total_checks: total,
    },
    400
  );
}

export const configPolicies = () => delay(CONFIG_POLICIES, 300);

export interface ConfigChecksResult {
  items: ConfigCheck[];
  total: number;
  page: number;
  perPage: number;
  totalPages: number;
}

export function configChecks(
  page: number,
  perPage: number,
  search = ""
): Promise<ConfigChecksResult> {
  const q = search.trim().toLowerCase();
  const filtered = CONFIG_CHECKS.filter(
    (c) => !q || String(c.id).includes(q) || c.title.toLowerCase().includes(q) || c.target.toLowerCase().includes(q)
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
    },
    300
  );
}

/* ==========================================================================
   Security Configuration Assessment (SCA) - scan engine results
   ========================================================================== */

export type ScaAgentStatus = "online" | "offline" | "unknown";

export interface ScaAgent {
  id: string;
  agent_code: string;
  hostname: string;
  operating_system: string;
  platform: string;
  version: string;
  status: ScaAgentStatus;
  last_seen: string;
  enabled: boolean;
  scans: number;
}

export interface ScaScaTopFailure {
  id: string;
  check_id: string;
  title: string;
  severity: string;
  category: string;
  failures: number;
  risk: number;
}

export interface ScaScaEvent {
  id: string;
  event_type: string;
  agent_id: string | null;
  agent: string | null;
  policy_id: string | null;
  policy: string | null;
  scan_id: string | null;
  check_id: string | null;
  severity: string;
  message: string;
  payload: Record<string, unknown> | null;
  occurred_at: string;
}

export interface ScaDashboard {
  agents_total: number;
  agents_online: number;
  policies_active: number;
  scans_total: number;
  checks_total: number;
  checks_passed: number;
  checks_failed: number;
  checks_not_applicable: number;
  average_score: number;
  average_risk: number;
  events_today: number;
  drift_total: number;
  pending_remediation: number;
  top_failures: ScaScaTopFailure[];
  risk_distribution: { critical: number; high: number; medium: number; low: number };
  latest_events: ScaScaEvent[];
}

export interface ScaScan {
  id: string;
  policy_id: string;
  policy: string;
  policy_version: string;
  agent_id: string;
  agent: string;
  status: string;
  started_at: string | null;
  end_scan: string | null;
  total_checks: number;
  passed: number;
  failed: number;
  not_applicable: number;
  error_count: number;
  score: number;
  risk_score: number;
  critical_failures: number;
  high_failures: number;
  medium_failures: number;
  low_failures: number;
  duration: number;
  error_message: string | null;
  created_at: string;
}

export interface ScaResult {
  id: string;
  scan_id: string;
  check_id: string;
  check_result_id: string;
  title: string;
  target: string;
  category: string;
  severity: string;
  result: CheckResult | "error";
  expected_value: string | null;
  actual_value: string | null;
  evidence: Record<string, unknown> | null;
  error_message: string | null;
  executed_at: string;
}

export interface ScaDrift {
  id: string;
  agent_id: string;
  agent: string | null;
  policy_id: string;
  check_id: string;
  title: string | null;
  previous_result: string;
  current_result: string;
  previous_value: string | null;
  current_value: string | null;
  detected_at: string;
  severity: string;
  description: string;
}

export interface ScaAnalysis {
  id: string;
  kind: string;
  reference_id: string;
  provider: string;
  analysis: string;
  summary: string;
  recommended_actions: string[] | null;
  risk_score: number;
  confidence: number;
  extra: Record<string, unknown> | null;
  created_at: string;
}

export interface ScaRemediation {
  id: string;
  check_id: string;
  check_title: string | null;
  agent_id: string;
  agent: string | null;
  action_type: string;
  description: string | null;
  requested_by: string;
  approved_by: string | null;
  status: string;
  result: string | null;
  executed_at: string | null;
  created_at: string;
}

export interface ScaScansResult {
  items: ScaScan[];
  total: number;
  page: number;
  perPage: number;
  totalPages: number;
}

export interface ScaResultsResult {
  items: ScaResult[];
  total: number;
  page: number;
  perPage: number;
  totalPages: number;
}

export interface ScaEventsResult {
  items: ScaScaEvent[];
  total: number;
  page: number;
  perPage: number;
  totalPages: number;
}

export interface ScaDriftsResult {
  items: ScaDrift[];
  total: number;
  page: number;
  perPage: number;
  totalPages: number;
}

export interface ScaRemediationsResult {
  items: ScaRemediation[];
  total: number;
  page: number;
  perPage: number;
  totalPages: number;
}

const SCA_AGENTS: ScaAgent[] = [
  {
    id: "a-001",
    agent_code: "001",
    hostname: "BEAM",
    operating_system: "Windows 11 Enterprise",
    platform: "windows",
    version: "1.0.0",
    status: "online",
    last_seen: new Date(Date.now() - 1000 * 60 * 2).toISOString(),
    enabled: true,
    scans: 4,
  },
  {
    id: "a-002",
    agent_code: "002",
    hostname: "BEAM-2",
    operating_system: "Windows 11 Enterprise",
    platform: "windows",
    version: "1.0.0",
    status: "online",
    last_seen: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
    enabled: true,
    scans: 3,
  },
  {
    id: "a-003",
    agent_code: "003",
    hostname: "BEAM-3",
    operating_system: "Windows 11 Pro",
    platform: "windows",
    version: "1.0.0",
    status: "offline",
    last_seen: new Date(Date.now() - 1000 * 60 * 60 * 3).toISOString(),
    enabled: true,
    scans: 2,
  },
];

const SCA_POLICY_NAME = "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0";

function scaScan(
  id: string,
  agent: ScaAgent,
  passed: number,
  failed: number,
  na: number,
  minutesAgo: number,
  extra = {},
): ScaScan {
  const total = passed + failed + na;
  const score = passed + failed === 0 ? 0 : Math.round((passed / (passed + failed)) * 100);
  return {
    id,
    policy_id: "cis-win11",
    policy: SCA_POLICY_NAME,
    policy_version: "v3.0.0",
    agent_id: agent.id,
    agent: `${agent.hostname} (${agent.agent_code})`,
    status: "completed",
    started_at: new Date(Date.now() - 1000 * 60 * (minutesAgo + 1)).toISOString(),
    end_scan: new Date(Date.now() - 1000 * 60 * minutesAgo).toISOString(),
    total_checks: total,
    passed,
    failed,
    not_applicable: na,
    error_count: 0,
    score,
    risk_score: Math.min(100, Math.round((failed * 6) / total)),
    critical_failures: Math.round(failed * 0.15),
    high_failures: Math.round(failed * 0.45),
    medium_failures: Math.round(failed * 0.3),
    low_failures: Math.round(failed * 0.1),
    duration: 8.4,
    error_message: null,
    created_at: new Date(Date.now() - 1000 * 60 * (minutesAgo + 2)).toISOString(),
    ...extra,
  };
}

const SCA_SCANS: ScaScan[] = [
  scaScan("s-001", SCA_AGENTS[0], 120, 355, 6, 25),
  scaScan("s-002", SCA_AGENTS[1], 205, 270, 6, 60),
  scaScan("s-003", SCA_AGENTS[2], 96, 379, 6, 95),
  scaScan("s-004", SCA_AGENTS[0], 118, 357, 6, 130),
  scaScan("s-005", SCA_AGENTS[1], 210, 265, 6, 200),
  scaScan("s-006", SCA_AGENTS[0], 121, 354, 6, 260),
];

const SCA_EVENTS: ScaScaEvent[] = [
  { id: "ev-01", event_type: "scan_completed", agent_id: SCA_AGENTS[0].id, agent: "BEAM (001)", policy_id: "cis-win11", policy: SCA_POLICY_NAME, scan_id: "s-001", check_id: null, severity: "info", message: "Scan completed for CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 on BEAM: 120 passed, 355 failed, 6 n/a", payload: { passed: 120, failed: 355, score: 25 }, occurred_at: new Date(Date.now() - 1000 * 60 * 25).toISOString() },
  { id: "ev-02", event_type: "critical_check_failed", agent_id: SCA_AGENTS[0].id, agent: "BEAM (001)", policy_id: "cis-win11", policy: SCA_POLICY_NAME, scan_id: "s-001", check_id: null, severity: "critical", message: "53 critical check(s) failed", payload: null, occurred_at: new Date(Date.now() - 1000 * 60 * 25).toISOString() },
  { id: "ev-03", event_type: "scan_completed", agent_id: SCA_AGENTS[1].id, agent: "BEAM-2 (002)", policy_id: "cis-win11", policy: SCA_POLICY_NAME, scan_id: "s-002", check_id: null, severity: "info", message: "Scan completed for CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 on BEAM-2: 205 passed, 270 failed, 6 n/a", payload: { passed: 205, failed: 270, score: 43 }, occurred_at: new Date(Date.now() - 1000 * 60 * 60).toISOString() },
  { id: "ev-04", event_type: "configuration_changed", agent_id: SCA_AGENTS[0].id, agent: "BEAM (001)", policy_id: "cis-win11", policy: SCA_POLICY_NAME, scan_id: "s-004", check_id: "26018", severity: "high", message: "check outcome changed passed -> failed", payload: null, occurred_at: new Date(Date.now() - 1000 * 60 * 130).toISOString() },
  { id: "ev-05", event_type: "agent_offline", agent_id: SCA_AGENTS[2].id, agent: "BEAM-3 (003)", policy_id: null, policy: null, scan_id: null, check_id: null, severity: "high", message: "Agent 'BEAM-3' went offline", payload: null, occurred_at: new Date(Date.now() - 1000 * 60 * 180).toISOString() },
  { id: "ev-06", event_type: "scan_completed", agent_id: SCA_AGENTS[2].id, agent: "BEAM-3 (003)", policy_id: "cis-win11", policy: SCA_POLICY_NAME, scan_id: "s-003", check_id: null, severity: "info", message: "Scan completed for CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 on BEAM-3: 96 passed, 379 failed, 6 n/a", payload: { passed: 96, failed: 379, score: 20 }, occurred_at: new Date(Date.now() - 1000 * 60 * 95).toISOString() },
  { id: "ev-07", event_type: "configuration_changed", agent_id: SCA_AGENTS[1].id, agent: "BEAM-2 (002)", policy_id: "cis-win11", policy: SCA_POLICY_NAME, scan_id: "s-005", check_id: "26014", severity: "medium", message: "check outcome changed failed -> passed", payload: null, occurred_at: new Date(Date.now() - 1000 * 60 * 200).toISOString() },
];

const SCA_DRIFTS: ScaDrift[] = [
  { id: "d-01", agent_id: SCA_AGENTS[0].id, agent: "BEAM (001)", policy_id: "cis-win11", check_id: "26018", title: "Audit account logon events", previous_result: "passed", current_result: "failed", previous_value: "Enabled", current_value: "Disabled", detected_at: new Date(Date.now() - 1000 * 60 * 130).toISOString(), severity: "high", description: "check outcome changed from passed to failed between scans" },
  { id: "d-02", agent_id: SCA_AGENTS[1].id, agent: "BEAM-2 (002)", policy_id: "cis-win11", check_id: "26014", title: "SMB: Enable insecure guest logons", previous_result: "failed", current_result: "passed", previous_value: "Disabled", current_value: "Enabled", detected_at: new Date(Date.now() - 1000 * 60 * 200).toISOString(), severity: "medium", description: "check outcome changed from failed to passed between scans" },
  { id: "d-03", agent_id: SCA_AGENTS[0].id, agent: "BEAM (001)", policy_id: "cis-win11", check_id: "26001", title: "Enforce password history", previous_result: "passed", current_result: "failed", previous_value: "Enabled", current_value: "Disabled", detected_at: new Date(Date.now() - 1000 * 60 * 260).toISOString(), severity: "high", description: "check outcome changed from passed to failed between scans" },
];

const SCA_ANALYSES: ScaAnalysis[] = [
  {
    id: "an-01",
    kind: "sca_check_analysis",
    reference_id: "r-0001",
    provider: "heuristic",
    analysis: "Audit account logon events is disabled on BEAM (001) while the CIS benchmark requires it to be enabled.",
    summary: "Audit account logon events – failed (high).",
    recommended_actions: ["Enable 'Audit account logon events' via auditpol", "Verify with a verification scan"],
    risk_score: 7.5,
    confidence: 0.85,
    extra: { priority: 3, severity: "high", result: "failed", category: "Audit" },
    created_at: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
  },
];

const SCA_REMEDIATIONS: ScaRemediation[] = [
  {
    id: "rem-01",
    check_id: "26018",
    check_title: "Audit account logon events",
    agent_id: SCA_AGENTS[0].id,
    agent: "BEAM (001)",
    action_type: "apply_benchmark_setting",
    description: "Enable 'Audit account logon events'",
    requested_by: "analyst",
    approved_by: "admin",
    status: "completed",
    result: "demo: remediation applied for the requested setting",
    executed_at: new Date(Date.now() - 1000 * 60 * 100).toISOString(),
    created_at: new Date(Date.now() - 1000 * 60 * 110).toISOString(),
  },
  {
    id: "rem-02",
    check_id: "26014",
    check_title: "SMB: Enable insecure guest logons",
    agent_id: SCA_AGENTS[1].id,
    agent: "BEAM-2 (002)",
    action_type: "apply_benchmark_setting",
    description: "Disable insecure SMB guest logons",
    requested_by: "analyst",
    approved_by: null,
    status: "pending",
    result: null,
    executed_at: null,
    created_at: new Date(Date.now() - 1000 * 60 * 20).toISOString(),
  },
];

function pageSlice<T>(items: T[], page: number, perPage: number) {
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const safePage = Math.min(Math.max(1, page), totalPages);
  const start = (safePage - 1) * perPage;
  return { items: items.slice(start, start + perPage), total: items.length, page: safePage, perPage, totalPages };
}

export const scaMockDashboard = (): Promise<ScaDashboard> => {
  const completed = SCA_SCANS;
  const totalChecks = completed.reduce((n, s) => n + s.total_checks, 0);
  const totalPassed = completed.reduce((n, s) => n + s.passed, 0);
  const totalFailed = completed.reduce((n, s) => n + s.failed, 0);
  const totalNa = completed.reduce((n, s) => n + s.not_applicable, 0);
  return delay(
    {
      agents_total: SCA_AGENTS.length,
      agents_online: SCA_AGENTS.filter((a) => a.status === "online").length,
      policies_active: 3,
      scans_total: completed.length,
      checks_total: totalChecks,
      checks_passed: totalPassed,
      checks_failed: totalFailed,
      checks_not_applicable: totalNa,
      average_score: Math.round(completed.reduce((n, s) => n + s.score, 0) / completed.length),
      average_risk: Math.round(completed.reduce((n, s) => n + s.risk_score, 0) / completed.length),
      events_today: 6,
      drift_total: SCA_DRIFTS.length,
      pending_remediation: SCA_REMEDIATIONS.filter((r) => r.status === "pending").length,
      top_failures: [
        { id: "c-01", check_id: "26018", title: "Audit account logon events", severity: "high", category: "Audit", failures: 3, risk: 6 },
        { id: "c-02", check_id: "26001", title: "Enforce password history", severity: "high", category: "Account Policies", failures: 3, risk: 6 },
        { id: "c-03", check_id: "26046", title: "SMB: Enable insecure guest logons", severity: "medium", category: "SMB", failures: 2, risk: 3 },
      ],
      risk_distribution: { critical: 1, high: 1, medium: 1, low: 0 },
      latest_events: SCA_EVENTS.slice(0, 6),
    },
    400
  );
};

export const scaMockAgents = () => delay(SCA_AGENTS, 300);

export const scaMockScans = (params: { page?: number; perPage?: number; status?: string } = {}) =>
  delay(pageSlice(SCA_SCANS, params.page ?? 1, params.perPage ?? 20), 300);

export const scaMockEvents = (params: { page?: number; perPage?: number } = {}) =>
  delay(pageSlice(SCA_EVENTS, params.page ?? 1, params.perPage ?? 20), 300);

export const scaMockDrifts = (params: { page?: number; perPage?: number } = {}) =>
  delay(pageSlice(SCA_DRIFTS, params.page ?? 1, params.perPage ?? 20), 300);

export const scaMockRemediations = (params: { page?: number; perPage?: number; status?: string } = {}) => {
  const filtered = params.status ? SCA_REMEDIATIONS.filter((r) => r.status === params.status) : SCA_REMEDIATIONS;
  return delay(pageSlice(filtered, params.page ?? 1, params.perPage ?? 20), 300);
};

export const scaMockAnalyses = () => delay(SCA_ANALYSES, 300);

export const scaMockScanDetail = (scanId: string): Promise<ScaScan | null> =>
  delay(SCA_SCANS.find((s) => s.id === scanId) ?? null, 250);

export const scaMockScanResults = (scanId: string, params: { page?: number; perPage?: number; result?: string; search?: string } = {}) => {
  const scan = SCA_SCANS.find((s) => s.id === scanId);
  const items: ScaResult[] = scan
    ? Array.from({ length: scan.failed }, (_, i) => ({
        id: `r-${scanId}-${i}`,
        scan_id: scanId,
        check_id: String(26000 + (i % 50)),
        check_result_id: `r-${scanId}-${i}`,
        title: CONFIG_CHECKS[(i % 50)].title,
        target: CONFIG_CHECKS[(i % 50)].target,
        category: "Configuration",
        severity: i % 4 === 0 ? "critical" : i % 3 === 0 ? "high" : i % 2 === 0 ? "medium" : "low",
        result: "failed",
        expected_value: "Enabled",
        actual_value: "Disabled",
        evidence: { source: "Demo collector" },
        error_message: null,
        executed_at: scan.end_scan ?? new Date().toISOString(),
      }))
    : [];
  const filtered = params.result ? items.filter((r) => r.result === params.result) : items;
  return delay(pageSlice(filtered, params.page ?? 1, params.perPage ?? 20), 250);
};


