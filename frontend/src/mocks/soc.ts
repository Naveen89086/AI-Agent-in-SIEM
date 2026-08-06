/**
 * Mock data for the SOC dashboard sections that do not have a backend
 * endpoint yet (Endpoint Security, Threat Intelligence, Compliance,
 * MITRE heatmap, attack timeline). Each fetcher returns a Promise so the
 * widgets can render loading / empty / error states and later be swapped
 * for real `/api/v1` calls without changing their interface.
 */

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
