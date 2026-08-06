import type { IconName } from "./components/icons";

export interface SidebarItem {
  label: string;
  icon: IconName;
  to: string;
  end?: boolean;
}

export interface SidebarGroup {
  title: string;
  items: SidebarItem[];
}

/**
 * Full enterprise navigation model for the SOC console. Items that do not
 * have a dedicated page yet route to the closest existing view so the whole
 * menu stays live.
 */
export const SIDEBAR_GROUPS: SidebarGroup[] = [
  {
    title: "Home",
    items: [{ label: "Overview", icon: "home", to: "/", end: true }],
  },
  {
    title: "Explore",
    items: [
      { label: "Discover", icon: "compass", to: "/search" },
      { label: "Dashboards", icon: "dashboard", to: "/", end: true },
      { label: "Visualizations", icon: "chart", to: "/", end: true },
      { label: "Reports", icon: "reports", to: "/reports" },
      { label: "Alerting", icon: "alerting", to: "/alerts" },
      { label: "Maps", icon: "maps", to: "/", end: true },
      { label: "Notifications", icon: "notifications", to: "/alerts" },
    ],
  },
  {
    title: "Endpoint Security",
    items: [
      { label: "Endpoint Summary", icon: "monitor", to: "/endpoint", end: true },
      { label: "Configuration Assessment", icon: "shieldCheck", to: "/endpoint/config" },
      { label: "Malware Detection", icon: "bug", to: "/endpoint/malware" },
      { label: "File Integrity Monitoring", icon: "fileSearch", to: "/endpoint/fim" },
      { label: "Process Monitoring", icon: "activity", to: "/endpoint/process" },
      { label: "Network Monitoring", icon: "network", to: "/", end: true },
      { label: "Registry Monitoring", icon: "database", to: "/endpoint/registry" },
      { label: "Windows Event Logs", icon: "scrollText", to: "/search" },
      { label: "Linux Audit Logs", icon: "terminal", to: "/search" },
      { label: "USB Device Monitoring", icon: "usb", to: "/endpoint/usb" },
      { label: "Installed Software", icon: "box", to: "/search" },
      { label: "User Activity", icon: "userRound", to: "/search" },
    ],
  },
  {
    title: "Threat Intelligence",
    items: [
      { label: "Threat Hunting", icon: "crosshair", to: "/search" },
      { label: "MITRE ATT&CK", icon: "shield", to: "/", end: true },
      { label: "IOC Management", icon: "fingerprint", to: "/search" },
      { label: "Threat Intelligence Feeds", icon: "rss", to: "/search" },
      { label: "Attack Timeline", icon: "history", to: "/", end: true },
      { label: "AI Threat Analysis", icon: "sparkles", to: "/alerts" },
      { label: "Behavioral Analysis", icon: "brain", to: "/alerts" },
    ],
  },
  {
    title: "Security Operations",
    items: [
      { label: "Alerts", icon: "alert", to: "/alerts" },
      { label: "Cases", icon: "folderOpen", to: "/cases" },
      { label: "Incident Response", icon: "shieldAlert", to: "/cases" },
      { label: "SOAR Playbooks", icon: "play", to: "/soar" },
      { label: "AI SOC Agent", icon: "bot", to: "/", end: true },
      { label: "Analyst Queue", icon: "users", to: "/alerts" },
      { label: "Investigation Timeline", icon: "history", to: "/", end: true },
      { label: "Evidence Collection", icon: "fileStack", to: "/search" },
    ],
  },
  {
    title: "Compliance",
    items: [
      { label: "PCI DSS", icon: "creditCard", to: "/reports" },
      { label: "HIPAA", icon: "heartPulse", to: "/reports" },
      { label: "GDPR", icon: "shieldCheck", to: "/reports" },
      { label: "ISO 27001", icon: "award", to: "/reports" },
      { label: "NIST 800-53", icon: "bookOpenCheck", to: "/reports" },
      { label: "CIS Benchmarks", icon: "sliders", to: "/reports" },
      { label: "SOC 2", icon: "badgeCheck", to: "/reports" },
      { label: "TSC", icon: "scale", to: "/reports" },
    ],
  },
  {
    title: "Cloud Security",
    items: [
      { label: "AWS", icon: "cloud", to: "/sources" },
      { label: "Azure", icon: "cloudy", to: "/sources" },
      { label: "Google Cloud", icon: "cloud", to: "/sources" },
      { label: "Docker", icon: "container", to: "/sources" },
      { label: "Kubernetes", icon: "boxes", to: "/sources" },
      { label: "GitHub", icon: "gitBranch", to: "/sources" },
      { label: "Microsoft 365", icon: "mail", to: "/sources" },
      { label: "Google Workspace", icon: "globe", to: "/sources" },
    ],
  },
  {
    title: "Asset Management",
    items: [
      { label: "Endpoints", icon: "monitor", to: "/endpoint", end: true },
      { label: "Servers", icon: "server", to: "/sources" },
      { label: "Network Devices", icon: "router", to: "/sources" },
      { label: "IoT Devices", icon: "cpu", to: "/sources" },
      { label: "Mobile Devices", icon: "smartphone", to: "/sources" },
      { label: "Asset Inventory", icon: "archive", to: "/sources" },
    ],
  },
  {
    title: "Agent Management",
    items: [
      { label: "Agent Overview", icon: "monitorCog", to: "/endpoint", end: true },
      { label: "Agent Groups", icon: "layers", to: "/endpoint", end: true },
      { label: "Enrollment", icon: "userPlus", to: "/endpoint", end: true },
      { label: "Updates", icon: "refresh", to: "/endpoint", end: true },
      { label: "Agent Health", icon: "heartPulse", to: "/endpoint", end: true },
      { label: "Agent Logs", icon: "scrollText", to: "/endpoint", end: true },
    ],
  },
  {
    title: "Server Management",
    items: [
      { label: "Rules", icon: "gavel", to: "/rules" },
      { label: "Decoders", icon: "braces", to: "/rules" },
      { label: "CDB Lists", icon: "list", to: "/rules" },
      { label: "Statistics", icon: "chart", to: "/", end: true },
      { label: "Cluster", icon: "network", to: "/", end: true },
      { label: "Logs", icon: "scrollText", to: "/rules" },
      { label: "Security", icon: "lock", to: "/rules" },
      { label: "Rules Tester", icon: "flaskConical", to: "/rules" },
      { label: "Dev Tools", icon: "wrench", to: "/rules" },
      { label: "Settings", icon: "settings", to: "/rules" },
    ],
  },
  {
    title: "Indexer Management",
    items: [
      { label: "Index Management", icon: "database", to: "/sources" },
      { label: "Snapshot Management", icon: "databaseBackup", to: "/sources" },
      { label: "Index Security", icon: "lockKeyhole", to: "/sources" },
      { label: "Sample Data", icon: "beaker", to: "/search" },
      { label: "Dev Tools", icon: "terminal", to: "/sources" },
    ],
  },
  {
    title: "AI Center",
    items: [
      { label: "AI Assistant", icon: "sparkles", to: "/", end: true },
      { label: "AI Incident Analysis", icon: "brainCircuit", to: "/alerts" },
      { label: "AI Chat", icon: "messageSquare", to: "/", end: true },
      { label: "Knowledge Base", icon: "bookOpen", to: "/", end: true },
      { label: "Root Cause Analysis", icon: "search", to: "/", end: true },
      { label: "AI Recommendations", icon: "lightbulb", to: "/", end: true },
      { label: "Auto Remediation", icon: "wand2", to: "/soar" },
    ],
  },
  {
    title: "Reporting",
    items: [
      { label: "Executive Reports", icon: "briefcase", to: "/reports" },
      { label: "SOC Reports", icon: "shield", to: "/reports" },
      { label: "Compliance Reports", icon: "clipboardCheck", to: "/reports" },
      { label: "Threat Reports", icon: "fileSearch", to: "/reports" },
      { label: "Export Center", icon: "download", to: "/reports" },
    ],
  },
  {
    title: "System",
    items: [
      { label: "Settings", icon: "settings", to: "/", end: true },
      { label: "User Management", icon: "userCog", to: "/alerts" },
      { label: "Roles & Permissions", icon: "keyRound", to: "/alerts" },
      { label: "Integrations", icon: "plug", to: "/sources" },
      { label: "API Keys", icon: "keyRound", to: "/alerts" },
      { label: "Audit Logs", icon: "scrollText", to: "/search" },
      { label: "System Health", icon: "activity", to: "/", end: true },
      { label: "Backup & Restore", icon: "databaseBackup", to: "/", end: true },
      { label: "About", icon: "info", to: "/", end: true },
    ],
  },
];

export const DEFAULT_OPEN_GROUPS = ["Home", "Endpoint Security", "Security Operations", "AI Center"];
