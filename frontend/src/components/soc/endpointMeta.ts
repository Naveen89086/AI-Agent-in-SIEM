import type { IconName } from "../icons";
import type { StatusTone } from "../../mocks/soc";

export const ENDPOINT_MODULE_ICONS: Record<string, IconName> = {
  config: "shieldCheck",
  malware: "octagon",
  fim: "copy",
  process: "activity",
  registry: "list",
  usb: "drive",
};

export const ENDPOINT_STATUS_LABEL: Record<StatusTone, { text: string; className: string }> = {
  ok: { text: "Protected", className: "status-ok" },
  warn: { text: "Attention", className: "status-warn" },
  crit: { text: "Critical", className: "status-crit" },
};

export const ENDPOINT_STATUS_COLOR: Record<StatusTone, string> = {
  ok: "var(--green)",
  warn: "var(--amber)",
  crit: "var(--red)",
};

export const ACTIVITY_OUTCOME_LABEL: Record<string, { text: string; className: string }> = {
  blocked: { text: "Blocked", className: "status-crit" },
  quarantined: { text: "Quarantined", className: "status-warn" },
  detected: { text: "Detected", className: "status-warn" },
  pending: { text: "Pending review", className: "status-warn" },
  remediated: { text: "Remediated", className: "status-ok" },
  cleared: { text: "Cleared", className: "status-ok" },
};
