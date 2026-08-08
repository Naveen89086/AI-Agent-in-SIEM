"""Deterministic seed data for the syscheck (FIM) and SCA modules.

Demo mode only (see ``SCA_DEMO_MODE``). Seeded once on startup when the
tables are empty so the FIM dashboard, inventory, events and the SCA dashboard
are fully backed by the database instead of frontend-only mocks. All data is
reproducible (fixed seeds) which keeps tests and drift demos stable.

An enrichment pass upgrades pre-existing policy rows (created before the SCA
engine) with the new metadata, rules and compliance references without
destroying them.
"""

import random
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.sca import (
    Agent,
    CheckResult,
    CheckRule,
    ComplianceReference,
    Policy,
    PolicyCheck,
    PolicyScan,
)
from app.models.syscheck import SyscheckAgent, SyscheckEvent, SyscheckFile
# --------------------------------------------------------------------------
# Constants (mirror the Wazuh reference screenshots)
# --------------------------------------------------------------------------

REGISTRY_PATHS = [
    "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Environment",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer",
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer",
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
]

EVENT_RULES = {
    "deleted": ("Registry Key Entry Deleted.", 5, 597),
    "added": ("Registry Key Entry Added.", 6, 596),
    "modified": ("Registry Key Entry Modified.", 4, 599),
}

# (user, weight) matching the "Most active users" reference distribution.
USER_WEIGHTS = [
    ("SYSTEM", 50.0),
    ("Administrators", 38.39),
    ("LOCAL SERVICE", 6.25),
    ("Others", 5.36),
]

# (event, weight) matching the "Actions" reference distribution.
ACTION_WEIGHTS = [
    ("deleted", 41.04),
    ("added", 40.53),
    ("modified", 18.42),
]

FILES = [
    ("C:\\Windows\\regedit.exe", datetime(2026, 7, 29, 7, 40), "TrustedInstaller", "S-1-5-80-...", 577536),
    ("C:\\Windows\\system.ini", datetime(2022, 5, 7, 10, 52), "SYSTEM", "S-1-5-18", 219),
    ("C:\\Windows\\System32\\drivers\\etc\\hosts", datetime(2026, 5, 9, 17, 21), "SYSTEM", "S-1-5-18", 2707),
    ("C:\\Windows\\System32\\drivers\\etc\\hosts.backup", datetime(2026, 4, 12, 14, 7), "Administrators", "S-1-5-32-544", 1054),
    ("C:\\Windows\\System32\\drivers\\etc\\hosts.ics", datetime(2026, 8, 5, 10, 56), "SYSTEM", "S-1-5-18", 621),
    ("C:\\Windows\\System32\\drivers\\etc\\hosts.rollback", datetime(2026, 5, 9, 17, 21), "Administrators", "S-1-5-32-544", 2635),
    ("C:\\Windows\\System32\\drivers\\etc\\lmhosts.sam", datetime(2024, 4, 1, 12, 54), "SYSTEM", "S-1-5-18", 3683),
    ("C:\\Windows\\System32\\drivers\\etc\\networks", datetime(2022, 5, 7, 10, 52), "SYSTEM", "S-1-5-18", 407),
    ("C:\\Windows\\System32\\drivers\\etc\\protocol", datetime(2022, 5, 7, 10, 52), "SYSTEM", "S-1-5-18", 1358),
    ("C:\\Windows\\System32\\drivers\\etc\\services", datetime(2022, 5, 7, 10, 52), "SYSTEM", "S-1-5-18", 17635),
    ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", datetime(2026, 7, 15, 15, 23), "TrustedInstaller", "S-1-5-80-...", 454656),
    ("C:\\Windows\\System32\\winrm.vbs", datetime(2024, 4, 1, 12, 52), "TrustedInstaller", "S-1-5-80-...", 204072),
    ("C:\\Windows\\win.ini", datetime(2022, 5, 7, 10, 52), "SYSTEM", "S-1-5-18", 92),
]

# (title, target) pool used to build the 481 checks per CIS policy.
CHECK_POOL = [
    ("Enforce password history", "net.exe accounts"),
    ("Maximum password age", "net.exe accounts"),
    ("Minimum password age", "net.exe accounts"),
    ("Minimum password length", "net.exe accounts"),
    ("Relax minimum password length limits", "Registry"),
    ("Account lockout duration", "net.exe accounts"),
    ("Account lockout threshold", "net.exe accounts"),
    ("Reset account lockout counter", "net.exe accounts"),
    ("Block Microsoft accounts", "Registry"),
    ("Guest account status", "net user guest"),
    ("Store passwords using reversible encryption", "net.exe accounts"),
    ("Do not allow anonymous enumeration of SAM accounts", "Registry"),
    ("Do not allow anonymous enumeration of SAM accounts and shares", "Registry"),
    ("Restrict anonymous access to named pipes and shares", "Registry"),
    ("Mapped drives are not shared to all sessions", "Registry"),
    ("Allow network access to the computer to be restricted", "Registry"),
    ("Administrator account status", "net user Administrator"),
    ("Audit account logon events", "Auditpol.exe"),
    ("Audit account management", "Auditpol.exe"),
    ("Audit detailed file share", "Auditpol.exe"),
    ("Audit file share", "Auditpol.exe"),
    ("Audit logoff", "Auditpol.exe"),
    ("Audit logon", "Auditpol.exe"),
    ("Audit policy change", "Auditpol.exe"),
    ("Audit privilege use", "Auditpol.exe"),
    ("Audit process creation", "Auditpol.exe"),
    ("Audit system events", "Auditpol.exe"),
    ("Network security: minimum session security for NTLM SSP", "Registry"),
    ("Network security: LAN Manager authentication level", "Registry"),
    ("Interactive logon: Do not display last user name", "Registry"),
    ("Interactive logon: Machine inactivity limit", "Registry"),
    ("Interactive logon: Message text for users attempting to log on", "Registry"),
    ("User Account Control: Admin Approval Mode", "Registry"),
    ("User Account Control: Run all administrators in Admin Approval Mode", "Registry"),
    ("User Account Control: Only elevate UIAccess applications", "Registry"),
    ("Windows Defender: Turn on real-time protection", "PowerShell"),
    ("Windows Defender: Turn on cloud-delivered protection", "PowerShell"),
    ("Windows Defender: Scan all downloaded files and attachments", "PowerShell"),
    ("Windows Firewall: Domain profile state", "Registry"),
    ("Windows Firewall: Private profile state", "Registry"),
    ("Windows Firewall: Public profile state", "Registry"),
    ("BitLocker: Require additional authentication at startup", "Registry"),
    ("BitLocker: Encrypt fixed data drives", "PowerShell"),
    ("Credential Guard: Enable virtualization-based security", "Registry"),
    ("Remote Desktop: Require Network Level Authentication", "Registry"),
    ("SMB: Configure SMB v1 client driver", "Registry"),
    ("SMB: Enable insecure guest logons", "Registry"),
    ("PowerShell: Enable script block logging", "Registry"),
    ("PowerShell: Enable transcription", "Registry"),
    ("Windows Update: Configure automatic updates", "Registry"),
    ("DNS Client: Configure DNS over HTTPS", "PowerShell"),
]

POLICIES = [
    {
        "slug": "cis-win11",
        "policy_id": "cis-win11",
        "name": "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0",
        "benchmark": "CIS Microsoft Windows 11 Enterprise Benchmark",
        "version": "v3.0.0",
        "platform": "windows",
        "framework": "CIS",
        "publisher": "Center for Internet Security",
    },
    {
        "slug": "cis-win10",
        "policy_id": "cis-win10",
        "name": "CIS Microsoft Windows 10 Enterprise Benchmark v2.0.0",
        "benchmark": "CIS Microsoft Windows 10 Enterprise Benchmark",
        "version": "v2.0.0",
        "platform": "windows",
        "framework": "CIS",
        "publisher": "Center for Internet Security",
    },
    {
        "slug": "cis-ubuntu",
        "policy_id": "cis-ubuntu",
        "name": "CIS Ubuntu 22.04 LTS Benchmark v2.0.0",
        "benchmark": "CIS Ubuntu 22.04 LTS Benchmark",
        "version": "v2.0.0",
        "platform": "linux",
        "framework": "CIS",
        "publisher": "Center for Internet Security",
    },
]

AGENT_SCANS = {
    "001": {"passed": 120, "failed": 355, "not_applicable": 6},
    "002": {"passed": 205, "failed": 270, "not_applicable": 6},
    "003": {"passed": 340, "failed": 135, "not_applicable": 6},
}

# Severity/category metadata for check generation (cycled over the pool).
CATEGORY_META = [
    ("Password Policy", "high", "Passwords are the primary credential for interactive logon; weak policy allows credential theft."),
    ("Password Policy", "medium", "Longer, complex passwords resist brute force and dictionary attacks."),
    ("Account Management", "medium", "Lockout thresholds slow automated password guessing."),
    ("Account Management", "low", "Reducing standing privileges limits lateral movement."),
    ("Authentication", "high", "Interactive logon settings resist pass-the-hash and credential replay."),
    ("Audit", "medium", "Auditing provides forensic visibility into account activity."),
    ("Audit", "high", "Audit policy changes help detect attacker attempts to hide."),
    ("Firewall", "critical", "A disabled firewall exposes the endpoint to unauthorized network access."),
    ("Endpoint Protection", "critical", "Real-time protection blocks malware before it can run."),
    ("Endpoint Protection", "high", "Cloud-delivered protection shares threat intel for faster response."),
    ("Remote Access", "medium", "Restricting remote access reduces the attack surface."),
    ("Network Security", "high", "Insecure network protocols can be abused for man-in-the-middle attacks."),
    ("Services", "medium", "Unnecessary services enlarge the attack surface."),
    ("Logging", "medium", "Logging is essential to detect and investigate incidents."),
    ("File Permissions", "medium", "Loose file permissions allow privilege escalation."),
]

REMEDIATION_HINTS = {
    "Password Policy": "Configure the relevant Local Security Policy setting under Security Settings > Account Policies.",
    "Authentication": "Enforce the required setting through Group Policy under Computer Configuration > Windows Settings.",
    "Audit": "Enable the required audit policy via Auditpol.exe or Advanced Audit Policy Configuration.",
    "Firewall": "Enable the Windows Firewall profile through Windows Defender Firewall.",
    "Endpoint Protection": "Enable the Microsoft Defender protection feature via policy or PowerShell.",
    "Account Management": "Adjust the account management setting in Local Security Policy.",
    "Network Security": "Configure the network security setting in Local Security Policy > Security Options.",
    "Remote Access": "Restrict the remote access setting in Local Security Policy or System Properties.",
    "Services": "Set the service startup type via Services.msc or Group Policy.",
    "Logging": "Enable the required logging configuration.",
    "File Permissions": "Correct the ACL using icacls or the file Properties dialog.",
}

NA_SET = {12, 24, 36, 48, 60, 72}

# Deterministic per-agent outcome ordering multiplier.
_AGENT_MULT = {"001": 13, "002": 37, "003": 71}

NUM_CHECKS = 481


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _weighted_choice(rng: random.Random, pairs: list[tuple[str, float]]) -> str:
    total = sum(w for _, w in pairs)
    roll = rng.uniform(0, total)
    acc = 0.0
    for label, w in pairs:
        acc += w
        if roll <= acc:
            return label
    return pairs[-1][0]


def _category_for(index: int) -> tuple[str, str, str]:
    """Deterministic (category, severity, rationale) for a check index."""
    category, severity, rationale = CATEGORY_META[index % len(CATEGORY_META)]
    return category, severity, rationale


def _remediation_for(category: str) -> str:
    return REMEDIATION_HINTS.get(category, "Apply the vendor hardening guidance for this setting.")


CHECK_ID_BASE = 26000


def _outcome_for(check_id: int, agent_code: str) -> str:
    """Deterministic PASS/FAIL/NOT_APPLICABLE for demo scans of an agent.

    Demo checks use ``check_id = CHECK_ID_BASE + index`` so NA_SET and the
    rank ordering below operate on the normalized index.
    """
    index = check_id - CHECK_ID_BASE
    if index in NA_SET:
        return "not_applicable"
    # Unknown agents (registered through the API after seeding) get the
    # default demo profile so a demo scan never crashes on them.
    passed = AGENT_SCANS.get(agent_code, AGENT_SCANS["002"])["passed"]
    mult = _AGENT_MULT.get(agent_code, 13)
    key = (index * mult) % 1000003
    # Order non-NA checks by the deterministic key; the first `passed` pass.
    rank = sum(1 for c in range(NUM_CHECKS) if c not in NA_SET and (c * mult) % 1000003 < key)
    return "passed" if rank < passed else "failed"


def _build_check_meta(check_id: int, title: str, target: str) -> dict:
    """Metadata used for both fresh seeding and enrichment of existing rows."""
    category, severity, rationale = _category_for(check_id)
    return {
        "title": title,
        "target": target,
        "category": category,
        "severity": severity,
        "description": f"{title} ({target}).",
        "rationale": rationale,
        "remediation": _remediation_for(category),
    }


# Real, executable CheckRule definitions keyed by exact CHECK_POOL title.
# These replace the synthetic rules so real-mode scans genuinely collect and
# evaluate endpoint configuration (CIS Windows benchmark, net accounts /
# auditpol / Get-MpPreference / registry). Checks without a mapping keep their
# rule row but disabled: real mode then honestly reports "no rule defined"
# instead of fabricating a PASS/FAIL.
REAL_RULES = {
    "Enforce password history": {
        "rule_type": "command", "command": "net.exe accounts",
        "pattern": r"Length of password history maintained:\s+(\d+)",
        "operator": "gte", "expected_value": "24",
    },
    "Maximum password age": {
        "rule_type": "command", "command": "net.exe accounts",
        "pattern": r"Maximum password age \(days\):\s+(\d+)",
        "operator": "lte", "expected_value": "60",
    },
    "Minimum password age": {
        "rule_type": "command", "command": "net.exe accounts",
        "pattern": r"Minimum password age \(days\):\s+(\d+)",
        "operator": "gte", "expected_value": "1",
    },
    "Minimum password length": {
        "rule_type": "command", "command": "net.exe accounts",
        "pattern": r"Minimum password length:\s+(\d+)",
        "operator": "gte", "expected_value": "14",
    },
    "Account lockout duration": {
        "rule_type": "command", "command": "net.exe accounts",
        "pattern": r"Lockout duration \(minutes\):\s+(\d+)",
        "operator": "gte", "expected_value": "15",
    },
    "Account lockout threshold": {
        "rule_type": "command", "command": "net.exe accounts",
        "pattern": r"Lockout threshold:\s+(\d+)",
        "operator": "gte", "expected_value": "5",
    },
    "Reset account lockout counter": {
        "rule_type": "command", "command": "net.exe accounts",
        "pattern": r"Lockout observation window \(minutes\):\s+(\d+)",
        "operator": "gte", "expected_value": "15",
    },
    "Store passwords using reversible encryption": {
        "rule_type": "command", "command": "net.exe accounts",
        "pattern": r"Store passwords using reversible encryption:\s*(\w+)",
        "operator": "eq", "expected_value": "disabled",
    },
    "Guest account status": {
        "rule_type": "command", "command": "net.exe user guest",
        "pattern": r"Account active\s+(Yes|No)",
        "operator": "eq", "expected_value": "No",
    },
    "Administrator account status": {
        "rule_type": "command", "command": "net.exe user Administrator",
        "pattern": r"Account active\s+(Yes|No)",
        "operator": "eq", "expected_value": "No",
    },
    "Audit account logon events": {
        "rule_type": "command", "command": "auditpol /get /category:*",
        "pattern": r"(?m)^\s*Credential Validation\s+([^\r\n]+)$",
        "operator": "eq", "expected_value": "Success and Failure",
    },
    "Audit account management": {
        "rule_type": "command", "command": "auditpol /get /category:*",
        "pattern": r"(?m)^\s*User Account Management\s+([^\r\n]+)$",
        "operator": "eq", "expected_value": "Success and Failure",
    },
    "Audit detailed file share": {
        "rule_type": "command", "command": "auditpol /get /category:*",
        "pattern": r"(?m)^\s*File Share\s+([^\r\n]+)$",
        "operator": "eq", "expected_value": "Success and Failure",
    },
    "Audit file share": {
        "rule_type": "command", "command": "auditpol /get /category:*",
        "pattern": r"(?m)^\s*File System\s+([^\r\n]+)$",
        "operator": "eq", "expected_value": "Success and Failure",
    },
    "Audit logoff": {
        "rule_type": "command", "command": "auditpol /get /category:*",
        "pattern": r"(?m)^\s*Logoff\s+([^\r\n]+)$",
        "operator": "eq", "expected_value": "Success and Failure",
    },
    "Audit logon": {
        "rule_type": "command", "command": "auditpol /get /category:*",
        "pattern": r"(?m)^\s*Logon\s+([^\r\n]+)$",
        "operator": "eq", "expected_value": "Success and Failure",
    },
    "Audit policy change": {
        "rule_type": "command", "command": "auditpol /get /category:*",
        "pattern": r"(?m)^\s*Audit Policy Change\s+([^\r\n]+)$",
        "operator": "eq", "expected_value": "Success and Failure",
    },
    "Audit privilege use": {
        "rule_type": "command", "command": "auditpol /get /category:*",
        "pattern": r"(?m)^\s*Sensitive Privilege Use\s+([^\r\n]+)$",
        "operator": "eq", "expected_value": "Success and Failure",
    },
    "Audit process creation": {
        "rule_type": "command", "command": "auditpol /get /category:*",
        "pattern": r"(?m)^\s*Process Creation\s+([^\r\n]+)$",
        "operator": "eq", "expected_value": "Success and Failure",
    },
    "Audit system events": {
        "rule_type": "command", "command": "auditpol /get /category:*",
        "pattern": r"(?m)^\s*Security State Change\s+([^\r\n]+)$",
        "operator": "eq", "expected_value": "Success and Failure",
    },
    "Windows Defender: Turn on real-time protection": {
        "rule_type": "command", "command": "powershell.exe -NoProfile -Command Get-MpPreference",
        "pattern": r"DisableRealtimeMonitoring\s*:\s*(\w+)",
        "operator": "eq", "expected_value": "False",
    },
    "Windows Defender: Turn on cloud-delivered protection": {
        "rule_type": "command", "command": "powershell.exe -NoProfile -Command Get-MpPreference",
        "pattern": r"MAPSReporting\s*:\s*(\d+)",
        "operator": "gte", "expected_value": "1",
    },
    "Windows Defender: Scan all downloaded files and attachments": {
        "rule_type": "command", "command": "powershell.exe -NoProfile -Command Get-MpPreference",
        "pattern": r"DisableIOAVProtection\s*:\s*(\w+)",
        "operator": "eq", "expected_value": "False",
    },
    "Windows Firewall: Domain profile state": {
        "rule_type": "registry",
        "registry_path": r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
        "registry_value": "EnableFirewall", "operator": "eq", "expected_value": "1",
    },
    "Windows Firewall: Private profile state": {
        "rule_type": "registry",
        "registry_path": r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile",
        "registry_value": "EnableFirewall", "operator": "eq", "expected_value": "1",
    },
    "Windows Firewall: Public profile state": {
        "rule_type": "registry",
        "registry_path": r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile",
        "registry_value": "EnableFirewall", "operator": "eq", "expected_value": "1",
    },
    "Interactive logon: Do not display last user name": {
        "rule_type": "registry",
        "registry_path": r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "registry_value": "dontdisplaylastusername", "operator": "eq", "expected_value": "1",
    },
    "User Account Control: Admin Approval Mode": {
        "rule_type": "registry",
        "registry_path": r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "registry_value": "EnableLUA", "operator": "eq", "expected_value": "1",
    },
    "Interactive logon: Machine inactivity limit": {
        "rule_type": "registry",
        "registry_path": r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "registry_value": "InactivityTimeoutSecs", "operator": "gte", "expected_value": "900",
    },
}


def _make_rule(policy_check_id: str, target: str, check_id: int, platform: str) -> CheckRule:
    """Deterministic CheckRule for a check (one rule per check for now)."""
    if target.startswith("net.exe"):
        return CheckRule(
            policy_check_id=policy_check_id,
            rule_type="command",
            target=target,
            command=target,
            operator="eq",
            expected_value="Enabled" if check_id % 2 == 0 else "15",
        )
    if target == "Auditpol.exe":
        return CheckRule(
            policy_check_id=policy_check_id,
            rule_type="command",
            target=target,
            command="auditpol /get /category:*",
            operator="contains",
            expected_value="Success and Failure",
        )
    if target == "PowerShell":
        return CheckRule(
            policy_check_id=policy_check_id,
            rule_type="command",
            target=target,
            command="powershell.exe -NoProfile -Command Get-MpPreference",
            operator="eq",
            expected_value="True",
        )
    if platform == "linux":
        return CheckRule(
            policy_check_id=policy_check_id,
            rule_type="file",
            target=target or "/etc/passwd",
            file_path=target or "/etc/passwd",
            operator="exists",
            expected_value="yes",
        )
    # registry rule
    path = REGISTRY_PATHS[check_id % len(REGISTRY_PATHS)]
    return CheckRule(
        policy_check_id=policy_check_id,
        rule_type="registry",
        target="Registry",
        registry_path=path,
        registry_value="EnableLUA",
        operator="eq",
        expected_value="1",
    )


def _make_compliance(policy_check_id: str, policy: Policy, check_id: int) -> list[ComplianceReference]:
    return [
        ComplianceReference(
            policy_check_id=policy_check_id,
            framework=policy.framework,
            control_id=f"{policy.framework} {policy.version} {check_id % 80 + 1}.{check_id % 10 + 1}",
            control_name=f"{policy.name} check {check_id}",
        )
    ]


# ---------------------------------------------------------------------------
# Syscheck (FIM)
# ---------------------------------------------------------------------------

def seed_syscheck(db: Session) -> None:
    """Seed syscheck agents, the file inventory and the event stream (demo mode only)."""
    if not settings.fim_demo_mode:
        return
    if db.execute(select(SyscheckAgent.id).limit(1)).first() is not None:
        return

    rng = random.Random(42)
    now = _utcnow()

    agents = [
        SyscheckAgent(code="001", name="BEAM", platform="windows", os_name="Windows 11 Enterprise", status="active", registry_entries=9699),
        SyscheckAgent(code="002", name="BEAM", platform="windows", os_name="Windows 11 Enterprise", status="active", registry_entries=9412),
        SyscheckAgent(code="003", name="BEAM", platform="linux", os_name="Ubuntu 22.04 LTS", status="disconnected", registry_entries=0),
    ]
    db.add_all(agents)
    db.flush()

    primary = agents[0]
    for path, modified, user, uid, size in FILES:
        db.add(
            SyscheckFile(
                agent_id=primary.id,
                file_path=path,
                last_modified=modified.replace(tzinfo=timezone.utc),
                user=user,
                user_id=uid,
                size=size,
            )
        )

    total = 977
    for i in range(total):
        event = _weighted_choice(rng, ACTION_WEIGHTS)
        user = _weighted_choice(rng, USER_WEIGHTS)
        rule, level, rule_id = EVENT_RULES[event]
        hours_ago = (rng.random() ** 3) * 24
        ts = now - timedelta(hours=hours_ago, seconds=rng.random() * 2)
        db.add(
            SyscheckEvent(
                agent_id=primary.id,
                timestamp=ts,
                path=REGISTRY_PATHS[i % len(REGISTRY_PATHS)],
                event=event,
                user=user,
                rule=rule,
                level=level,
                rule_id=rule_id,
                manager_name="kaliinux",
            )
        )
    db.flush()


# ---------------------------------------------------------------------------
# SCA agents
# ---------------------------------------------------------------------------

def seed_sca_agents(db: Session) -> None:
    """Mirror the syscheck demo agents into the SCA agent registry."""
    existing = {a.agent_code for a in db.execute(select(Agent)).scalars().all()}
    for sy in db.execute(select(SyscheckAgent).order_by(SyscheckAgent.code)).scalars().all():
        if sy.code in existing:
            continue
        db.add(
            Agent(
                agent_code=sy.code,
                hostname=sy.name,
                operating_system=sy.os_name,
                platform=sy.platform,
                version="2.0.0",
                status="online" if sy.status == "active" else "offline",
                transport_url=None,
                enabled=True,
            )
        )
    db.flush()


# ---------------------------------------------------------------------------
# Policies / checks / rules / scans
# ---------------------------------------------------------------------------

def _upsert_policy(db: Session, spec: dict) -> Policy:
    policy = db.scalar(select(Policy).where(Policy.slug == spec["slug"]))
    if policy is None:
        policy = Policy(policy_id=spec["policy_id"], slug=spec["slug"], name=spec["name"])
        db.add(policy)
        db.flush()
    policy.name = spec["name"]
    policy.policy_id = spec["policy_id"]
    policy.benchmark = spec["benchmark"]
    policy.version = spec["version"]
    policy.platform = spec["platform"]
    policy.framework = spec["framework"]
    policy.publisher = spec["publisher"]
    policy.status = "active"
    policy.enabled = True
    db.flush()
    return policy


def _enrich_or_create_checks(db: Session, policy: Policy) -> list[PolicyCheck]:
    """Create checks (fresh) or enrich existing ones (pre-existing DB)."""
    checks = list(db.execute(select(PolicyCheck).where(PolicyCheck.policy_id == policy.id)).scalars().all())
    if not checks:
        for i in range(NUM_CHECKS):
            title, target = CHECK_POOL[i % len(CHECK_POOL)]
            meta = _build_check_meta(i, title, target)
            checks.append(
                PolicyCheck(
                    policy_id=policy.id,
                    check_id=26000 + i,
                    title=title,
                    target=meta["target"],
                    description=meta["description"],
                    rationale=meta["rationale"],
                    remediation=meta["remediation"],
                    severity=meta["severity"],
                    category=meta["category"],
                    platform=policy.platform,
                    version=policy.version,
                    result=None,
                    enabled=True,
                )
            )
        db.add_all(checks)
        db.flush()
    else:
        for i, check in enumerate(checks):
            title, target = CHECK_POOL[i % len(CHECK_POOL)]
            meta = _build_check_meta(i, title, target)
            check.description = meta["description"]
            check.rationale = meta["rationale"]
            check.remediation = meta["remediation"]
            check.severity = meta["severity"]
            check.category = meta["category"]
            check.platform = policy.platform
            check.version = policy.version
            check.enabled = True
            if not check.target:
                check.target = meta["target"]
        db.flush()
    return checks


def _ensure_rules_and_refs(db: Session, policy: Policy, checks: list[PolicyCheck]) -> None:
    """Create CheckRule + ComplianceReference rows when missing, then apply the
    real (executable) rule definitions.

    Real rules are applied idempotently on every startup so pre-existing rule
    rows are upgraded to genuinely executable checks; checks without a real
    mapping keep a rule row but disabled (real mode then honestly reports
    "no rule defined for check").
    """
    has_rules = (
        db.execute(
            select(CheckRule.id)
            .where(CheckRule.policy_check_id == checks[0].id)
            .limit(1)
        ).first()
        is not None
    )
    if not has_rules:
        for check in checks:
            db.add(_make_rule(check.id, check.target, check.check_id, policy.platform))
            db.add_all(_make_compliance(check.id, policy, check.check_id))
        db.flush()
    _apply_real_rules(db, checks)


def _apply_real_rules(db: Session, checks: list[PolicyCheck]) -> None:
    """Overwrite the first rule of each check with its real definition (or
    disable it when no real definition exists)."""
    for check in checks:
        rule = db.scalar(
            select(CheckRule)
            .where(CheckRule.policy_check_id == check.id)
            .order_by(CheckRule.created_at)
            .limit(1)
        )
        spec = REAL_RULES.get(check.title)
        if spec is None:
            if rule is not None:
                rule.enabled = False
            continue
        if rule is None:
            rule = CheckRule(
                policy_check_id=check.id,
                rule_type=spec.get("rule_type", "command"),
                operator="eq",
                enabled=True,
            )
            db.add(rule)
        for key, value in spec.items():
            setattr(rule, key, value)
        rule.enabled = True
    db.flush()


def _demo_evidence(policy: Policy, check: PolicyCheck, outcome: str) -> tuple[str | None, dict]:
    """Deterministic demo evidence for a check outcome."""
    expected = "Enabled" if check.check_id % 2 == 0 else "Disabled"
    if outcome == "passed":
        actual = expected
    elif outcome == "not_applicable":
        actual = "N/A"
    else:
        actual = "Disabled" if check.check_id % 2 == 0 else "15"
    evidence = {
        "source": "Demo collector",
        "check_id": check.check_id,
        "title": check.title,
    }
    if check.target.startswith("net.exe"):
        evidence["command"] = check.target
        evidence["stdout"] = f"policy setting: {actual}"
        evidence["exit_code"] = 0
    elif check.target == "Registry" or check.target == "Auditpol.exe":
        evidence["registry_path"] = REGISTRY_PATHS[check.check_id % len(REGISTRY_PATHS)]
        evidence["registry_value"] = actual
    return actual, evidence


def _ensure_demo_scans(db: Session, policy: Policy, checks: list[PolicyCheck], agents: list[Agent]) -> None:
    """Create a completed demo PolicyScan + CheckResults for each agent.

    Pre-existing scans (created before the SCA engine) are upgraded in place:
    marked completed, given risk/severity figures and backfilled with
    CheckResults instead of being replaced.
    """
    existing = {
        scan.agent_id: scan
        for scan in db.execute(select(PolicyScan).where(PolicyScan.policy_id == policy.id)).scalars().all()
    }
    now = _utcnow()
    for agent in agents:
        counts = AGENT_SCANS.get(agent.agent_code, {"passed": 0, "failed": 0, "not_applicable": 0})
        total = counts["passed"] + counts["failed"] + counts["not_applicable"]
        score = round((counts["passed"] / (counts["passed"] + counts["failed"]) * 100)) if counts["passed"] + counts["failed"] else 0

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        outcomes = {c.check_id: _outcome_for(c.check_id, agent.agent_code) for c in checks}
        for check in checks:
            if outcomes[check.check_id] == "failed":
                severity_counts[check.severity] = severity_counts.get(check.severity, 0) + 1
        risk = _risk_from_severity(severity_counts, total)

        scan = existing.get(agent.id)
        if scan is None:
            scan = PolicyScan(policy_id=policy.id, agent_id=agent.id)
            db.add(scan)
            db.flush()
            scan.started_at = now - timedelta(minutes=40)
            scan.end_scan = now - timedelta(minutes=38)

        scan.policy_version = policy.version
        scan.status = "completed"
        scan.total_checks = total
        scan.passed = counts["passed"]
        scan.failed = counts["failed"]
        scan.not_applicable = counts["not_applicable"]
        scan.error_count = 0
        scan.score = score
        scan.risk_score = risk
        scan.critical_failures = severity_counts["critical"]
        scan.high_failures = severity_counts["high"]
        scan.medium_failures = severity_counts["medium"]
        scan.low_failures = severity_counts["low"]
        scan.duration = 118.4
        scan.error_message = None
        db.flush()

        has_results = (
            db.execute(select(CheckResult.id).where(CheckResult.scan_id == scan.id).limit(1)).first()
            is not None
        )
        if has_results:
            continue

        for check in checks:
            outcome = outcomes[check.check_id]
            actual, evidence = _demo_evidence(policy, check, outcome)
            db.add(
                CheckResult(
                    scan_id=scan.id,
                    policy_check_id=check.id,
                    agent_id=agent.id,
                    result=outcome,
                    expected_value="Enabled" if check.check_id % 2 == 0 else "Disabled",
                    actual_value=actual,
                    evidence=_json(evidence),
                    error_message=None,
                    executed_at=now - timedelta(minutes=38),
                    execution_duration=0.24,
                )
            )
    db.flush()


def _risk_from_severity(counts: dict[str, int], total_checks: int) -> int:
    """Risk = weighted failures as a fraction of the worst-case posture.

    Worst case = every check failed at critical severity (weight 10), giving
    a score normalized to 0-100 that differentiates agents.
    """
    weights = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}
    weighted = sum(counts.get(sev, 0) * weight for sev, weight in weights.items())
    if not total_checks:
        return 0
    return min(100, round(weighted * 100 / (10 * total_checks)))


def _json(value: dict) -> str:
    import json

    return json.dumps(value)


def _ensure_demo_events(db: Session) -> None:
    """Deterministic demo SCA events + configuration drift records.

    Seeded scans bypass the engine, so their scan_completed / agent / drift
    events are materialized here so the Events and Drift feeds are populated
    in demo mode. Runs only when the events table is empty.
    """
    from app.models.sca import ConfigurationDrift, ScaEvent

    if db.scalar(select(ScaEvent.id).limit(1)) is not None:
        return

    now = _utcnow()
    scans = db.execute(
        select(PolicyScan).where(PolicyScan.status == "completed")
    ).scalars().all()
    for scan in scans:
        occurred = scan.end_scan or now
        db.add(
            ScaEvent(
                event_type="scan_completed",
                agent_id=scan.agent_id,
                policy_id=scan.policy_id,
                scan_id=scan.id,
                severity="info",
                message=(
                    f"Scan completed: {scan.passed} passed, {scan.failed} failed, "
                    f"{scan.not_applicable} n/a (score {scan.score})"
                ),
                payload=_json({"passed": scan.passed, "failed": scan.failed, "score": scan.score}),
                occurred_at=occurred,
            )
        )
        if scan.critical_failures:
            db.add(
                ScaEvent(
                    event_type="critical_check_failed",
                    agent_id=scan.agent_id,
                    policy_id=scan.policy_id,
                    scan_id=scan.id,
                    severity="critical",
                    message=f"{scan.critical_failures} critical check(s) failed",
                    occurred_at=occurred,
                )
            )

    for agent in db.execute(select(Agent)).scalars().all():
        if agent.status == "offline":
            db.add(
                ScaEvent(
                    event_type="agent_offline",
                    agent_id=agent.id,
                    severity="high",
                    message=f"Agent '{agent.hostname}' went offline",
                    occurred_at=now - timedelta(hours=2, minutes=10),
                )
            )

    # Drift records: deterministic regressions + improvements per agent using
    # real stored CheckResult values so the drift feed is grounded in data.
    for agent in db.execute(select(Agent).order_by(Agent.agent_code)).scalars().all():
        scans_for_agent = [
            s for s in scans if s.agent_id == agent.id
        ]
        if not scans_for_agent:
            continue
        for scan in scans_for_agent:
            results = list(
                db.execute(
                    select(CheckResult)
                    .where(CheckResult.scan_id == scan.id)
                    .order_by(CheckResult.policy_check_id)
                ).scalars().all()
            )
            failed = [r for r in results if r.result == "failed"]
            passed = [r for r in results if r.result == "passed"]
            regressed = failed[:2]
            improved = passed[:1]
            for idx, item in enumerate(regressed):
                drift = ConfigurationDrift(
                    agent_id=agent.id,
                    policy_id=scan.policy_id,
                    check_id=item.policy_check_id,
                    previous_result="passed",
                    current_result="failed",
                    previous_value=item.expected_value,
                    current_value=item.actual_value,
                    detected_at=(scan.end_scan or now) - timedelta(minutes=45 + idx * 8),
                    severity="high" if item.expected_value else "medium",
                    description=(
                        f"configuration drifted: check outcome changed from passed to failed "
                        f"between scans"
                    ),
                )
                db.add(drift)
                db.add(
                    ScaEvent(
                        event_type="configuration_changed",
                        agent_id=agent.id,
                        policy_id=scan.policy_id,
                        scan_id=scan.id,
                        check_id=item.policy_check_id,
                        severity=drift.severity,
                        message=f"check outcome changed passed -> failed",
                        occurred_at=drift.detected_at,
                    )
                )
            for item in improved:
                db.add(
                    ConfigurationDrift(
                        agent_id=agent.id,
                        policy_id=scan.policy_id,
                        check_id=item.policy_check_id,
                        previous_result="failed",
                        current_result="passed",
                        previous_value="Disabled",
                        current_value=item.actual_value,
                        detected_at=(scan.end_scan or now) - timedelta(hours=3, minutes=5),
                        severity="low",
                        description="hardening improved: check outcome changed from failed to passed",
                    )
                )
    db.flush()


def seed_policies(db: Session) -> None:
    """Seed or enrich the CIS benchmark policies, checks, rules and scans."""
    agents = list(db.execute(select(Agent).order_by(Agent.agent_code)).scalars().all())

    for spec in POLICIES:
        policy = _upsert_policy(db, spec)
        checks = _enrich_or_create_checks(db, policy)
        # Denormalized demo outcome for the checks table (per-check column).
        for check in checks:
            if not check.result:
                check.result = _outcome_for(check.check_id, "001")
        _ensure_rules_and_refs(db, policy, checks)
        _ensure_demo_scans(db, policy, checks, agents)
    _ensure_demo_events(db)
    db.flush()


def seed_endpoint_data(db: Session) -> None:
    """Seed both FIM and SCA modules if empty (demo mode)."""
    seed_syscheck(db)
    seed_sca_agents(db)
    seed_policies(db)
    db.commit()
