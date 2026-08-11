"""Endpoint agent CLI.

Subcommands:
    register   - enroll this machine (protected endpoint + IOC + vulnerability
                 + telemetry) and save the returned API keys
    heartbeat  - send a keep-alive for all subsystems
    inventory  - collect and submit installed-software inventory (once)
    observe    - collect and submit indicator observations (once)
    telemetry  - collect and submit one network/process/service snapshot
    scan       - register (if needed), collect + submit inventory, then submit
                 observations and trigger a vulnerability scan
    daemon     - loop: inventory, observations, telemetry blocks, heartbeats

The agent derives a stable per-machine identity (Windows MachineGuid) used both
for the protected-endpoint registration and the subsystem agent registrations,
so the manager can enforce the single-protected-device model.

Run ``python -m endpoint_agent scan --demo`` for a local end-to-end smoke test
against a running manager (demo data is always labeled demo).
"""

import argparse
import hashlib
import json
import logging
import time

from endpoint_agent.collector import (
    collect_inventory,
    collect_observations,
    filter_new,
)
from endpoint_agent.config import EndpointAgentConfig
from endpoint_agent.transport import EndpointAgentTransport, TransportError


def _log(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _ensure_protected_registered(cfg: EndpointAgentConfig, transport: EndpointAgentTransport) -> None:
    """Register this machine with the manager (single-device model).

    Idempotent for the same machine; a second, different device is rejected
    server-side with ``single_endpoint_limit``.
    """
    result = transport.register_protected_endpoint()
    if result.get("registered"):
        logging.getLogger("endpoint_agent").info(
            "Protected endpoint registered: %s (%s)",
            result.get("endpoint", {}).get("hostname"),
            result.get("endpoint", {}).get("machine_guid"),
        )


def _ensure_registered(cfg: EndpointAgentConfig, transport: EndpointAgentTransport) -> tuple[str, str]:
    """Return (ioc_api_key, vuln_api_key), registering when needed."""
    ioc_key = cfg.load_ioc_api_key()
    vuln_key = cfg.load_vuln_api_key()
    if ioc_key and vuln_key:
        return ioc_key, vuln_key
    if not ioc_key:
        result = transport.register_ioc()
        ioc_key = result.get("api_key", "")
        if ioc_key:
            cfg.save_ioc_api_key(ioc_key)
            logging.getLogger("endpoint_agent").info("Registered IOC agent %s", cfg.agent_code)
    if not vuln_key:
        result = transport.register_vuln()
        vuln_key = result.get("api_key", "")
        if vuln_key:
            cfg.save_vuln_api_key(vuln_key)
            logging.getLogger("endpoint_agent").info("Registered vulnerability agent %s", cfg.agent_code)
    return ioc_key, vuln_key


def _ensure_telemetry_registered(cfg: EndpointAgentConfig, transport: EndpointAgentTransport) -> str:
    """Return the telemetry API key, registering when needed."""
    telemetry_key = cfg.load_telemetry_api_key()
    if telemetry_key:
        return telemetry_key
    result = transport.register_telemetry()
    telemetry_key = result.get("api_key", "")
    if telemetry_key:
        cfg.save_telemetry_api_key(telemetry_key)
        logging.getLogger("endpoint_agent").info("Registered telemetry agent %s", cfg.agent_code)
    return telemetry_key


def _inventory_fingerprint(items: list[dict]) -> str:
    payload = json.dumps(items, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _cmd_register(cfg: EndpointAgentConfig, transport: EndpointAgentTransport) -> int:
    _ensure_protected_registered(cfg, transport)
    ioc_key, vuln_key = _ensure_registered(cfg, transport)
    if ioc_key:
        print(f"ioc_api_key={ioc_key[:8]}... (saved to {cfg.ioc_api_key_file})")
    if vuln_key:
        print(f"vuln_api_key={vuln_key[:8]}... (saved to {cfg.vuln_api_key_file})")
    telemetry_key = _ensure_telemetry_registered(cfg, transport)
    if telemetry_key:
        print(f"telemetry_api_key={telemetry_key[:8]}... (saved to {cfg.telemetry_api_key_file})")
    return 0


def _cmd_heartbeat(cfg: EndpointAgentConfig, transport: EndpointAgentTransport) -> int:
    ioc_key, vuln_key = _ensure_registered(cfg, transport)
    if ioc_key:
        print(transport.heartbeat_ioc(ioc_key))
    if vuln_key:
        print(transport.heartbeat_vuln(vuln_key))
    telemetry_key = _ensure_telemetry_registered(cfg, transport)
    if telemetry_key:
        print(transport.heartbeat_telemetry(telemetry_key))
    return 0


def _cmd_inventory(cfg: EndpointAgentConfig, transport: EndpointAgentTransport) -> int:
    ioc_key, vuln_key = _ensure_registered(cfg, transport)
    items = collect_inventory(demo=cfg.demo)
    if not items:
        logging.getLogger("endpoint_agent").warning("No inventory collected (empty snapshot); skipping submission")
        return 0
    cached = cfg.load_inventory_cache()
    fingerprint = _inventory_fingerprint(items)
    if cached == fingerprint:
        logging.getLogger("endpoint_agent").info("Inventory unchanged; skipping submission")
        return 0
    print(transport.submit_inventory(vuln_key, items))
    cfg.save_inventory_cache(fingerprint)
    return 0


def _cmd_observe(cfg: EndpointAgentConfig, transport: EndpointAgentTransport) -> int:
    ioc_key, vuln_key = _ensure_registered(cfg, transport)
    observations = collect_observations(
        demo=cfg.demo,
        max_obs=cfg.max_observations,
        skip_private=cfg.skip_private_ips,
    )
    if not observations:
        logging.getLogger("endpoint_agent").info("No new observations this cycle")
        return 0
    print(transport.submit_observations(ioc_key, observations))
    return 0


def _cmd_scan(cfg: EndpointAgentConfig, transport: EndpointAgentTransport) -> int:
    _ensure_protected_registered(cfg, transport)
    ioc_key, vuln_key = _ensure_registered(cfg, transport)
    items = collect_inventory(demo=cfg.demo)
    if items:
        print(transport.submit_inventory(vuln_key, items))
    observations = collect_observations(
        demo=cfg.demo,
        max_obs=cfg.max_observations,
        skip_private=cfg.skip_private_ips,
    )
    if observations:
        print(transport.submit_observations(ioc_key, observations))
    logging.getLogger("endpoint_agent").info("Scan complete (collect + submit)")
    return 0


def _telemetry_demo_flags(cfg: EndpointAgentConfig) -> dict:
    """Resolve per-module demo flags; global --demo turns all of them on."""
    if cfg.demo:
        return {"network": True, "process": True, "service": True}
    return {
        "network": cfg.network_demo,
        "process": cfg.process_demo,
        "service": cfg.service_demo,
    }


def _collect_telemetry_block(cfg: EndpointAgentConfig) -> dict:
    """Collect one full telemetry snapshot with per-module demo flags."""
    from endpoint_agent.telemetry_collector import (
        _now_iso,
        collect_network,
        collect_processes,
        collect_services,
    )

    flags = _telemetry_demo_flags(cfg)
    return {
        "collected_at": _now_iso(),
        "network": collect_network(
            demo=flags["network"],
            max_connections=cfg.max_connections,
            max_listeners=cfg.max_listeners,
        ),
        "processes": collect_processes(demo=flags["process"]),
        "services": collect_services(demo=flags["service"]),
    }


def _cmd_telemetry(cfg: EndpointAgentConfig, transport: EndpointAgentTransport) -> int:
    telemetry_key = _ensure_telemetry_registered(cfg, transport)
    snapshot = _collect_telemetry_block(cfg)
    if not snapshot["processes"] and not snapshot["services"] and not snapshot["network"]["connections"]:
        logging.getLogger("endpoint_agent").info("No telemetry collected; skipping submission")
        return 0
    flags = _telemetry_demo_flags(cfg)
    result = transport.submit_telemetry_snapshot(
        telemetry_key, snapshot, demo=bool(flags["network"] or flags["process"] or flags["service"])
    )
    print(result)
    return 0


def _cmd_daemon(cfg: EndpointAgentConfig, transport: EndpointAgentTransport) -> int:
    log = logging.getLogger("endpoint_agent")
    _ensure_protected_registered(cfg, transport)
    ioc_key, vuln_key = _ensure_registered(cfg, transport)
    telemetry_key = _ensure_telemetry_registered(cfg, transport)
    last_inventory = time.monotonic()
    last_observation = time.monotonic()
    last_heartbeat = time.monotonic()
    last_network = time.monotonic()
    last_process = time.monotonic()
    last_service = time.monotonic()
    log.info("Daemon started for agent %s (interval i=%ss o=%ss h=%ss n=%ss p=%ss s=%ss)",
             cfg.agent_code, cfg.inventory_interval, cfg.observation_interval,
             cfg.heartbeat_interval, cfg.network_interval, cfg.process_interval,
             cfg.service_interval)
    flags = _telemetry_demo_flags(cfg)
    try:
        while True:
            now = time.monotonic()
            try:
                if now - last_inventory >= cfg.inventory_interval:
                    items = collect_inventory(demo=cfg.demo)
                    if items:
                        transport.submit_inventory(vuln_key, items)
                    last_inventory = now
                if now - last_observation >= cfg.observation_interval:
                    observations = collect_observations(
                        demo=cfg.demo,
                        max_obs=cfg.max_observations,
                        skip_private=cfg.skip_private_ips,
                    )
                    seen = cfg.load_observation_history()
                    fresh = filter_new(observations, seen)
                    if fresh:
                        transport.submit_observations(ioc_key, fresh)
                        cfg.save_observation_history(seen)
                    last_observation = now
                if now - last_network >= cfg.network_interval:
                    _submit_network_block(cfg, transport, telemetry_key, flags["network"])
                    last_network = now
                if now - last_process >= cfg.process_interval:
                    _submit_process_block(cfg, transport, telemetry_key, flags["process"])
                    last_process = now
                if now - last_service >= cfg.service_interval:
                    _submit_service_block(cfg, transport, telemetry_key, flags["service"])
                    last_service = now
                if now - last_heartbeat >= cfg.heartbeat_interval:
                    transport.heartbeat_ioc(ioc_key)
                    transport.heartbeat_vuln(vuln_key)
                    transport.heartbeat_telemetry(telemetry_key)
                    last_heartbeat = now
            except TransportError as exc:
                log.warning("Transport error: %s", exc)
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Daemon stopped")
    return 0


def _submit_network_block(cfg, transport, api_key: str, demo: bool) -> None:
    from endpoint_agent.telemetry_collector import collect_network

    network = collect_network(demo=demo, max_connections=cfg.max_connections, max_listeners=cfg.max_listeners)
    transport.submit_telemetry_snapshot(
        api_key,
        {"collected_at": None, "network": network, "processes": [], "services": []},
        demo=demo,
    )


def _submit_process_block(cfg, transport, api_key: str, demo: bool) -> None:
    from endpoint_agent.telemetry_collector import collect_processes

    processes = collect_processes(demo=demo)
    transport.submit_telemetry_snapshot(
        api_key,
        {"collected_at": None, "network": {}, "processes": processes, "services": []},
        demo=demo,
    )


def _submit_service_block(cfg, transport, api_key: str, demo: bool) -> None:
    from endpoint_agent.telemetry_collector import collect_services

    services = collect_services(demo=demo)
    transport.submit_telemetry_snapshot(
        api_key,
        {"collected_at": None, "network": {}, "processes": [], "services": services},
        demo=demo,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SIEM endpoint agent")
    parser.add_argument("--config", help="YAML config file")
    parser.add_argument("--server-url", help="SIEM manager base URL")
    parser.add_argument("--agent-code", help="unique agent code")
    parser.add_argument("--registration-token", help="shared registration token")
    parser.add_argument("--demo", action="store_true", help="use demo collectors (labeled demo)")
    parser.add_argument("--log-level", default="INFO")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("register", help="register with the manager and save API keys")
    sub.add_parser("heartbeat", help="send a keep-alive")
    sub.add_parser("inventory", help="collect + submit installed software")
    sub.add_parser("observe", help="collect + submit indicator observations")
    sub.add_parser("scan", help="collect + submit inventory and observations")
    sub.add_parser("telemetry", help="collect + submit one network/process/service snapshot")
    sub.add_parser("daemon", help="run the polling loop")
    args = parser.parse_args(argv)

    _log(args.log_level)
    if args.config:
        cfg = EndpointAgentConfig.from_yaml(args.config)
    else:
        cfg = EndpointAgentConfig.from_env()
    if args.server_url:
        cfg.server_url = args.server_url
    if args.agent_code:
        cfg.agent_code = args.agent_code
    if args.registration_token:
        cfg.registration_token = args.registration_token
    if args.demo:
        cfg.demo = True

    transport = EndpointAgentTransport(cfg)
    handlers = {
        "register": _cmd_register,
        "heartbeat": _cmd_heartbeat,
        "inventory": _cmd_inventory,
        "observe": _cmd_observe,
        "scan": _cmd_scan,
        "telemetry": _cmd_telemetry,
        "daemon": _cmd_daemon,
    }
    return handlers[args.command](cfg, transport)


if __name__ == "__main__":
    raise SystemExit(main())
