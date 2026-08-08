"""Command line interface for the standalone FIM endpoint agent.

Commands::

    register    Register with the FIM manager and persist the API key.
    heartbeat   Send one heartbeat (or loop with --interval).
    baseline    Build / show the local file baseline for the monitored paths.
    monitor     Detect file changes and submit them to the manager.
    daemon      Register if needed, then heartbeat + monitor forever.

Only the directories listed in the config (default ``C:\\FIM-Test``) are
watched - never a whole drive.
"""

import argparse
import json
import logging
import os
import platform
import sys
import time

from fim_agent import __version__
from fim_agent.config import FimAgentConfig
from fim_agent.transport import FimTransport, TransportError


def _build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--server", default=None, help="FIM manager base URL")
    common.add_argument("--agent-code", default=None, help="unique agent code")
    common.add_argument("--config", default=None, help="path to fim_agent.yaml")
    common.add_argument("--api-key-file", default=None, help="path to persist the API key")
    common.add_argument("--log-level", default=None, choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    parser = argparse.ArgumentParser(
        prog="fim-agent", description="Standalone FIM endpoint agent", parents=[common]
    )
    parser.add_argument("--version", action="version", version=__version__)

    sub = parser.add_subparsers(dest="command", required=True)

    reg = sub.add_parser("register", parents=[common], help="register with the FIM manager")
    reg.add_argument("--registration-token", default=None, help="shared registration secret")
    reg.add_argument(
        "--monitor-paths",
        default="",
        help="semicolon-separated directories to watch (default C:\\FIM-Test)",
    )

    beat = sub.add_parser("heartbeat", parents=[common], help="send a heartbeat")
    beat.add_argument("--interval", type=float, default=0, help="loop interval in seconds")

    base = sub.add_parser("baseline", parents=[common], help="build/show the local baseline")
    base.add_argument("--show", action="store_true", help="print the baseline as JSON")

    mon = sub.add_parser("monitor", parents=[common], help="detect and report file changes")
    mon.add_argument("--once", action="store_true", help="process pending events and exit")
    mon.add_argument("--no-watchdog", action="store_true", help="force polling-only detection")
    mon.add_argument(
        "--poll-interval", type=float, default=0, help="polling interval in seconds"
    )

    daemon = sub.add_parser(
        "daemon", parents=[common], help="register if needed, then heartbeat + monitor"
    )
    daemon.add_argument("--registration-token", default=None, help="shared registration secret")
    daemon.add_argument(
        "--monitor-paths",
        default="",
        help="semicolon-separated directories to watch (default C:\\FIM-Test)",
    )
    return parser


def _config(args: argparse.Namespace) -> FimAgentConfig:
    cfg = FimAgentConfig.from_env()
    if getattr(args, "config", None):
        cfg = FimAgentConfig.from_yaml(args.config)
    if args.server:
        cfg.server_url = args.server
    if args.agent_code:
        # Re-derive per-agent state-file defaults when the code is overridden.
        cfg.agent_code = args.agent_code
        if not getattr(args, "api_key_file", None):
            cfg.api_key_file = os.path.join(
                os.path.expanduser("~"), f".fim-agent-{args.agent_code}.key"
            )
        if not getattr(args, "baseline_file", None):
            cfg.baseline_file = os.path.join(
                os.path.expanduser("~"), f".fim-agent-{args.agent_code}.baseline.json"
            )
    if getattr(args, "api_key_file", None):
        cfg.api_key_file = args.api_key_file
    monitor_paths = getattr(args, "monitor_paths", "") or ""
    if monitor_paths:
        cfg.monitored_paths = [p.strip() for p in monitor_paths.split(";") if p.strip()]
    if getattr(args, "poll_interval", 0) or 0 > 0:
        cfg.poll_interval = args.poll_interval
    if getattr(args, "no_watchdog", False):
        cfg.use_watchdog = False
    return cfg


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _load_api_key(cfg: FimAgentConfig) -> str | None:
    api_key = cfg.load_api_key()
    if not api_key:
        print(
            "no saved API key - run 'python -m fim_agent register' first",
            file=sys.stderr,
        )
    return api_key


def _cmd_register(args: argparse.Namespace) -> int:
    cfg = _config(args)
    token = getattr(args, "registration_token", None) or cfg.registration_token
    transport = FimTransport(cfg)
    try:
        response = transport.register(registration_token=token)
    except TransportError as exc:
        print(f"register failed: {exc}", file=sys.stderr)
        return 1
    api_key = response.get("api_key")
    if not api_key:
        print(f"register failed: no api_key in response {response}", file=sys.stderr)
        return 1
    cfg.save_api_key(api_key)
    print(
        f"registered agent '{response.get('code')}' "
        f"(status={response.get('status')}); API key saved to {cfg.api_key_file}"
    )
    return 0


def _cmd_heartbeat(args: argparse.Namespace) -> int:
    cfg = _config(args)
    api_key = _load_api_key(cfg)
    if not api_key:
        return 1
    transport = FimTransport(cfg)
    interval = args.interval
    while True:
        try:
            response = transport.heartbeat(api_key)
            print(
                f"heartbeat: agent={response.get('code')} "
                f"status={response.get('status')} last_seen={response.get('last_seen')}"
            )
        except TransportError as exc:
            print(f"heartbeat failed: {exc}", file=sys.stderr)
            return 1
        if interval <= 0:
            return 0
        time.sleep(interval)


def _cmd_baseline(args: argparse.Namespace) -> int:
    cfg = _config(args)
    from fim_agent.baseline import Baseline

    baseline = Baseline().scan(cfg.monitored_paths, cfg.exclude_patterns)
    baseline.save(cfg.baseline_file)
    print(f"baseline saved to {cfg.baseline_file} ({len(baseline.entries)} file(s))")
    if args.show:
        print(json.dumps(baseline.entries, indent=2, sort_keys=True))
    return 0


def _cmd_monitor(args: argparse.Namespace) -> int:
    cfg = _config(args)
    api_key = _load_api_key(cfg)
    if not api_key:
        return 1
    from fim_agent.monitor import FimMonitor

    monitor = FimMonitor(cfg, api_key=api_key)
    if args.once:
        sent = monitor.run_once()
        print(f"processed pending changes: {sent} sent")
        return 0
    try:
        monitor.run()
    except KeyboardInterrupt:
        monitor.stop()
        print("stopped")
    return 0


def _cmd_daemon(args: argparse.Namespace) -> int:
    cfg = _config(args)
    api_key = cfg.load_api_key()
    if not api_key:
        if not _cmd_register(args):
            api_key = cfg.load_api_key()
    if not api_key:
        return 1
    from fim_agent.monitor import FimMonitor

    monitor = FimMonitor(cfg, api_key=api_key)
    try:
        monitor.run()
    except KeyboardInterrupt:
        monitor.stop()
        print("stopped")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.log_level or "INFO")
    command = getattr(args, "command", "")
    if command == "register":
        return _cmd_register(args)
    if command == "heartbeat":
        return _cmd_heartbeat(args)
    if command == "baseline":
        return _cmd_baseline(args)
    if command == "monitor":
        return _cmd_monitor(args)
    if command == "daemon":
        return _cmd_daemon(args)
    parser.error(f"unknown command '{command}'")


if __name__ == "__main__":
    sys.exit(main())
