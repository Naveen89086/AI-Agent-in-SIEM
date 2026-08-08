"""Command line interface for the standalone SCA agent.

Commands::

    register    Register with the SCA manager and persist the API key.
    heartbeat   Send one heartbeat (or loop with --interval).
    scan        Run allowlisted collectors over a rules file and print evidence.
    daemon      Loop: heartbeat, pull pending jobs, collect and submit evidence.
"""

import argparse
import json
import platform
import sys
import time

from agent import __version__
from agent.config import AgentConfig
from agent.runner import rules_from_dicts, run_scan
from agent.transport import ScaTransport, TransportError


def _build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--server", default=None, help="SCA manager base URL")
    common.add_argument("--agent-code", default=None, help="unique agent code")
    common.add_argument("--api-key-file", default=None, help="path to persist the API key")

    parser = argparse.ArgumentParser(
        prog="sca-agent", description="Standalone SCA endpoint agent", parents=[common]
    )
    parser.add_argument("--version", action="version", version=__version__)

    sub = parser.add_subparsers(dest="command", required=True)

    reg = sub.add_parser("register", parents=[common], help="register with the SCA manager")
    reg.add_argument("--registration-token", default=None, help="shared registration secret")

    beat = sub.add_parser("heartbeat", parents=[common], help="send a heartbeat")
    beat.add_argument("--interval", type=float, default=0, help="loop interval in seconds")
    beat.add_argument("--offline", action="store_true", help="report offline")

    scan = sub.add_parser("scan", parents=[common], help="run collectors over a rules file")
    scan.add_argument("rules", help="path to rules JSON (list of rule dicts)")
    scan.add_argument("--output", default=None, help="write evidence JSON to this file")
    scan.add_argument("--platform", default="", help="override platform (windows/linux)")

    daemon = sub.add_parser(
        "daemon", parents=[common], help="heartbeat, pull jobs and submit evidence"
    )
    daemon.add_argument(
        "--interval", type=float, default=60, help="poll interval in seconds"
    )
    return parser


def _config(args: argparse.Namespace) -> AgentConfig:
    cfg = AgentConfig.from_env()
    if args.server:
        cfg.server_url = args.server
    if args.agent_code:
        cfg.agent_code = args.agent_code
    if getattr(args, "api_key_file", None):
        cfg.api_key_file = args.api_key_file
    return cfg


def _cmd_register(args: argparse.Namespace) -> int:
    cfg = _config(args)
    token = getattr(args, "registration_token", None) or cfg.registration_token
    transport = ScaTransport(cfg)
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
        f"registered agent '{response.get('agent_code')}' "
        f"(status={response.get('status')}); API key saved to {cfg.api_key_file}"
    )
    return 0


def _cmd_heartbeat(args: argparse.Namespace) -> int:
    cfg = _config(args)
    api_key = cfg.load_api_key()
    if not api_key:
        print(
            "no saved API key - run 'python -m agent register' first", file=sys.stderr
        )
        return 1
    transport = ScaTransport(cfg)
    interval = args.interval
    while True:
        try:
            response = transport.heartbeat(api_key, status="offline" if args.offline else "online")
            print(
                f"heartbeat: agent={response.get('agent_code')} "
                f"status={response.get('status')} last_seen={response.get('last_seen')}"
            )
        except TransportError as exc:
            print(f"heartbeat failed: {exc}", file=sys.stderr)
            return 1
        if interval <= 0:
            return 0
        time.sleep(interval)


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        with open(args.rules, "r", encoding="utf-8") as fh:
            payloads = json.load(fh)
    except OSError as exc:
        print(f"cannot read rules file: {exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"invalid rules JSON: {exc}", file=sys.stderr)
        return 1
    if not isinstance(payloads, list):
        print("rules file must contain a JSON list", file=sys.stderr)
        return 1

    rules = rules_from_dicts(payloads)
    evidence = run_scan(rules, args.platform or platform.system().lower())
    payload = {
        "agent_code": _config(args).agent_code,
        "platform": args.platform or platform.system().lower(),
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "results": evidence,
    }
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        print(f"evidence written to {args.output}")
    else:
        print(json.dumps(payload, indent=2, default=str))
    return 0


def _cmd_daemon(args: argparse.Namespace) -> int:
    cfg = _config(args)
    api_key = cfg.load_api_key()
    if not api_key:
        print(
            "no saved API key - run 'python -m agent register' first", file=sys.stderr
        )
        return 1
    transport = ScaTransport(cfg)
    interval = max(1.0, getattr(args, "interval", 60))
    while True:
        try:
            beat = transport.heartbeat(api_key, status="online")
            print(
                f"heartbeat: agent={beat.get('agent_code')} "
                f"status={beat.get('status')}"
            )
            job_payload = transport.fetch_job(api_key)
            job = (job_payload or {}).get("job")
            if job and job.get("rules"):
                rules = rules_from_dicts(job["rules"])
                evidence = run_scan(rules, job.get("platform") or platform.system().lower())
                submitted = transport.submit_evidence(
                    api_key, job["scan_id"], evidence
                )
                print(
                    f"submitted {len(evidence)} evidence record(s) for scan "
                    f"{job['scan_id']} (status={submitted.get('status')})"
                )
            else:
                print("no pending job")
        except TransportError as exc:
            print(f"daemon error: {exc}", file=sys.stderr)
        time.sleep(interval)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "register":
        return _cmd_register(args)
    if args.command == "heartbeat":
        return _cmd_heartbeat(args)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "daemon":
        return _cmd_daemon(args)
    parser.error(f"unknown command '{args.command}'")


if __name__ == "__main__":
    sys.exit(main())
