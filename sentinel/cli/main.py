"""`sentinel` command line. A thin client of the service facade: parse args, call, format."""

import argparse
import json
import os
import re
import sys
from collections.abc import Callable
from importlib.metadata import version
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from sentinel.api.service import SentinelService, ServiceError, init_workspace
from sentinel.cli.render import (
    format_brief,
    format_detail,
    format_event,
    format_report,
    format_status,
    format_summary,
    matches,
)
from sentinel.config.secrets import Secrets, SecretsError, load_secrets
from sentinel.config.settings import Settings, load_settings
from sentinel.contracts.models import Event, IncidentReport
from sentinel.contracts.text import terminal_safe

ServiceFactory = Callable[[Settings, Secrets], SentinelService]
DEFAULT_CONFIG = Path("config.toml")
CHANNEL_CHOICES = ("slack", "discord", "telegram")
PROTO_CHOICES = ("tcp", "udp", "icmp", "dns", "arp", "dhcp", "mdns")
LENIENT_COMMANDS = {"doctor", "init", "config"}  # must work even when secrets.env is broken
_DURATION = re.compile(r"^(\d+(?:\.\d+)?)([smhd]?)$")
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}
EXAMPLES = """examples:
  sentinel init                                   create config.toml and a private secrets.env
  sentinel replay capture.pcap -t -H 192.168.2.30 replay, showing one device's traffic
  sentinel replay a.pcap b.pcap --brief -n        several captures, one line per incident, notify
  sudo sentinel watch --for 10m                   live capture for ten minutes
  sentinel status                                 where things stand
  sentinel incidents --since 24h --min-score 0.7  what needs attention
  sentinel ack inc-aabb                           acknowledge (a unique id prefix is enough)
  sentinel notify test slack

See USER_GUIDE.md for setup, notifications and LLM configuration."""


def parse_duration(text: str) -> float:
    """'90', '90s', '15m', '2h', '1d' -> seconds."""
    match = _DURATION.match(text.strip().lower())
    if not match or float(match.group(1)) <= 0:
        raise argparse.ArgumentTypeError(f"{text!r} is not a duration like 30s, 15m, 2h or 1d")
    return float(match.group(1)) * _UNITS[match.group(2)]


def _stream_flags(sp: argparse.ArgumentParser) -> None:
    group = sp.add_mutually_exclusive_group()
    group.add_argument(
        "-t", "--show-traffic", dest="traffic", action="store_const", const=True,
        help="print every packet event as it is processed",
    )  # fmt: skip
    group.add_argument(
        "-T", "--no-traffic", dest="traffic", action="store_const", const=False,
        help="do not print traffic (overrides config)",
    )  # fmt: skip
    sp.add_argument("-H", "--host", help="traffic view only: events involving this IP")
    sp.add_argument("-p", "--port", type=int, help="traffic view only: events on this port")
    sp.add_argument("--proto", choices=PROTO_CHOICES, help="traffic view only: one protocol")
    sp.add_argument("-n", "--notify", action="store_true", help="notify about new incidents")
    sp.add_argument("-b", "--brief", action="store_true", help="one line per incident")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel",
        description="Small-network anomaly detector: finds scans, brute force, beacons and DNS "
        "tunnels, explains them in plain English and alerts you on Slack, Discord or Telegram.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"sentinel {version('sentinel')}")
    p.add_argument(
        "--config", type=Path, help=f"settings file (default: {DEFAULT_CONFIG} if present)"
    )
    p.add_argument("--json", action="store_true", help="machine-readable output (JSON lines)")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    sub = p.add_subparsers(dest="command", metavar="command")

    sub.add_parser("init", help="create config.toml and a private secrets.env here").add_argument(
        "--dir", type=Path, default=Path(), help="directory to create them in (default: here)"
    )
    replay = sub.add_parser("replay", help="run pcap/pcapng files through the detection pipeline")
    replay.add_argument("pcaps", type=Path, nargs="+", metavar="PCAP")
    _stream_flags(replay)
    watch = sub.add_parser("watch", help="capture live traffic with tcpdump (needs sudo)")
    watch.add_argument("--iface", help="interface (default: [capture] interface)")
    watch.add_argument(
        "--for", dest="duration", type=parse_duration, metavar="TIME",
        help="stop after this long, e.g. 90s, 10m, 2h",
    )  # fmt: skip
    _stream_flags(watch)
    sub.add_parser("status", help="one-screen summary: database, incidents, notify, LLM")
    inc = sub.add_parser("incidents", help="list stored incidents (open ones by default)")
    inc.add_argument("-n", "--limit", type=int, default=20)
    inc.add_argument(
        "--since", type=parse_duration, metavar="TIME", help="only the last 24h, 90m, ..."
    )
    inc.add_argument("--min-score", type=float, default=0.0, metavar="0-1")
    inc.add_argument("-a", "--all", action="store_true", help="include dismissed and resolved")
    show = sub.add_parser("incident", help="show one incident with its alert timeline")
    show.add_argument("incident_id", metavar="ID", help="an incident id or unique prefix")
    for name, text in (("ack", "acknowledge"), ("dismiss", "dismiss as a false alarm"),
                       ("resolve", "mark as resolved")):  # fmt: skip
        sp = sub.add_parser(name, help=f"{text} one or more incidents")
        sp.add_argument("incident_ids", nargs="+", metavar="ID")
    notify = sub.add_parser("notify", help="notification utilities")
    notify_sub = notify.add_subparsers(dest="notify_command", required=True)
    test = notify_sub.add_parser("test", help="send a sample incident to one channel")
    test.add_argument("channel", choices=CHANNEL_CHOICES)
    llm = sub.add_parser("llm", help="LLM utilities")
    llm_sub = llm.add_subparsers(dest="llm_command", required=True)
    llm_sub.add_parser("test", help="list models and summarise a sample incident")
    config = sub.add_parser("config", help="show the effective settings (secrets are never shown)")
    config.add_argument("config_command", choices=["show"])
    doctor = sub.add_parser("doctor", help="check configuration, credentials, interface and LLM")
    doctor.add_argument("--fix", action="store_true", help="repair what is safe (secrets.env mode)")
    return p


def _out(args: argparse.Namespace, human: str, data: Any) -> None:
    print(json.dumps(data) if args.json else human, flush=True)


def _color(args: argparse.Namespace) -> bool:
    if args.json or args.color == "never":
        return False
    return args.color == "always" or (sys.stdout.isatty() and "NO_COLOR" not in os.environ)


def _event_json(event: Event) -> dict[str, Any]:
    return {"type": type(event).__name__, **event.model_dump()}


def _run_stream(args: argparse.Namespace, service: SentinelService, settings: Settings) -> int:
    show = settings.cli.show_traffic if args.traffic is None else args.traffic
    color = _color(args)
    if args.notify and not (settings.notify.enabled and settings.notify.channels):
        print(
            "warning: --notify has no effect: set [notify] enabled = true and list channels "
            "in config.toml",
            file=sys.stderr,
        )

    def on_event(event: Event) -> None:
        if matches(event, args.host, args.port, args.proto):
            _out(args, format_event(event), {"event": _event_json(event)})

    def on_report(report: IncidentReport) -> None:
        text = format_brief(report, color) if args.brief else format_report(report, color)
        _out(args, text, {"report": report.model_dump()})

    common: dict[str, Any] = {
        "on_event": on_event if show else None, "on_report": on_report, "notify": args.notify,
    }  # fmt: skip
    if args.command == "watch":
        summary = service.watch(args.iface or settings.capture.interface,
                                duration_seconds=args.duration, **common)  # fmt: skip
        _out(args, format_summary(summary), {"summary": summary.model_dump()})
        return 0
    for pcap in args.pcaps:
        if len(args.pcaps) > 1:
            _out(args, f"== {pcap} ==", {"file": str(pcap)})
        summary = service.replay(pcap, **common)
        _out(args, format_summary(summary), {"summary": summary.model_dump()})
    return 0


def _show_config(args: argparse.Namespace, settings: Settings, secrets: Secrets) -> int:
    present = {
        "slack": secrets.slack_webhook_url is not None,
        "discord": secrets.discord_webhook_url is not None,
        "telegram": secrets.telegram_bot_token is not None and secrets.telegram_chat_id is not None,
        "llm_api_key": secrets.llm_api_key is not None,
    }
    data = settings.model_dump(mode="json") | {"credentials_present": present}
    _out(args, json.dumps(data, indent=2), data)
    return 0


def _list_incidents(args: argparse.Namespace, service: SentinelService) -> int:
    found = service.incidents(
        args.limit, since_seconds=args.since, min_score=args.min_score, include_closed=args.all
    )
    for inc in found:
        human = (
            f"{inc.id}  {inc.status:<13} score={inc.score:.2f}  {' > '.join(inc.chain)}  "
            f"{terminal_safe(inc.summary or '')}"
        )
        _out(args, human, inc.model_dump())
    if not found and not args.json:
        print("no matching incidents (use --all to include dismissed and resolved)")
    return 0


def _set_status(args: argparse.Namespace, service: SentinelService) -> int:
    status = {"ack": "acknowledged", "dismiss": "dismissed", "resolve": "resolved"}[args.command]
    for reference in args.incident_ids:
        inc = service.set_incident_status(reference, status)
        _out(args, f"{inc.id} -> {inc.status}", inc.model_dump())
    return 0


def _llm_test(args: argparse.Namespace, service: SentinelService) -> int:
    result = service.llm_test()
    e = result.explanation
    fallback = f" (fallback: {result.fallback_reason})" if result.fallback_reason else ""
    human = (
        f"models: {', '.join(result.models) or '(none listed)'}\nsource: {e.source}{fallback}\n"
        f"{e.headline}\n{e.what_happened}\n{e.likely_cause}\n{e.suggested_action}"
    )
    _out(args, human, result.model_dump())
    return 0 if e.source == "llm" else 1


def _doctor(args: argparse.Namespace, service: SentinelService, settings: Settings) -> int:
    checks = service.doctor(settings.secrets_file, fix=args.fix)
    for c in checks:
        _out(args, f"[{'ok' if c.ok else '!!'}] {c.name}: {c.detail}", c.model_dump())
    return 0 if all(c.ok for c in checks) else 1


def _notify_test(args: argparse.Namespace, service: SentinelService) -> int:
    delivery = service.notify_test(args.channel)
    _out(args, f"{delivery.channel}: {delivery.status} ({delivery.detail})", delivery.model_dump())
    return 0 if delivery.status == "sent" else 1


def _show_incident(args: argparse.Namespace, service: SentinelService) -> int:
    detail = service.incident(args.incident_id)
    _out(args, format_detail(detail, _color(args)), detail.model_dump())
    return 0


def _status(args: argparse.Namespace, service: SentinelService) -> int:
    report = service.status()
    _out(args, format_status(report), report.model_dump())
    return 0


def _init(args: argparse.Namespace) -> int:
    for path, created in init_workspace(args.dir):
        _out(
            args,
            f"{'created' if created else 'kept   '} {path}",
            {"path": str(path), "created": created},
        )
    if not args.json:
        print("next: edit secrets.env, enable channels in config.toml, then run `sentinel doctor`")
    return 0


def _dispatch(
    args: argparse.Namespace, service: SentinelService, settings: Settings, secrets: Secrets
) -> int:
    handlers: dict[str, Callable[[], int]] = {
        "replay": lambda: _run_stream(args, service, settings),
        "watch": lambda: _run_stream(args, service, settings),
        "status": lambda: _status(args, service),
        "incidents": lambda: _list_incidents(args, service),
        "incident": lambda: _show_incident(args, service),
        "ack": lambda: _set_status(args, service),
        "dismiss": lambda: _set_status(args, service),
        "resolve": lambda: _set_status(args, service),
        "notify": lambda: _notify_test(args, service),
        "llm": lambda: _llm_test(args, service),
        "config": lambda: _show_config(args, settings, secrets),
        "doctor": lambda: _doctor(args, service, settings),
    }
    return handlers[args.command]()


def default_service(settings: Settings, secrets: Secrets) -> SentinelService:
    return SentinelService(settings, secrets)


def _load(args: argparse.Namespace) -> tuple[Settings, Secrets] | None:
    """Settings and secrets, or None after printing why they cannot be used."""
    config = args.config or (DEFAULT_CONFIG if DEFAULT_CONFIG.exists() else None)
    try:
        settings = load_settings(config)
        return settings, load_secrets(settings.secrets_file)
    except SecretsError as exc:
        if args.command in LENIENT_COMMANDS:  # `doctor` reports it and `--fix` repairs it
            return settings, Secrets()
        print(f"configuration error: {exc}", file=sys.stderr)
    except (ValidationError, OSError, ValueError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
    return None


def main(argv: list[str] | None = None, build_service: ServiceFactory = default_service) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "init":
        return _init(args)
    loaded = _load(args)
    if loaded is None:
        return 1
    settings, secrets = loaded
    service = build_service(settings, secrets)
    try:
        return _dispatch(args, service, settings, secrets)
    except ServiceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except BrokenPipeError:
        # Output was piped to something that closed early (`| head`). Silence the flush at exit.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    finally:
        service.close()


if __name__ == "__main__":
    sys.exit(main())
