"""`sentinel` command line. A thin client of the service facade: parse args, call, format."""

import argparse
import json
import os
import sys
from collections.abc import Callable
from importlib.metadata import version
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from sentinel.api.service import SentinelService, ServiceError
from sentinel.cli.render import (
    format_detail,
    format_event,
    format_report,
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
EXAMPLES = """examples:
  sentinel replay capture.pcap --show-traffic --host 192.168.2.30
  sentinel replay capture.pcap --notify
  sudo sentinel watch --iface bridge100 --proto dns --show-traffic
  sentinel incidents && sentinel incident inc-aabbccddee30-110
  sentinel notify test slack

See USER_GUIDE.md for setup, notifications and LLM configuration."""


def _traffic_flags(sp: argparse.ArgumentParser) -> None:
    group = sp.add_mutually_exclusive_group()
    group.add_argument(
        "--show-traffic", dest="traffic", action="store_const", const=True,
        help="print every packet event as it is processed",
    )  # fmt: skip
    group.add_argument(
        "--no-traffic", dest="traffic", action="store_const", const=False,
        help="do not print traffic (overrides config)",
    )  # fmt: skip
    sp.add_argument("--host", help="traffic view only: events involving this IP")
    sp.add_argument("--port", type=int, help="traffic view only: events on this port")
    sp.add_argument("--proto", choices=PROTO_CHOICES, help="traffic view only: one protocol")
    sp.add_argument("--notify", action="store_true", help="send notifications for new incidents")


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
    sub = p.add_subparsers(dest="command", metavar="command")

    replay = sub.add_parser("replay", help="run a pcap/pcapng file through the detection pipeline")
    replay.add_argument("pcap", type=Path)
    _traffic_flags(replay)
    watch = sub.add_parser("watch", help="capture live traffic with tcpdump (needs sudo)")
    watch.add_argument("--iface", help="interface (default: [capture] interface)")
    _traffic_flags(watch)
    inc = sub.add_parser("incidents", help="list recent stored incidents")
    inc.add_argument("--limit", type=int, default=20)
    show = sub.add_parser("incident", help="show one incident with its alert timeline")
    show.add_argument("incident_id")
    notify = sub.add_parser("notify", help="notification utilities")
    notify_sub = notify.add_subparsers(dest="notify_command", required=True)
    test = notify_sub.add_parser("test", help="send a sample incident to one channel")
    test.add_argument("channel", choices=CHANNEL_CHOICES)
    llm = sub.add_parser("llm", help="LLM utilities")
    llm_sub = llm.add_subparsers(dest="llm_command", required=True)
    llm_sub.add_parser("test", help="list models and summarise a sample incident")
    config = sub.add_parser("config", help="show the effective settings (secrets are never shown)")
    config.add_argument("config_command", choices=["show"])
    sub.add_parser("doctor", help="check configuration, credentials, interface and LLM server")
    return p


def _out(args: argparse.Namespace, human: str, data: Any) -> None:
    print(json.dumps(data) if args.json else human, flush=True)


def _event_json(event: Event) -> dict[str, Any]:
    return {"type": type(event).__name__, **event.model_dump()}


def _run_stream(args: argparse.Namespace, service: SentinelService, settings: Settings) -> int:
    show = settings.cli.show_traffic if args.traffic is None else args.traffic

    def on_event(event: Event) -> None:
        if matches(event, args.host, args.port, args.proto):
            _out(args, format_event(event), {"event": _event_json(event)})

    def on_report(report: IncidentReport) -> None:
        _out(args, format_report(report), {"report": report.model_dump()})

    if args.notify and not (settings.notify.enabled and settings.notify.channels):
        print(
            "warning: --notify has no effect: set [notify] enabled = true and list channels "
            "in config.toml",
            file=sys.stderr,
        )
    kwargs = {"on_event": on_event if show else None, "on_report": on_report, "notify": args.notify}
    if args.command == "replay":
        summary = service.replay(args.pcap, **kwargs)
    else:
        summary = service.watch(args.iface or settings.capture.interface, **kwargs)
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
    for inc in service.incidents(args.limit):
        human = (
            f"{inc.id}  {inc.status:<10} score={inc.score:.2f}  {' > '.join(inc.chain)}  "
            f"{terminal_safe(inc.summary or '')}"
        )
        _out(args, human, inc.model_dump())
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
    checks = service.doctor(settings.secrets_file)
    for c in checks:
        _out(args, f"[{'ok' if c.ok else '!!'}] {c.name}: {c.detail}", c.model_dump())
    return 0 if all(c.ok for c in checks) else 1


def _show_incident(args: argparse.Namespace, service: SentinelService) -> int:
    detail = service.incident(args.incident_id)
    _out(args, format_detail(detail), detail.model_dump())
    return 0


def _notify_test(args: argparse.Namespace, service: SentinelService) -> int:
    delivery = service.notify_test(args.channel)
    _out(args, f"{delivery.channel}: {delivery.status} ({delivery.detail})", delivery.model_dump())
    return 0 if delivery.status == "sent" else 1


def _dispatch(
    args: argparse.Namespace, service: SentinelService, settings: Settings, secrets: Secrets
) -> int:
    handlers: dict[str, Callable[[], int]] = {
        "replay": lambda: _run_stream(args, service, settings),
        "watch": lambda: _run_stream(args, service, settings),
        "incidents": lambda: _list_incidents(args, service),
        "incident": lambda: _show_incident(args, service),
        "notify": lambda: _notify_test(args, service),
        "llm": lambda: _llm_test(args, service),
        "config": lambda: _show_config(args, settings, secrets),
        "doctor": lambda: _doctor(args, service, settings),
    }
    return handlers[args.command]()


def default_service(settings: Settings, secrets: Secrets) -> SentinelService:
    return SentinelService(settings, secrets)


def main(argv: list[str] | None = None, build_service: ServiceFactory = default_service) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    config = args.config or (DEFAULT_CONFIG if DEFAULT_CONFIG.exists() else None)
    try:
        settings = load_settings(config)
        secrets = load_secrets(settings.secrets_file)
    except (ValidationError, SecretsError, OSError, ValueError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 1
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
