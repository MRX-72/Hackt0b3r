"""`sentinel` command line. A thin client of the service facade: parse args, call, format."""

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from sentinel.api.service import SentinelService, ServiceError
from sentinel.cli.render import format_event, format_report, format_summary
from sentinel.config.secrets import Secrets, SecretsError, load_secrets
from sentinel.config.settings import Settings, load_settings
from sentinel.contracts.models import Event, IncidentReport
from sentinel.contracts.text import terminal_safe

ServiceFactory = Callable[[Settings, Secrets], SentinelService]
DEFAULT_CONFIG = Path("config.toml")
CHANNEL_CHOICES = ("slack", "discord", "telegram")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description="Small-network anomaly detector")
    p.add_argument(
        "--config", type=Path, help=f"settings file (default: {DEFAULT_CONFIG} if present)"
    )
    p.add_argument("--json", action="store_true", help="machine-readable output (JSON lines)")
    sub = p.add_subparsers(dest="command", required=True)

    def traffic_flags(sp: argparse.ArgumentParser) -> None:
        group = sp.add_mutually_exclusive_group()
        group.add_argument("--show-traffic", dest="traffic", action="store_const", const=True,
                           help="print every packet event as it is processed")  # fmt: skip
        group.add_argument("--no-traffic", dest="traffic", action="store_const", const=False,
                           help="do not print traffic (overrides config)")  # fmt: skip
        sp.add_argument(
            "--notify", action="store_true", help="send notifications for new incidents"
        )

    replay = sub.add_parser("replay", help="run a pcap/pcapng file through the detection pipeline")
    replay.add_argument("pcap", type=Path)
    traffic_flags(replay)
    watch = sub.add_parser("watch", help="capture live traffic with tcpdump (needs sudo)")
    watch.add_argument("--iface", help="interface (default: [capture] interface)")
    traffic_flags(watch)
    inc = sub.add_parser("incidents", help="list recent stored incidents")
    inc.add_argument("--limit", type=int, default=20)
    notify = sub.add_parser("notify", help="notification utilities")
    notify_sub = notify.add_subparsers(dest="notify_command", required=True)
    test = notify_sub.add_parser("test", help="send a sample incident to one channel")
    test.add_argument("channel", choices=CHANNEL_CHOICES)
    llm = sub.add_parser("llm", help="LLM utilities")
    llm_sub = llm.add_subparsers(dest="llm_command", required=True)
    llm_sub.add_parser("test", help="list models and summarise a sample incident")
    sub.add_parser("doctor", help="check configuration, credentials, interface and LLM server")
    return p


def _out(args: argparse.Namespace, human: str, data: Any) -> None:
    print(json.dumps(data) if args.json else human, flush=True)


def _event_json(event: Event) -> dict[str, Any]:
    return {"type": type(event).__name__, **event.model_dump()}


def _run_stream(args: argparse.Namespace, service: SentinelService, settings: Settings) -> int:
    show = settings.cli.show_traffic if args.traffic is None else args.traffic

    def on_event(event: Event) -> None:
        _out(args, format_event(event), {"event": _event_json(event)})

    def on_report(report: IncidentReport) -> None:
        _out(args, format_report(report), {"report": report.model_dump()})

    kwargs = {"on_event": on_event if show else None, "on_report": on_report, "notify": args.notify}
    if args.command == "replay":
        summary = service.replay(args.pcap, **kwargs)
    else:
        summary = service.watch(args.iface or settings.capture.interface, **kwargs)
    _out(args, format_summary(summary), {"summary": summary.model_dump()})
    return 0


def _dispatch(args: argparse.Namespace, service: SentinelService, settings: Settings) -> int:
    if args.command in ("replay", "watch"):
        return _run_stream(args, service, settings)
    if args.command == "incidents":
        for inc in service.incidents(args.limit):
            _out(
                args,
                f"{inc.id}  {inc.status:<10} score={inc.score:.2f}  "
                f"{' > '.join(inc.chain)}  {terminal_safe(inc.summary or '')}",
                inc.model_dump(),
            )
        return 0
    if args.command == "notify":
        delivery = service.notify_test(args.channel)
        _out(
            args,
            f"{delivery.channel}: {delivery.status} ({delivery.detail})",
            delivery.model_dump(),
        )
        return 0 if delivery.status == "sent" else 1
    if args.command == "llm":
        result = service.llm_test()
        e = result.explanation
        human = (
            f"models: {', '.join(result.models) or '(none listed)'}\n"
            f"source: {e.source}"
            + (f" (fallback: {result.fallback_reason})" if result.fallback_reason else "")
            + f"\n{e.headline}\n{e.what_happened}\n{e.likely_cause}\n{e.suggested_action}"
        )
        _out(args, human, result.model_dump())
        return 0 if e.source == "llm" else 1
    checks = service.doctor(settings.secrets_file)
    for c in checks:
        _out(args, f"[{'ok' if c.ok else '!!'}] {c.name}: {c.detail}", c.model_dump())
    return 0 if all(c.ok for c in checks if "optional" not in c.detail) else 1


def default_service(settings: Settings, secrets: Secrets) -> SentinelService:
    return SentinelService(settings, secrets)


def main(argv: list[str] | None = None, build_service: ServiceFactory = default_service) -> int:
    args = _parser().parse_args(argv)
    config = args.config or (DEFAULT_CONFIG if DEFAULT_CONFIG.exists() else None)
    try:
        settings = load_settings(config)
        secrets = load_secrets(settings.secrets_file)
    except (ValidationError, SecretsError, OSError, ValueError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 1
    service = build_service(settings, secrets)
    try:
        return _dispatch(args, service, settings)
    except ServiceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        service.close()


if __name__ == "__main__":
    sys.exit(main())
