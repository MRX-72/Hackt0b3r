"""Slack, Discord and Telegram request builders. Payload formats: docs/FACTS.md."""

import html
from collections.abc import Callable
from dataclasses import dataclass

from raven.config.secrets import Secrets
from raven.contracts.models import Channel, Explanation, SanitizedIncident
from raven.contracts.severity import severity_label
from raven.net.http import Request, json_request

# Conservative limits below the documented ones (Discord content 2000, Telegram text 4096).
_SLACK_MAX = 2900
_DISCORD_DESC_MAX = 1800
_DISCORD_TITLE_MAX = 200
_TELEGRAM_MAX = 3800
_DISCORD_COLORS = {"critical": 0xB71C1C, "high": 0xE65100, "medium": 0xF9A825, "low": 0x1565C0}

Builder = Callable[[str, "Notification"], Request]


@dataclass(frozen=True)
class Notification:
    incident: SanitizedIncident
    explanation: Explanation
    link: str | None = None

    @property
    def severity_label(self) -> str:
        return severity_label(self.incident.score)

    @property
    def targets(self) -> str:
        found = dict.fromkeys(str(s.target_ip) for s in self.incident.steps if s.target_ip)
        return ", ".join(found) or "n/a"

    @property
    def techniques(self) -> str:
        names = {s.technique: s.technique_name for s in self.incident.steps}
        return ", ".join(f"{t} {n}" for t, n in names.items())

    def lines(self) -> list[str]:
        e = self.explanation
        out = [
            e.what_happened,
            e.likely_cause,
            f"Suggested: {e.suggested_action}",
            e.confidence_note,
        ]
        if self.link:
            out.append(f"Details: {self.link}")
        return out


def slack_escape(text: str) -> str:
    """Slack control characters; stops <!channel>, <@U123> and <url|label> from being parsed."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_request(webhook_url: str, n: Notification, timeout: float) -> Request:
    head = f"[{n.severity_label.upper()}] {slack_escape(n.explanation.headline)}"
    body = "\n".join(slack_escape(line) for line in n.lines())[:_SLACK_MAX]
    meta = f"Device {n.incident.host_ip} | Target {n.targets} | {slack_escape(n.techniques)}"
    payload = {
        "text": head,
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": head[:150]}},
            {"type": "section", "text": {"type": "mrkdwn", "text": body}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": meta}]},
        ],
    }
    return json_request("POST", webhook_url, payload, timeout=timeout)


def discord_request(webhook_url: str, n: Notification, timeout: float) -> Request:
    payload = {
        "username": "Raven",
        "allowed_mentions": {"parse": []},  # no @everyone/@role/@user pings from any text
        "embeds": [
            {
                "title": f"[{n.severity_label.upper()}] {n.explanation.headline}"[
                    :_DISCORD_TITLE_MAX
                ],
                "description": "\n".join(n.lines())[:_DISCORD_DESC_MAX],
                "color": _DISCORD_COLORS[n.severity_label],
                "fields": [
                    {"name": "Device", "value": str(n.incident.host_ip), "inline": True},
                    {"name": "Target", "value": n.targets[:200], "inline": True},
                    {"name": "ATT&CK", "value": n.techniques[:900] or "n/a", "inline": True},
                ],
            }
        ],
    }
    return json_request("POST", webhook_url, payload, timeout=timeout)


def telegram_request(token: str, chat_id: str, n: Notification, timeout: float) -> Request:
    lines = [
        f"<b>[{n.severity_label.upper()}] {html.escape(n.explanation.headline, quote=False)}</b>"
    ]
    lines += [html.escape(line, quote=False) for line in n.lines()]
    lines.append(
        f"Device {n.incident.host_ip} | Target {n.targets} | "
        f"{html.escape(n.techniques, quote=False)}"
    )
    payload = {"chat_id": chat_id, "text": "\n".join(lines)[:_TELEGRAM_MAX], "parse_mode": "HTML"}
    return json_request(
        "POST", f"https://api.telegram.org/bot{token}/sendMessage", payload, timeout=timeout
    )


def build_builders(
    secrets: Secrets, timeout: float
) -> dict[Channel, Callable[[Notification], Request]]:
    """Request builders for the channels that have credentials."""
    out: dict[Channel, Callable[[Notification], Request]] = {}
    if secrets.slack_webhook_url:
        url = secrets.slack_webhook_url.get_secret_value()
        out["slack"] = lambda n: slack_request(url, n, timeout)
    if secrets.discord_webhook_url:
        durl = secrets.discord_webhook_url.get_secret_value()
        out["discord"] = lambda n: discord_request(durl, n, timeout)
    if secrets.telegram_bot_token and secrets.telegram_chat_id:
        token = secrets.telegram_bot_token.get_secret_value()
        chat = secrets.telegram_chat_id.get_secret_value()
        out["telegram"] = lambda n: telegram_request(token, chat, n, timeout)
    return out
