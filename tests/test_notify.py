import json
from collections import deque

import pytest

from raven.config.secrets import Secrets
from raven.config.settings import NotifySettings
from raven.contracts.models import Alert, Delivery, Explanation, Incident, SanitizedIncident
from raven.explain.sanitize import sanitize_incident
from raven.explain.templates import explain_template
from raven.net.http import Request, Response, TransportError
from raven.notify.channels import (
    Notification,
    discord_request,
    slack_escape,
    slack_request,
    telegram_request,
)
from raven.notify.router import Notifier

MAC = "aa:bb:cc:dd:ee:30"
SECRETS = Secrets.model_validate(
    {
        "slack_webhook_url": "https://hooks.slack.test/services/T/B/SECRETSLACK",
        "discord_webhook_url": "https://discord.test/api/webhooks/1/SECRETDISCORD",
        "telegram_bot_token": "123:SECRETTELEGRAM",
        "telegram_chat_id": "42",
    }
)


def incident(
    id: str = "inc-1", severity: float = 0.9, techniques: tuple[str, ...] = ("T1046",)
) -> SanitizedIncident:
    alerts = [
        Alert(
            id=f"a{i}", ts=float(i), detector="portscan", host_mac=MAC, host_ip="192.168.2.30",
            severity=severity, confidence=0.9, evidence={"unique_dst_ports": 50.0}, technique=t,
        )
        for i, t in enumerate(techniques)
    ]  # fmt: skip
    inc = Incident(
        id=id, host_mac=MAC, start_ts=0, end_ts=1, alerts=[a.id for a in alerts],
        chain=list(techniques), score=0.8,
    )  # fmt: skip
    return sanitize_incident(inc, alerts)


class Net:
    """Scripted transport; records requests."""

    def __init__(self, *replies: Response | Exception) -> None:
        self.replies = deque(replies)
        self.requests: list[Request] = []

    def __call__(self, request: Request) -> Response:
        self.requests.append(request)
        reply = self.replies.popleft() if self.replies else Response(200, b"ok")
        if isinstance(reply, Exception):
            raise reply
        return reply


def notifier(net: Net, **over: object) -> tuple[Notifier, list[float], list[tuple[Delivery, str]]]:
    settings = NotifySettings.model_validate(
        {"enabled": True, "channels": ["slack"], "retries": 2, **over}
    )
    sleeps: list[float] = []
    log: list[tuple[Delivery, str]] = []
    clock = {"t": 0.0}

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock["t"] += seconds

    n = Notifier(settings, SECRETS, net, clock=lambda: clock["t"], sleep=sleep)
    n.on_delivery = lambda d, i: log.append((d, i))
    n.clock = clock  # type: ignore[attr-defined]
    return n, sleeps, log


def note(inc: SanitizedIncident | None = None) -> Notification:
    inc = inc or incident()
    return Notification(inc, explain_template(inc), "https://raven.local/inc-1")


def test_slack_payload_matches_incoming_webhook_format() -> None:
    req = slack_request("https://hooks.slack.test/x", note(), 5)
    body = json.loads(req.body or b"")
    assert req.method == "POST" and req.headers["Content-Type"] == "application/json"
    assert body["text"].startswith("[CRITICAL]") and body["blocks"][1]["text"]["type"] == "mrkdwn"
    assert "192.168.2.30" in json.dumps(body)


@pytest.mark.security
def test_slack_escape_neutralises_mentions_and_links() -> None:
    assert (
        slack_escape("<!channel> <@U1> <http://x|y> & z")
        == "&lt;!channel&gt; &lt;@U1&gt; &lt;http://x|y&gt; &amp; z"
    )
    inc = incident()
    hostile = Explanation(
        headline="<!channel> hi", what_happened="<@U123>", likely_cause="x", action_id="monitor",
        suggested_action="y", confidence_note="z", source="llm",
    )  # fmt: skip
    text = (slack_request("https://h", Notification(inc, hostile), 5).body or b"").decode()
    assert "<!channel>" not in text and "<@U123>" not in text


@pytest.mark.security
def test_discord_disables_all_mention_parsing_and_caps_lengths() -> None:
    inc = incident()
    long = Explanation(
        headline="h" * 100, what_happened="w" * 5000, likely_cause="x", action_id="monitor",
        suggested_action="y", confidence_note="z", source="llm",
    )  # fmt: skip
    body = json.loads(discord_request("https://d", Notification(inc, long), 5).body or b"")
    assert body["allowed_mentions"] == {"parse": []}
    assert len(body["embeds"][0]["description"]) <= 1800 and len(body["embeds"][0]["title"]) <= 200


@pytest.mark.security
def test_telegram_uses_html_escaping_and_token_in_path_only() -> None:
    inc = incident()
    e = Explanation(
        headline="<b>x</b> & y", what_happened="a<b", likely_cause="x", action_id="monitor",
        suggested_action="y", confidence_note="z", source="llm",
    )  # fmt: skip
    req = telegram_request("123:TOK", "42", Notification(inc, e), 5)
    body = json.loads(req.body or b"")
    assert req.url == "https://api.telegram.org/bot123:TOK/sendMessage"
    assert body["chat_id"] == "42" and body["parse_mode"] == "HTML" and len(body["text"]) <= 4096
    assert "<b>x</b>" not in body["text"] and "&lt;b&gt;x&lt;/b&gt; &amp; y" in body["text"]
    assert "TOK" not in body["text"]


def test_successful_send_and_delivery_log() -> None:
    net = Net()
    n, _, log = notifier(net)
    [d] = n.notify(incident(), explain_template(incident()))
    assert (d.channel, d.status) == ("slack", "sent")
    assert len(net.requests) == 1 and log == [(d, "inc-1")]


def test_dedupe_resends_only_when_chain_grows() -> None:
    net = Net()
    n, _, _ = notifier(net)
    first = incident()
    n.notify(first, explain_template(first))
    [dup] = n.notify(first, explain_template(first))
    assert dup.status == "skipped" and dup.detail == "already notified"
    grown = incident(techniques=("T1046", "T1110"))
    [again] = n.notify(grown, explain_template(grown))
    assert again.status == "sent" and len(net.requests) == 2


def test_below_min_severity_and_disabled_do_not_send() -> None:
    net = Net()
    n, _, _ = notifier(net, min_severity=0.95)
    [d] = n.notify(incident(severity=0.9), explain_template(incident()))
    assert d.status == "skipped" and net.requests == []
    off, _, _ = notifier(net, enabled=False)
    assert off.notify(incident(), explain_template(incident())) == []


def test_transient_failures_retry_with_backoff_then_succeed() -> None:
    net = Net(Response(500, b""), TransportError("TimeoutError"), Response(200, b"ok"))
    n, sleeps, _ = notifier(net)
    [d] = n.notify(incident(), explain_template(incident()))
    assert d.status == "sent" and len(net.requests) == 3 and sleeps == [1.0, 2.0]


def test_rate_limit_response_honours_retry_after_but_caps_it() -> None:
    net = Net(
        Response(429, b'{"retry_after": 3.5}'),
        Response(429, b'{"parameters": {"retry_after": 999}}'),
        Response(204, b""),
    )
    n, sleeps, _ = notifier(net, channels=["discord"])
    [d] = n.notify(incident(), explain_template(incident()))
    assert d.status == "sent" and sleeps == [3.5, 30.0]


def test_permanent_errors_are_not_retried_and_exhausted_retries_fail() -> None:
    net = Net(Response(404, b"no_service"))
    n, sleeps, _ = notifier(net)
    [d] = n.notify(incident(), explain_template(incident()))
    assert (
        d.status == "failed" and d.detail == "HTTP 404" and len(net.requests) == 1 and sleeps == []
    )
    net2 = Net(Response(503, b""), Response(503, b""), Response(503, b""))
    n2, _, _ = notifier(net2)
    [d2] = n2.notify(incident(), explain_template(incident()))
    assert d2.status == "failed" and len(net2.requests) == 3


def test_telegram_ok_false_is_a_failure() -> None:
    net = Net(Response(200, b'{"ok": false, "description": "chat not found"}'))
    n, _, _ = notifier(net, channels=["telegram"], retries=0)
    [d] = n.notify(incident(), explain_template(incident()))
    assert d.status == "failed"
    good = Net(Response(200, b'{"ok": true, "result": {}}'))
    n2, _, _ = notifier(good, channels=["telegram"])
    assert n2.notify(incident(), explain_template(incident()))[0].status == "sent"


def test_circuit_breaker_opens_then_recovers_after_cooloff() -> None:
    net = Net(*[Response(400, b"")] * 3, Response(200, b"ok"))
    n, _, _ = notifier(net, breaker_failures=3, breaker_cooloff_seconds=100, retries=0)
    for i in range(3):
        n.notify(incident(f"i{i}"), explain_template(incident()))
    [blocked] = n.notify(incident("i3"), explain_template(incident()))
    assert (
        blocked.status == "skipped"
        and blocked.detail.startswith("circuit open")
        and len(net.requests) == 3
    )
    n.clock["t"] += 101.0  # type: ignore[attr-defined]
    [ok] = n.notify(incident("i4"), explain_template(incident()))
    assert ok.status == "sent"


def test_per_channel_rate_limit() -> None:
    net = Net()
    n, _, _ = notifier(net, max_per_minute=2)
    results = [
        n.notify(incident(f"i{i}"), explain_template(incident()))[0].status for i in range(3)
    ]
    assert results == ["sent", "sent", "skipped"]


def test_missing_credentials_skip_only_that_channel() -> None:
    net = Net()
    settings = NotifySettings(enabled=True, channels=["slack", "telegram"])
    only_slack = Secrets.model_validate({"slack_webhook_url": "https://h"})
    out = Notifier(settings, only_slack, net).notify(incident(), explain_template(incident()))
    assert [(d.channel, d.status) for d in out] == [("slack", "sent"), ("telegram", "skipped")]


@pytest.mark.security
def test_failure_details_never_contain_secrets_and_never_raise() -> None:
    net = Net(TransportError("ConnectionRefusedError"), TransportError("x"), TransportError("y"))
    n, _, _ = notifier(net, channels=["slack", "discord", "telegram"], retries=0)
    deliveries = n.notify(incident(), explain_template(incident()))
    blob = json.dumps([d.model_dump() for d in deliveries])
    for secret in ("SECRETSLACK", "SECRETDISCORD", "SECRETTELEGRAM", "hooks.slack.test"):
        assert secret not in blob
    assert all(d.status == "failed" for d in deliveries)


def test_manual_test_ignores_enabled_flag_and_dedupe() -> None:
    net = Net()
    n, _, _ = notifier(net, enabled=False)
    assert n.test("slack", incident(), explain_template(incident())).status == "sent"


def test_every_channel_shows_the_target() -> None:
    inc = incident()
    inc = inc.model_copy(
        update={"steps": [inc.steps[0].model_copy(update={"target_ip": "192.168.2.20"})]}
    )
    n = Notification(inc, explain_template(inc))
    for req in (
        slack_request("https://h", n, 5),
        discord_request("https://d", n, 5),
        telegram_request("1:t", "42", n, 5),
    ):
        assert "192.168.2.20" in (req.body or b"").decode()
