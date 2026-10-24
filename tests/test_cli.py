import json
import re
from pathlib import Path

import pytest

from sentinel.api.service import SentinelService
from sentinel.cli.main import main
from sentinel.config.secrets import Secrets
from sentinel.config.settings import Settings
from sentinel.net.http import Request, Response
from tests import frames as f
from tests import scenarios as sc


class Net:
    def __init__(self) -> None:
        self.requests: list[Request] = []

    def __call__(self, request: Request) -> Response:
        self.requests.append(request)
        if request.url.endswith("/api/tags"):
            return Response(200, json.dumps({"models": [{"name": "test-model"}]}).encode())
        if request.url.endswith("/api/chat"):
            content = {
                "headline": "Device shows suspicious activity",
                "what_happened": "The device behaved in an unusual way.",
                "likely_cause": "This may be unwanted software.",
                "action_id": "investigate_device",
                "confidence_note": "Please verify.",
            }
            return Response(200, json.dumps({"message": {"content": json.dumps(content)}}).encode())
        return Response(200, b"ok")


@pytest.fixture
def env(tmp_path: Path) -> dict[str, object]:
    secrets = tmp_path / "secrets.env"
    secrets.write_text("SLACK_WEBHOOK_URL=https://hooks.slack.test/services/SECRET\n")
    secrets.chmod(0o600)
    config = tmp_path / "config.toml"
    config.write_text(
        f'database = "{tmp_path / "s.db"}"\nsecrets_file = "{secrets}"\n'
        '[notify]\nenabled = true\nchannels = ["slack"]\n'
        '[llm]\nenabled = true\nmodel = "test-model"\n'
    )
    pcap = tmp_path / "a.pcap"
    sc.write_pcap(pcap, sc.normal_browsing(0, 300, sc.USER) + sc.port_scan(100.0, range(1, 201)))
    net = Net()

    def factory(settings: Settings, secrets_: Secrets) -> SentinelService:
        return SentinelService(settings, secrets_, net)

    return {"config": str(config), "pcap": str(pcap), "factory": factory, "net": net}


def cli(env: dict[str, object], *args: str) -> int:
    return main(["--config", str(env["config"]), *args], env["factory"])  # type: ignore[arg-type]


FLOW_LINE = re.compile(r"\d\d:\d\d:\d\d\.\d{3} 192\.168\.2\.30:\d+ -> 192\.168\.2\.20:\d+ tcp")


def test_replay_hides_traffic_by_default_and_prints_incidents(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli(env, "replay", str(env["pcap"])) == 0
    out = capsys.readouterr().out
    assert "INCIDENT [" in out and "T1046" in out and "frames=" in out
    assert not FLOW_LINE.search(out)


def test_show_traffic_flag_prints_one_line_per_event(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli(env, "replay", str(env["pcap"]), "--show-traffic") == 0
    out = capsys.readouterr().out
    assert FLOW_LINE.search(out) and "dns? " in out and "SYN" not in out
    assert out.count("\n") > 400


def test_config_can_turn_traffic_on_and_no_traffic_overrides_it(
    env: dict[str, object], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    config = Path(str(env["config"]))
    config.write_text(
        config.read_text().replace("[notify]", "[cli]\nshow_traffic = true\n[notify]")
    )
    cli(env, "replay", str(env["pcap"]))
    assert FLOW_LINE.search(capsys.readouterr().out)
    cli(env, "replay", str(env["pcap"]), "--no-traffic")
    assert not FLOW_LINE.search(capsys.readouterr().out)


def test_json_mode_emits_parseable_lines(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli(env, "--json", "replay", str(env["pcap"]), "--show-traffic") == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    kinds = {next(iter(line)) for line in lines}
    assert kinds == {"event", "report", "summary"}
    assert lines[-1]["summary"]["alerts"] >= 1


def test_notifications_only_when_asked(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    net: Net = env["net"]  # type: ignore[assignment]
    cli(env, "replay", str(env["pcap"]))
    assert not [r for r in net.requests if "slack" in r.url]
    cli(env, "replay", str(env["pcap"]), "--notify")
    assert [r for r in net.requests if "slack" in r.url]
    assert "slack=sent" in capsys.readouterr().out


def test_incidents_lists_stored_incidents(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    cli(env, "replay", str(env["pcap"]))
    capsys.readouterr()
    assert cli(env, "incidents") == 0
    assert "inc-aabbccddee30" in capsys.readouterr().out


def test_notify_test_and_llm_test_and_doctor(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli(env, "notify", "test", "slack") == 0
    assert "slack: sent" in capsys.readouterr().out
    assert cli(env, "notify", "test", "discord") == 1  # no credentials
    assert "skipped" in capsys.readouterr().out
    assert cli(env, "llm", "test") == 0
    out = capsys.readouterr().out
    assert "models: test-model" in out and "source: llm" in out
    cli(env, "doctor")
    doctor = capsys.readouterr().out
    assert "[ok] secrets file" in doctor and "[ok] llm server" in doctor


def test_errors_are_one_line_and_exit_nonzero(
    env: dict[str, object], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    assert cli(env, "replay", str(tmp_path / "missing.pcap")) == 1
    assert "error:" in capsys.readouterr().err
    bad = tmp_path / "bad.toml"
    bad.write_text("bogus = 1\n")
    assert main(["--config", str(bad), "doctor"]) == 1
    assert "configuration error" in capsys.readouterr().err


@pytest.mark.security
def test_loose_secrets_permissions_stop_the_cli_before_anything_is_sent(
    env: dict[str, object], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    (tmp_path / "secrets.env").chmod(0o644)
    assert cli(env, "notify", "test", "slack") == 1
    assert "chmod 600" in capsys.readouterr().err
    net: Net = env["net"]  # type: ignore[assignment]
    assert net.requests == []


@pytest.mark.security
def test_hostile_dns_names_are_escaped_in_the_traffic_view(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    name = bytes([5]) + b"a\x1b[2J" + b"\x03com\x00"
    packet = (1.0, f.eth(f.ipv4(17, f.udp(40000, 53, f.dns_query(name)))))
    pcap = tmp_path / "h.pcap"
    sc.write_pcap(pcap, [packet])
    config = tmp_path / "c.toml"
    config.write_text(
        f'database = "{tmp_path / "s.db"}"\nsecrets_file = "{tmp_path / "none.env"}"\n'
    )
    assert main(["--config", str(config), "replay", str(pcap), "--show-traffic"]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\\x1b" in out
