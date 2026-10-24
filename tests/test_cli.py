import argparse
import json
import os
import re
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from sentinel.api.service import SentinelService
from sentinel.cli import main as cli_main
from sentinel.cli.main import main, parse_duration
from sentinel.config.secrets import Secrets
from sentinel.config.settings import Settings, load_settings
from sentinel.contracts.models import IncidentReport
from sentinel.net.http import Request, Response
from sentinel.sensor.replay import read_pcap
from tests import frames as f
from tests import scenarios as sc
from tools.make_demo_pcap import main as make


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


def test_traffic_filters_narrow_the_view(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    cli(env, "replay", str(env["pcap"]), "--show-traffic", "--host", "192.168.2.30", "--port", "22")
    lines = [ln for ln in capsys.readouterr().out.splitlines() if " -> " in ln]
    assert lines and all("192.168.2.30" in ln and ":22" in ln for ln in lines)
    cli(env, "replay", str(env["pcap"]), "--show-traffic", "--proto", "dns")
    lines = [ln for ln in capsys.readouterr().out.splitlines() if " -> " in ln]
    assert lines and all(":53" in ln for ln in lines)
    cli(env, "replay", str(env["pcap"]), "--show-traffic", "--proto", "arp")
    assert " -> " not in capsys.readouterr().out


def test_incident_show_prints_timeline_with_target(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    cli(env, "replay", str(env["pcap"]))
    capsys.readouterr()
    assert cli(env, "incident", "inc-aabbccddee30-110") == 0
    out = capsys.readouterr().out
    assert "timeline:" in out and "portscan" in out and "-> 192.168.2.20" in out
    assert "unique_dst_ports=200" in out
    assert cli(env, "incident", "nope") == 1
    assert "no incident" in capsys.readouterr().err


def test_config_show_never_prints_secrets(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli(env, "config", "show") == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["credentials_present"] == {
        "slack": True, "discord": False, "telegram": False, "llm_api_key": False,
    }  # fmt: skip
    assert "SECRET" not in out and "hooks.slack" not in out


def test_no_command_prints_help_and_version_works(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "examples:" in capsys.readouterr().out
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0 and capsys.readouterr().out.startswith("sentinel 0.1.0")


def test_notify_flag_warns_when_notifications_are_not_configured(
    env: dict[str, object], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    config = Path(str(env["config"]))
    config.write_text(
        config.read_text().replace("enabled = true\nchannels", "enabled = false\nchannels")
    )
    assert cli(env, "replay", str(env["pcap"]), "--notify") == 0
    assert "--notify has no effect" in capsys.readouterr().err


def test_demo_pcap_tool_produces_all_four_attacks(tmp_path: Path) -> None:
    make(tmp_path / "demo.pcap")
    reports: list[IncidentReport] = []
    service = SentinelService(Settings(database=tmp_path / "s.db"), Secrets())
    service.replay(tmp_path / "demo.pcap", on_report=reports.append)
    service.close()
    chains = {tuple(r.incident.chain) for r in reports}
    assert ("T1046", "T1110") in chains and ("T1071.001", "T1071.004") in chains


def test_closed_output_pipe_is_not_an_error(
    env: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_: object) -> None:
        raise BrokenPipeError

    monkeypatch.setattr(cli_main, "_out", broken)
    monkeypatch.setattr(os, "dup2", lambda *_: 0)
    monkeypatch.setattr(
        sys, "stdout", type("S", (), {"fileno": lambda self: 1, "isatty": lambda self: False})()
    )
    assert cli(env, "replay", str(env["pcap"]), "--show-traffic") == 0


def run_ok(env: dict[str, object], capsys: pytest.CaptureFixture[str], *args: str) -> str:
    assert cli(env, *args) == 0
    return capsys.readouterr().out


def test_init_creates_private_files_and_never_overwrites(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "ws"
    target.mkdir()
    assert main(["init", "--dir", str(target)]) == 0
    assert "created" in capsys.readouterr().out
    assert (target / "secrets.env").stat().st_mode & 0o777 == 0o600
    (target / "config.toml").write_text("# mine\n")
    assert main(["init", "--dir", str(target)]) == 0
    assert "kept" in capsys.readouterr().out
    assert (target / "config.toml").read_text() == "# mine\n"


def test_shipped_config_template_is_valid_and_keeps_the_defaults() -> None:
    template = Path(__file__).resolve().parent.parent / "sentinel/config/templates/config.toml"
    assert load_settings(template) == Settings()


def test_status_summarises_database_incidents_notify_and_llm(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    run_ok(env, capsys, "replay", str(env["pcap"]))
    out = run_ok(env, capsys, "status")
    assert "1 total: 1 explained" in out and "notify     on (slack)" in out
    assert "llm        on (test-model)" in out
    data = json.loads(run_ok(env, capsys, "--json", "status"))
    assert data["incidents_by_status"] == {"explained": 1} and data[
        "channels_with_credentials"
    ] == ["slack"]


def test_ack_dismiss_resolve_by_prefix_with_audit_and_filtering(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    run_ok(env, capsys, "replay", str(env["pcap"]))
    assert "-> acknowledged" in run_ok(env, capsys, "ack", "inc-aabbcc")
    assert "inc-aabbcc" in run_ok(env, capsys, "incidents")  # acknowledged is still open work
    assert "-> dismissed" in run_ok(env, capsys, "dismiss", "inc-aabbccddee30-110")
    assert "no matching incidents" in run_ok(env, capsys, "incidents")
    assert "dismissed" in run_ok(env, capsys, "incidents", "--all")
    assert "-> resolved" in run_ok(env, capsys, "resolve", "inc-aabbccddee30-110")
    svc = SentinelService(load_settings(Path(str(env["config"]))), Secrets())
    actions = [(e.action, e.detail["status"]) for e in svc.storage.audit_entries()]
    svc.close()
    assert actions == [
        ("incident_status", "acknowledged"),
        ("incident_status", "dismissed"),
        ("incident_status", "resolved"),
    ]


def test_unknown_or_ambiguous_incident_references_are_explained(
    env: dict[str, object], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    packets = sc.port_scan(100.0, range(1, 201)) + sc.beacon(0, 20, 30.0)
    sc.write_pcap(tmp_path / "two.pcap", packets)
    run_ok(env, capsys, "replay", str(tmp_path / "two.pcap"))
    assert cli(env, "ack", "inc-aabbccddee") == 1
    assert "ambiguous (2 matches)" in capsys.readouterr().err
    assert cli(env, "ack", "zzz") == 1
    assert "no incident matching" in capsys.readouterr().err


def test_incident_list_filters(env: dict[str, object], capsys: pytest.CaptureFixture[str]) -> None:
    run_ok(env, capsys, "replay", str(env["pcap"]))
    assert "no matching" in run_ok(
        env, capsys, "incidents", "--since", "1h"
    )  # capture is from 1970
    assert "inc-aabbcc" in run_ok(env, capsys, "incidents", "--min-score", "0.5")
    assert "no matching" in run_ok(env, capsys, "incidents", "--min-score", "1.0")


def test_brief_and_multiple_files_and_short_flags(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    pcap = str(env["pcap"])
    out = run_ok(env, capsys, "replay", pcap, pcap, "-b", "-n")
    assert out.count("== ") == 2 and out.count("frames=") == 2
    assert "[CRITICAL" in out and "slack=sent" in out and "what:" not in out
    out = run_ok(env, capsys, "replay", pcap, "-t", "-H", "192.168.2.30", "-p", "22")
    lines = [ln for ln in out.splitlines() if " -> " in ln]
    assert lines and all(":22" in ln for ln in lines)
    assert " -> " not in run_ok(env, capsys, "replay", pcap, "-T")


def test_color_only_when_asked_and_never_in_json(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    assert "\x1b[" in run_ok(env, capsys, "--color", "always", "replay", str(env["pcap"]), "-b")
    assert "\x1b[" not in run_ok(env, capsys, "replay", str(env["pcap"]), "-b")
    assert "\x1b[" not in run_ok(
        env, capsys, "--color", "always", "--json", "replay", str(env["pcap"])
    )


def test_durations_parse_and_reject_nonsense() -> None:
    assert [parse_duration(t) for t in ("90", "90s", "15m", "2h", "1d", "1.5h")] == [
        90,
        90,
        900,
        7200,
        86400,
        5400,
    ]
    for bad in ("", "0", "-5m", "abc", "10x"):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_duration(bad)


def test_watch_passes_the_duration_to_the_capture(
    env: dict[str, object], capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    frames = list(read_pcap(Path(str(env["pcap"]))))
    seen: dict[str, object] = {}

    def fake_capture(
        argv: list[str], duration_seconds: float | None = None, stop: object = None
    ) -> Iterator[tuple[float, bytes]]:
        seen.update(argv=argv, duration=duration_seconds)
        return iter(frames)

    monkeypatch.setattr("sentinel.api.service.capture_live", fake_capture)
    out = run_ok(env, capsys, "watch", "--for", "35s", "--iface", "lo0")
    assert seen["duration"] == 35.0 and seen["argv"][:3] == ["tcpdump", "-i", "lo0"]  # type: ignore[index]
    assert "INCIDENT" in out and "frames=" in out


def test_doctor_works_with_loose_secrets_and_fix_repairs_them(
    env: dict[str, object], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    (tmp_path / "secrets.env").chmod(0o644)
    assert cli(env, "doctor") == 1
    assert "chmod 600" in capsys.readouterr().out
    assert cli(env, "doctor", "--fix") == 0
    assert "fixed" in capsys.readouterr().out
    assert (tmp_path / "secrets.env").stat().st_mode & 0o777 == 0o600


def test_alerts_are_a_solid_red_badge_and_traffic_is_dimmed_when_colour_is_on(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    out = run_ok(env, capsys, "--color", "always", "replay", str(env["pcap"]), "-t", "-b")
    assert re.search(r"\x1b\[1;97;41m \[CRITICAL \d\.\d\d\] \x1b\[0m", out)  # white on red
    alert = next(line for line in out.splitlines() if "CRITICAL" in line)
    assert "\x1b[1;31m" in alert and not alert.startswith("\x1b[2m")  # red text, not dimmed
    traffic = [line for line in out.splitlines() if " -> " in line]
    assert traffic and all(line.startswith("\x1b[2m") for line in traffic)  # dim grey
    lines = out.splitlines()
    at = lines.index(alert)
    assert lines[at - 1] == "" and lines[at + 1] == ""  # space around the alert in the noise


def test_without_colour_the_alert_is_plain_text_and_json_is_never_coloured(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    plain = run_ok(env, capsys, "--color", "never", "replay", str(env["pcap"]), "-t", "-b")
    assert "\x1b[" not in plain and re.search(r"\[CRITICAL \d\.\d\d\] inc-", plain)
    as_json = run_ok(env, capsys, "--color", "always", "--json", "replay", str(env["pcap"]), "-t")
    assert "\x1b[" not in as_json


def test_common_options_work_after_the_command_too(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    out = run_ok(env, capsys, "replay", str(env["pcap"]), "--json", "--color", "never")
    assert json.loads(out.splitlines()[-1])["summary"]["alerts"] >= 1
    assert run_ok(env, capsys, "status", "--json").startswith("{")


def test_history_command_lists_the_permanent_log_with_filters(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    run_ok(env, capsys, "replay", str(env["pcap"]))
    out = run_ok(env, capsys, "history")
    assert "CRITICAL" in out and "portscan" in out and "T1046" in out and "[replay]" in out
    assert "1 of 1 logged anomalies" in out
    assert "no logged anomalies match" in run_ok(env, capsys, "history", "--label", "low")
    assert "no logged anomalies match" in run_ok(env, capsys, "history", "--source", "live")
    assert "no logged anomalies match" in run_ok(
        env, capsys, "history", "--since", "1h"
    )  # capture is 1970
    assert "portscan" in run_ok(env, capsys, "history", "--text", "192.168.2.20")
    row = json.loads(run_ok(env, capsys, "history", "--json").splitlines()[0])
    assert row["label"] == "CRITICAL" and row["evidence"]["unique_dst_ports"] >= 200


def test_ui_refuses_a_missing_capture_file_instead_of_serving_nothing(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--config", str(env["config"]), "ui", "--replay", "nope.pcap", "--no-open"]) == 1
    assert "no such capture file: nope.pcap" in capsys.readouterr().err


def test_devices_command_lists_what_a_replay_saw(
    env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    assert "no devices seen yet" in run_ok(env, capsys, "devices")
    run_ok(env, capsys, "replay", str(env["pcap"]))
    out = run_ok(env, capsys, "devices")
    assert "aa:bb:cc:dd:ee:30" in out and "192.168.2.30" in out and "worst CRITICAL" in out
    assert "no alerts" in out and "devices" in out.splitlines()[-1]
    row = json.loads(run_ok(env, capsys, "devices", "--json", "-n", "1").splitlines()[0])
    assert row["mac"].startswith("aa:bb:cc:dd:ee:") and row["packets"] >= 0
