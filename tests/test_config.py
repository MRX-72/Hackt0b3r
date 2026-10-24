import os
import pwd
from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinel.config.secrets import Secrets, SecretsError, load_secrets
from sentinel.config.settings import find_config, load_settings, sentinel_home


def test_defaults_without_a_file() -> None:
    """R-CFG-001"""
    s = load_settings(None)
    assert s.detection.windows == [10, 300, 3600]
    assert not s.notify.enabled
    assert not s.llm.enabled


def test_toml_overrides_and_int_keys(tmp_path: Path) -> None:
    p = tmp_path / "c.toml"
    p.write_text("[detection]\nwindows = [10]\n[detection.scan_min_unique_ports]\n10 = 5\n")
    s = load_settings(p)
    assert s.detection.windows == [10]
    assert s.detection.scan_min_unique_ports == {10: 5}


@pytest.mark.parametrize(
    "toml",
    ["[detection]\nwindows = [15]\n", "[detection]\nwindows = [10, 600]\n",
     "[detection]\nwindows = []\n", "bogus = 1\n",
     "[notify]\nmin_severity = 2\n", '[llm]\nruntime = "magic"\n'],
)  # fmt: skip
def test_invalid_config_fails_fast(tmp_path: Path, toml: str) -> None:
    p = tmp_path / "c.toml"
    p.write_text(toml)
    with pytest.raises(ValidationError):
        load_settings(p)


def secrets_file(tmp_path: Path, text: str, mode: int = 0o600) -> Path:
    p = tmp_path / "secrets.env"
    p.write_text(text)
    p.chmod(mode)
    return p


@pytest.mark.security
def test_secrets_file_is_read_and_env_wins(tmp_path: Path) -> None:
    p = secrets_file(tmp_path, "# c\nSLACK_WEBHOOK_URL='https://a'\nDISCORD_WEBHOOK_URL=\n")
    s = load_secrets(p, {"DISCORD_WEBHOOK_URL": "https://d", "SLACK_WEBHOOK_URL": "https://env"})
    assert s.slack_webhook_url is not None
    assert s.slack_webhook_url.get_secret_value() == "https://env"
    assert s.discord_webhook_url is not None
    assert s.telegram_bot_token is None


@pytest.mark.security
def test_secrets_are_redacted_in_repr(tmp_path: Path) -> None:
    s = load_secrets(secrets_file(tmp_path, "TELEGRAM_BOT_TOKEN=123:abc\n"), {})
    assert "123:abc" not in repr(s)
    assert "123:abc" not in s.model_dump_json()


@pytest.mark.security
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_loose_permissions_are_refused(tmp_path: Path, mode: int) -> None:
    with pytest.raises(SecretsError, match="chmod 600"):
        load_secrets(secrets_file(tmp_path, "SLACK_WEBHOOK_URL=x\n", mode), {})


def test_unknown_key_and_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SecretsError, match=":1:"):
        load_secrets(secrets_file(tmp_path, "SLAK_WEBHOOK_URL=x\n"), {})
    assert load_secrets(tmp_path / "none.env", {}) == Secrets()


def test_data_lives_in_one_per_user_folder_not_the_working_directory(
    private_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    s = load_settings(None)
    assert s.database == private_home / "sentinel.db"
    assert s.secrets_file == private_home / "secrets.env"
    monkeypatch.delenv("SENTINEL_HOME")
    assert sentinel_home() == Path.home() / ".sentinel"


def test_sudo_uses_the_invoking_users_folder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINEL_HOME")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "someone")
    monkeypatch.setattr(
        pwd,
        "getpwnam",
        lambda _: pwd.struct_passwd(("someone", "x", 501, 20, "", "/Users/someone", "")),
    )
    assert sentinel_home() == Path("/Users/someone/.sentinel")
    monkeypatch.setenv("SUDO_USER", "nobody-such")
    monkeypatch.setattr(pwd, "getpwnam", lambda _: (_ for _ in ()).throw(KeyError()))
    assert sentinel_home() == Path.home() / ".sentinel"


def test_config_discovery_order(
    private_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    assert find_config() is None
    (private_home / "config.toml").write_text("")
    assert find_config() == private_home / "config.toml"
    (work / "config.toml").write_text("")
    assert find_config() == Path("config.toml")
    other = tmp_path / "other.toml"
    other.write_text("")
    monkeypatch.setenv("SENTINEL_CONFIG", str(other))
    assert find_config() == other
    assert find_config(Path("x.toml")) == Path("x.toml")


def test_relative_paths_in_a_config_file_mean_next_to_that_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conf = tmp_path / "etc" / "c.toml"
    conf.parent.mkdir()
    conf.write_text('database = "data/s.db"\nsecrets_file = "~/s.env"\n')
    monkeypatch.chdir(tmp_path.parent)
    s = load_settings(conf)
    assert s.database == (tmp_path / "etc" / "data" / "s.db").resolve()
    assert s.secrets_file == Path.home() / "s.env"


@pytest.mark.security
def test_root_ignores_a_config_that_someone_else_could_have_planted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    planted = work / "config.toml"
    planted.write_text('database = "/etc/cron.d/oops"\n')
    monkeypatch.chdir(work)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", str(os.getuid()))
    assert find_config() == Path("config.toml")  # owned by the invoking user: fine
    monkeypatch.setenv("SUDO_UID", str(os.getuid() + 1))
    assert find_config() is None  # owned by somebody else: ignored
    monkeypatch.setenv("SUDO_UID", str(os.getuid()))
    planted.chmod(0o666)
    assert find_config() is None  # writable by everyone: ignored
    monkeypatch.setattr(os, "geteuid", os.getuid)  # a normal user is unaffected
    assert find_config() == Path("config.toml")
    assert find_config(Path("typed-by-the-user.toml")) == Path("typed-by-the-user.toml")


@pytest.mark.security
@pytest.mark.parametrize(
    ("key", "bad"),
    [
        ("SLACK_WEBHOOK_URL", "http://hooks.slack.test/services/TOPSECRET"),
        ("DISCORD_WEBHOOK_URL", "ftp://discord.test/TOPSECRET"),
        ("TELEGRAM_BOT_TOKEN", "123456:TOPSECRET/../../evil?x="),
        ("TELEGRAM_BOT_TOKEN", "no-colon-TOPSECRET"),
        ("TELEGRAM_CHAT_ID", "12 34; TOPSECRET"),
    ],
)
def test_credentials_of_the_wrong_shape_are_refused_without_echoing_them(
    tmp_path: Path, key: str, bad: str
) -> None:
    f = tmp_path / "s.env"
    f.write_text(f"{key}={bad}\n")
    f.chmod(0o600)
    with pytest.raises(SecretsError) as err:
        load_secrets(f, {})
    assert key in str(err.value)  # says which setting is wrong
    assert "TOPSECRET" not in str(err.value) and "TOPSECRET" not in repr(err.value)


def test_well_formed_credentials_are_accepted(tmp_path: Path) -> None:
    f = tmp_path / "s.env"
    f.write_text(
        "SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T0/B0/xyz\n"
        "DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/1/abc\n"
        "TELEGRAM_BOT_TOKEN=123456789:AAFakeTokenForTestsOnly_abcdefghij0123\n"
        "TELEGRAM_CHAT_ID=-1001234567890\n"
    )
    f.chmod(0o600)
    s = load_secrets(f, {})
    assert (
        s.telegram_chat_id is not None and s.telegram_chat_id.get_secret_value() == "-1001234567890"
    )
    assert load_secrets(f, {"TELEGRAM_CHAT_ID": "@mychannel"}).telegram_chat_id is not None


@pytest.mark.security
def test_a_trailing_newline_or_a_hostless_url_cannot_slip_past_validation(tmp_path: Path) -> None:
    f = tmp_path / "s.env"
    f.write_text("")
    f.chmod(0o600)
    for key, bad in (("SLACK_WEBHOOK_URL", "https://"), ("DISCORD_WEBHOOK_URL", "https:///x")):
        with pytest.raises(SecretsError):
            load_secrets(f, {key: bad})
    # surrounding whitespace in an environment value is stripped, not carried into a URL
    s = load_secrets(f, {"TELEGRAM_BOT_TOKEN": "123:abc-DEF\n", "TELEGRAM_CHAT_ID": " 42 "})
    assert (
        s.telegram_bot_token is not None
        and s.telegram_bot_token.get_secret_value() == "123:abc-DEF"
    )
    with pytest.raises(SecretsError):  # an embedded newline is not whitespace to strip
        load_secrets(f, {"TELEGRAM_BOT_TOKEN": "12\n3:abc"})
