from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinel.config.secrets import Secrets, SecretsError, load_secrets
from sentinel.config.settings import load_settings


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
