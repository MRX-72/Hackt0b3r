"""Secrets from a 0600 KEY=VALUE file, overridden by environment variables. Never logged."""

import os
import re
from collections.abc import Mapping
from pathlib import Path

from pydantic import BaseModel, ConfigDict, SecretStr, ValidationError, field_validator

KEYS = (
    "SLACK_WEBHOOK_URL",
    "DISCORD_WEBHOOK_URL",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "LLM_API_KEY",
)


class SecretsError(Exception):
    pass


_TELEGRAM_TOKEN = re.compile(r"^\d+:[A-Za-z0-9_-]+$")  # goes into a URL path: no / ? # allowed
_TELEGRAM_CHAT = re.compile(r"^(-?\d+|@[A-Za-z0-9_]{3,})$")


class Secrets(BaseModel):
    # An invalid value must not be echoed back in the error text (it is a secret).
    model_config = ConfigDict(frozen=True, hide_input_in_errors=True)

    slack_webhook_url: SecretStr | None = None
    discord_webhook_url: SecretStr | None = None
    telegram_bot_token: SecretStr | None = None
    telegram_chat_id: SecretStr | None = None
    llm_api_key: SecretStr | None = None

    @field_validator("slack_webhook_url", "discord_webhook_url")
    @classmethod
    def _https_only(cls, v: SecretStr | None) -> SecretStr | None:
        """A webhook is a bearer secret: it must never travel over plain http."""
        return _check(v, v is not None and v.get_secret_value().startswith("https://"),
                      "a webhook URL must start with https://")  # fmt: skip

    @field_validator("telegram_bot_token")
    @classmethod
    def _token_shape(cls, v: SecretStr | None) -> SecretStr | None:
        return _check(v, v is not None and bool(_TELEGRAM_TOKEN.match(v.get_secret_value())),
                      "a Telegram bot token looks like 123456:ABC-def")  # fmt: skip

    @field_validator("telegram_chat_id")
    @classmethod
    def _chat_shape(cls, v: SecretStr | None) -> SecretStr | None:
        return _check(v, v is not None and bool(_TELEGRAM_CHAT.match(v.get_secret_value())),
                      "a Telegram chat id is a number or @channelname")  # fmt: skip


def _check(value: SecretStr | None, ok: bool, message: str) -> SecretStr | None:
    if value is not None and not ok:
        raise ValueError(message)
    return value


def _read_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    if path.stat().st_mode & 0o077:
        raise SecretsError(f"{path} must not be readable by group/others: run chmod 600 {path}")
    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or key.strip() not in KEYS:
            raise SecretsError(f"{path}:{number}: expected one of {', '.join(KEYS)} as KEY=VALUE")
        values[key.strip()] = value.strip().strip("'\"")
    return values


def load_secrets(path: Path, environ: Mapping[str, str] | None = None) -> Secrets:
    env = os.environ if environ is None else environ
    merged = _read_file(path) | {k: env[k] for k in KEYS if env.get(k)}
    try:
        return Secrets.model_validate({k.lower(): v for k, v in merged.items() if v})
    except (
        ValidationError
    ) as exc:  # becomes the same error as a bad file mode: doctor can report it
        problems = "; ".join(
            f"{str(e['loc'][0]).upper()}: {e['msg'].removeprefix('Value error, ')}"
            for e in exc.errors()
        )
        raise SecretsError(f"{path}: {problems}") from None
