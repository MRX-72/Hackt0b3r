"""Secrets from a 0600 KEY=VALUE file, overridden by environment variables. Never logged."""

import os
from collections.abc import Mapping
from pathlib import Path

from pydantic import BaseModel, ConfigDict, SecretStr

KEYS = (
    "SLACK_WEBHOOK_URL",
    "DISCORD_WEBHOOK_URL",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "LLM_API_KEY",
)


class SecretsError(Exception):
    pass


class Secrets(BaseModel):
    model_config = ConfigDict(frozen=True)

    slack_webhook_url: SecretStr | None = None
    discord_webhook_url: SecretStr | None = None
    telegram_bot_token: SecretStr | None = None
    telegram_chat_id: SecretStr | None = None
    llm_api_key: SecretStr | None = None


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
    return Secrets.model_validate({k.lower(): v for k, v in merged.items() if v})
