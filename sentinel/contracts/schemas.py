"""JSON Schemas exported from the contracts (`make schemas`); a test checks they are current."""

import json
from pathlib import Path

from pydantic import BaseModel

from sentinel.contracts.models import (
    Alert,
    ArpEvent,
    AuditEntry,
    DhcpEvent,
    Flow,
    Incident,
    MdnsEvent,
)

MODELS: tuple[type[BaseModel], ...] = (
    Flow,
    ArpEvent,
    DhcpEvent,
    MdnsEvent,
    Alert,
    Incident,
    AuditEntry,
)
SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"


def render() -> dict[str, str]:
    return {
        f"{m.__name__}.json": json.dumps(m.model_json_schema(), indent=2, sort_keys=True) + "\n"
        for m in MODELS
    }


if __name__ == "__main__":
    SCHEMA_DIR.mkdir(exist_ok=True)
    for name, text in render().items():
        (SCHEMA_DIR / name).write_text(text)
