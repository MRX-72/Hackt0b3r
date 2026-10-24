from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def private_home(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Path:
    """No test may touch the real ~/.raven (history, config, secrets)."""
    home = tmp_path_factory.mktemp("raven-home")
    monkeypatch.setenv("RAVEN_HOME", str(home))
    monkeypatch.delenv("RAVEN_CONFIG", raising=False)
    return home
