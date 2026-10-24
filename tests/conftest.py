from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def private_home(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Path:
    """No test may touch the real ~/.sentinel (history, config, secrets)."""
    home = tmp_path_factory.mktemp("sentinel-home")
    monkeypatch.setenv("SENTINEL_HOME", str(home))
    monkeypatch.delenv("SENTINEL_CONFIG", raising=False)
    return home
