import os
import tempfile

import pytest

from wgpl import db, wireguard


@pytest.fixture
def wgpl_db(monkeypatch: pytest.MonkeyPatch) -> str:
    """Isolated SQLite database for each test."""
    path = os.path.join(tempfile.mkdtemp(), "wgpl.db")
    monkeypatch.setenv("WGPL_DB_PATH", path)
    db.init_db(path)
    yield path


@pytest.fixture
def wg0_interface(wgpl_db: str) -> str:
    """Register wg0 with a /24 pool."""
    public_key = wireguard.generate_keypair().public_key
    db.add_interface("wg0", "vpn.example.com", public_key, "10.0.0.0/24", 51820)
    return "wg0"
