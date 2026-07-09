import importlib.util
import os
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
HTTPException = fastapi.HTTPException


def _load_fastapi_example():
    path = Path(__file__).resolve().parents[1] / "examples" / "fastapi-self-service.py"
    os.environ.setdefault("WGPL_PORTAL_API_KEY", "test-portal-key")
    spec = importlib.util.spec_from_file_location("fastapi_self_service", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fastapi_example_requires_api_key_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("WGPL_PORTAL_API_KEY", raising=False)
    path = Path(__file__).resolve().parents[1] / "examples" / "fastapi-self-service.py"
    spec = importlib.util.spec_from_file_location("fastapi_self_service_fail", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    with pytest.raises(RuntimeError, match="WGPL_PORTAL_API_KEY"):
        spec.loader.exec_module(module)


def test_verify_api_key_rejects_missing() -> None:
    module = _load_fastapi_example()
    with pytest.raises(HTTPException) as exc:
        module.verify_api_key(None)
    assert exc.value.status_code == 401


def test_verify_api_key_rejects_invalid() -> None:
    module = _load_fastapi_example()
    with pytest.raises(HTTPException) as exc:
        module.verify_api_key("wrong-key")
    assert exc.value.status_code == 401


def test_verify_api_key_accepts_valid() -> None:
    module = _load_fastapi_example()
    module.verify_api_key("test-portal-key")
