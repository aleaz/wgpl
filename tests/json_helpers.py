"""Helpers for asserting CLI ``--json`` stdout envelopes."""

from __future__ import annotations

import json
from typing import Any


def json_success_data(result: Any) -> Any:
    """Parse --json stdout; require success envelope and return data."""
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    assert payload.get("status") == "success", payload
    assert "data" in payload, payload
    return payload["data"]


def json_status_payload(result: Any) -> dict[str, Any]:
    """Parse --json stdout for typed status reports (validate/doctor/actions)."""
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    assert "status" in payload, payload
    return payload
