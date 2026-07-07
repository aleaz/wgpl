"""
WGPL Self-Service Portal — ILLUSTRATIVE EXAMPLE ONLY.

WARNING: This sample exposes VPN QR codes containing private keys.
Do not deploy to production without authentication, TLS, and network isolation.
Set WGPL_PORTAL_API_KEY before starting the server.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

_PORTAL_API_KEY = os.environ.get("WGPL_PORTAL_API_KEY")
if not _PORTAL_API_KEY:
    raise RuntimeError(
        "WGPL_PORTAL_API_KEY must be set before starting this example. "
        "Do not deploy without authentication and network controls."
    )

app = FastAPI(title="WGPL Self-Service Portal")


def verify_api_key(provided: str | None) -> None:
    """Constant-time API key check for the illustrative portal."""
    if not provided or not secrets.compare_digest(provided, _PORTAL_API_KEY):
        raise HTTPException(status_code=401, detail="Unauthorized")


class OnboardRequest(BaseModel):
    employee_name: str = Field(
        min_length=1, max_length=32, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$"
    )
    department: str = Field(
        min_length=1, max_length=32, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$"
    )
    interface_name: str = Field(
        default="wg0", min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$"
    )
    expires: str = Field(default="30d", pattern=r"^[1-9][0-9]*(d|h)$")


@app.post("/api/vpn/onboard")
async def onboard_employee(
    req: OnboardRequest,
    background_tasks: BackgroundTasks,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> FileResponse:
    """
    Onboards a new employee, generates their VPN peer, and returns the QR code.

    Deploy only on a trusted internal network behind a reverse proxy with auth.
    """
    verify_api_key(x_api_key)
    safe_name = f"{req.department}_{req.employee_name}"

    try:
        add_cmd = [
            "wgpl",
            "-j",
            "peer",
            "add",
            req.interface_name,
            safe_name,
            "--expires",
            req.expires,
        ]

        result = subprocess.run(
            add_cmd, capture_output=True, text=True, check=True, timeout=10
        )
        peer_data = json.loads(result.stdout)
        peer_id = peer_data.get("id")

        fd, qr_path = tempfile.mkstemp(suffix=".png")
        os.close(fd)

        qr_cmd = [
            "wgpl",
            "peer",
            "qr",
            peer_id,
            "--interface",
            req.interface_name,
            "-o",
            qr_path,
        ]
        subprocess.run(qr_cmd, check=True, timeout=10)

        if os.path.exists(qr_path):

            def cleanup_qr() -> None:
                if os.path.exists(qr_path):
                    os.remove(qr_path)

            background_tasks.add_task(cleanup_qr)
            return FileResponse(
                qr_path,
                media_type="image/png",
                filename=f"vpn_profile_{safe_name}.png",
            )

        raise HTTPException(status_code=500, detail="QR Code generation failed")

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="WGPL command timed out")
    except subprocess.CalledProcessError:
        raise HTTPException(status_code=400, detail="WGPL command failed")
