"""Static composition root for internal projections."""

from .engine import ProjectionEngine
from .snapshots import ClientSnapshot, ServerSnapshot
from .wireguard import WireGuardProjection


_WIREGUARD = WireGuardProjection()
_WIREGUARD_ID = _WIREGUARD.identifier
_ENGINE = ProjectionEngine({_WIREGUARD_ID: _WIREGUARD})


def render_wireguard_server(snapshot: ServerSnapshot) -> str:
    return _ENGINE.render_server(_WIREGUARD_ID, snapshot)


def render_wireguard_client(snapshot: ClientSnapshot) -> str:
    return _ENGINE.render_client(_WIREGUARD_ID, snapshot)
