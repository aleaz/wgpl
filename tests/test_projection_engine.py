"""Isolated tests for Stage 1 projection dispatch."""

from collections.abc import Callable

import pytest

from wgpl.exceptions import (
    ProjectionRenderError,
    UnknownProjectionError,
    WgplException,
)
from wgpl.projection.contracts import Projection
from wgpl.projection.engine import ProjectionEngine
from wgpl.projection.snapshots import (
    ClientSnapshot,
    ServerPeerSnapshot,
    ServerSnapshot,
)


SERVER_SECRET = "server-snapshot-secret"
SERVER_PSK = "server-snapshot-psk"
CLIENT_SECRET = "client-snapshot-private"
CLIENT_PSK = "client-snapshot-psk"


def _server_snapshot() -> ServerSnapshot:
    return ServerSnapshot(
        interface_name="wg0",
        mtu=None,
        peers=(
            ServerPeerSnapshot(
                public_key=SERVER_SECRET,
                preshared_key=SERVER_PSK,
                allowed_ips=("10.0.0.2/32",),
            ),
        ),
    )


def _client_snapshot() -> ClientSnapshot:
    return ClientSnapshot(
        private_key=CLIENT_SECRET,
        ip_address="10.0.0.2",
        address_prefix_length=24,
        dns=None,
        mtu=None,
        server_public_key=SERVER_SECRET,
        preshared_key=CLIENT_PSK,
        endpoint="vpn.example.com",
        port=51820,
        allowed_ips=("10.0.0.0/24",),
        keepalive=None,
    )


class RecordingProjection:
    identifier = "recording"

    def __init__(self) -> None:
        self.server_snapshot: ServerSnapshot | None = None
        self.client_snapshot: ClientSnapshot | None = None

    def render_server(self, snapshot: ServerSnapshot) -> str:
        self.server_snapshot = snapshot
        return "server-artifact"

    def render_client(self, snapshot: ClientSnapshot) -> str:
        self.client_snapshot = snapshot
        return "client-artifact"


class FailingProjection:
    identifier = "failing"

    def __init__(self, error: BaseException) -> None:
        self.error = error

    def render_server(self, snapshot: ServerSnapshot) -> str:
        raise self.error

    def render_client(self, snapshot: ClientSnapshot) -> str:
        raise self.error


class SecretInspectingProjection:
    identifier = "failing"

    @staticmethod
    def _fail_after_inspection() -> str:
        try:
            raise LookupError("low-level renderer failure")
        except LookupError:
            raise RuntimeError("adapter failure")

    def render_server(self, snapshot: ServerSnapshot) -> str:
        assert snapshot.peers[0].public_key == SERVER_SECRET
        assert snapshot.peers[0].preshared_key == SERVER_PSK
        return self._fail_after_inspection()

    def render_client(self, snapshot: ClientSnapshot) -> str:
        assert snapshot.private_key == CLIENT_SECRET
        assert snapshot.server_public_key == SERVER_SECRET
        assert snapshot.preshared_key == CLIENT_PSK
        return self._fail_after_inspection()


def _exception_messages(error: BaseException) -> tuple[str, ...]:
    messages: list[str] = []
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        messages.append(str(current))
        current = current.__cause__ or current.__context__
    return tuple(messages)


def test_projection_protocol_is_satisfied_structurally() -> None:
    projection: Projection = RecordingProjection()

    assert projection.identifier == "recording"


def test_engine_dispatches_target_methods_with_snapshot_identity() -> None:
    projection = RecordingProjection()
    engine = ProjectionEngine({"recording": projection})
    server = _server_snapshot()
    client = _client_snapshot()

    assert engine.render_server("recording", server) == "server-artifact"
    assert engine.render_client("recording", client) == "client-artifact"
    assert projection.server_snapshot is server
    assert projection.client_snapshot is client


def test_engine_copies_supplied_registry() -> None:
    projection = RecordingProjection()
    registry: dict[str, Projection] = {"recording": projection}
    engine = ProjectionEngine(registry)

    registry.clear()

    assert engine.render_server("recording", _server_snapshot()) == "server-artifact"


def test_engine_rejects_empty_identifier() -> None:
    projection = RecordingProjection()

    with pytest.raises(
        ValueError, match="^Projection identifier must not be empty$"
    ):
        ProjectionEngine({"": projection})


def test_engine_rejects_registry_identifier_mismatch() -> None:
    projection = RecordingProjection()

    with pytest.raises(
        ValueError,
        match=r"^Projection registry key must match projection\.identifier$",
    ):
        ProjectionEngine({"other": projection})


def test_unknown_projection_error_is_exact() -> None:
    engine = ProjectionEngine({})

    with pytest.raises(UnknownProjectionError) as exc_info:
        engine.render_server("missing", _server_snapshot())

    assert str(exc_info.value) == "Unknown projection 'missing'"
    assert exc_info.value.__cause__ is None


@pytest.mark.parametrize(
    "invoke",
    [
        lambda engine: engine.render_server("failing", _server_snapshot()),
        lambda engine: engine.render_client("failing", _client_snapshot()),
    ],
    ids=["server", "client"],
)
def test_engine_preserves_wgpl_exception_identity(
    invoke: Callable[[ProjectionEngine], str],
) -> None:
    domain_error = WgplException("domain failure")
    engine = ProjectionEngine({"failing": FailingProjection(domain_error)})

    with pytest.raises(WgplException) as exc_info:
        invoke(engine)

    assert exc_info.value is domain_error


def test_unexpected_server_error_is_wrapped_with_cause() -> None:
    cause = RuntimeError("renderer failed")
    engine = ProjectionEngine({"failing": FailingProjection(cause)})

    with pytest.raises(ProjectionRenderError) as exc_info:
        engine.render_server("failing", _server_snapshot())

    assert str(exc_info.value) == "Projection 'failing' failed for server target"
    assert exc_info.value.__cause__ is cause


def test_unexpected_client_error_is_wrapped_without_snapshot_secrets() -> None:
    cause = RuntimeError("renderer failed")
    engine = ProjectionEngine({"failing": FailingProjection(cause)})

    with pytest.raises(ProjectionRenderError) as exc_info:
        engine.render_client("failing", _client_snapshot())

    assert str(exc_info.value) == "Projection 'failing' failed for client target"
    assert exc_info.value.__cause__ is cause
    chain_messages = (str(exc_info.value), str(exc_info.value.__cause__))
    for secret in (SERVER_SECRET, CLIENT_SECRET, CLIENT_PSK):
        assert all(secret not in message for message in chain_messages)


@pytest.mark.parametrize(
    ("invoke", "secrets"),
    [
        (
            lambda engine: engine.render_server("failing", _server_snapshot()),
            (SERVER_SECRET, SERVER_PSK),
        ),
        (
            lambda engine: engine.render_client("failing", _client_snapshot()),
            (SERVER_SECRET, CLIENT_SECRET, CLIENT_PSK),
        ),
    ],
    ids=["server", "client"],
)
def test_recursive_error_chain_excludes_snapshot_secrets(
    invoke: Callable[[ProjectionEngine], str],
    secrets: tuple[str, ...],
) -> None:
    engine = ProjectionEngine({"failing": SecretInspectingProjection()})
    with pytest.raises(ProjectionRenderError) as exc_info:
        invoke(engine)

    messages = _exception_messages(exc_info.value)
    assert messages == (
        f"Projection 'failing' failed for "
        f"{'server' if secrets == (SERVER_SECRET, SERVER_PSK) else 'client'} target",
        "adapter failure",
        "low-level renderer failure",
    )
    for secret in secrets:
        assert all(secret not in message for message in messages)


class RendererAbort(BaseException):
    pass


def test_engine_does_not_catch_base_exception() -> None:
    abort = RendererAbort("abort")
    engine = ProjectionEngine({"failing": FailingProjection(abort)})

    with pytest.raises(RendererAbort) as exc_info:
        engine.render_server("failing", _server_snapshot())

    assert exc_info.value is abort


def test_engine_exposes_no_public_registry_api() -> None:
    public_names = {name for name in dir(ProjectionEngine) if not name.startswith("_")}

    assert public_names == {"render_client", "render_server"}
