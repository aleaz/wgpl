"""Structural contract implemented by internal projections."""

from typing import Protocol

from .snapshots import ClientSnapshot, ServerSnapshot


class Projection(Protocol):
    identifier: str

    def render_server(self, snapshot: ServerSnapshot) -> str: ...

    def render_client(self, snapshot: ClientSnapshot) -> str: ...
