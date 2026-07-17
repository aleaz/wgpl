"""Internal projection lookup and target-specific dispatch."""

from collections.abc import Mapping

from wgpl.exceptions import (
    ProjectionRenderError,
    UnknownProjectionError,
    WgplException,
)

from .contracts import Projection
from .snapshots import ClientSnapshot, ServerSnapshot


class ProjectionEngine:
    def __init__(self, projections: Mapping[str, Projection]) -> None:
        self._projections = dict(projections)
        for identifier, projection in self._projections.items():
            if not identifier:
                raise ValueError("Projection identifier must not be empty")
            if identifier != projection.identifier:
                raise ValueError(
                    "Projection registry key must match projection.identifier"
                )

    def render_server(
        self,
        projection_id: str,
        snapshot: ServerSnapshot,
    ) -> str:
        projection = self._resolve(projection_id)
        try:
            return projection.render_server(snapshot)
        except WgplException:
            raise
        except Exception as exc:
            raise ProjectionRenderError(
                f"Projection '{projection_id}' failed for server target"
            ) from exc

    def render_client(
        self,
        projection_id: str,
        snapshot: ClientSnapshot,
    ) -> str:
        projection = self._resolve(projection_id)
        try:
            return projection.render_client(snapshot)
        except WgplException:
            raise
        except Exception as exc:
            raise ProjectionRenderError(
                f"Projection '{projection_id}' failed for client target"
            ) from exc

    def _resolve(self, projection_id: str) -> Projection:
        try:
            return self._projections[projection_id]
        except KeyError:
            raise UnknownProjectionError(
                f"Unknown projection '{projection_id}'"
            ) from None
