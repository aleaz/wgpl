from typing import Callable, cast
from unittest.mock import MagicMock, patch

import pytest

from wgpl import core
from wgpl.exceptions import WgplException


@patch("wgpl.core.wireguard.syncconf")
def test_apply_receives_exact_export_and_omits_soft_deleted_peer(
    mock_syncconf: MagicMock,
    wg0_interface: str,
) -> None:
    active = core.add_peer(wg0_interface, "active_export_peer")
    removed = core.add_peer(wg0_interface, "removed_export_peer")
    core.remove_peer(wg0_interface, str(removed["id"]))

    exported = core.get_interface_config(wg0_interface)
    core.sync_interface(wg0_interface)

    assert str(active["public_key"]) in exported
    assert str(removed["public_key"]) not in exported
    mock_syncconf.assert_called_once_with("wg0", exported)


@patch("wgpl.core.wireguard.syncconf")
@patch(
    "wgpl.core._project_server_config",
    return_value=("canonical-wg0", "projected-server-artifact"),
)
def test_sync_interface_passes_projected_name_and_artifact_once(
    mock_project: MagicMock,
    mock_syncconf: MagicMock,
) -> None:
    sync_with_observable_return = cast(Callable[[str], object], core.sync_interface)
    result = sync_with_observable_return("wg-prefix")

    mock_project.assert_called_once_with("wg-prefix")
    mock_syncconf.assert_called_once_with(
        "canonical-wg0",
        "projected-server-artifact",
    )
    assert result is None


@patch("wgpl.core.wireguard.syncconf")
@patch("wgpl.core._project_server_config")
def test_sync_interface_does_not_sync_after_projection_failure(
    mock_project: MagicMock,
    mock_syncconf: MagicMock,
) -> None:
    error = WgplException("projection failed")
    mock_project.side_effect = error

    with pytest.raises(WgplException) as exc_info:
        core.sync_interface("wg0")

    assert exc_info.value is error
    mock_project.assert_called_once_with("wg0")
    mock_syncconf.assert_not_called()
