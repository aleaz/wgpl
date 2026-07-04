from unittest.mock import patch, MagicMock

from wgpl import core


@patch("wgpl.core.wireguard.syncconf")
def test_sync_interface_passes_db_peer_set_only(
    mock_syncconf: MagicMock, wg0_interface: str
) -> None:
    """syncconf receives peer stanzas for DB peers only; removed peers are omitted."""
    kept = core.add_peer(wg0_interface, "keep")
    removed = core.add_peer(wg0_interface, "gone")
    assert removed["id"] is not None
    core.remove_peer(wg0_interface, removed["id"])

    core.sync_interface(wg0_interface)

    mock_syncconf.assert_called_once()
    interface_name, config = mock_syncconf.call_args[0]
    assert interface_name == "wg0"
    assert str(kept["public_key"]) in config
    assert str(removed["public_key"]) not in config
