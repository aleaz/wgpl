from unittest.mock import patch

from wgpl import core


@patch("wgpl.core.wireguard.syncconf")
def test_sync_interface_passes_db_peer_set_only(
    mock_syncconf: object, wg0_interface: str
) -> None:
    """syncconf receives peer stanzas for DB peers only; removed peers are omitted."""
    kept = core.add_peer(wg0_interface, "keep")
    removed = core.add_peer(wg0_interface, "gone")
    core.remove_peer(wg0_interface, removed["id"])

    core.sync_interface(wg0_interface)

    mock_syncconf.assert_called_once()
    interface_name, config = mock_syncconf.call_args[0]
    assert interface_name == wg0_interface
    assert kept["public_key"] in config
    assert removed["public_key"] not in config
