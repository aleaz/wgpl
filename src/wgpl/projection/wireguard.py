"""WireGuard rendering over immutable target snapshots."""

from .. import wireformat
from .snapshots import ClientSnapshot, ServerSnapshot


class WireGuardProjection:
    identifier = "wireguard"

    def render_server(self, snapshot: ServerSnapshot) -> str:
        interface_input: dict[str, object] = {
            "name": snapshot.interface_name,
            "mtu": snapshot.mtu,
        }
        return wireformat.build_server_config(
            interface_input,
            [
                (
                    {
                        "public_key": peer.public_key,
                        "preshared_key": peer.preshared_key,
                    },
                    list(peer.allowed_ips),
                )
                for peer in snapshot.peers
            ],
        )

    def render_client(self, snapshot: ClientSnapshot) -> str:
        peer_input: dict[str, object] = {
            "private_key": snapshot.private_key,
            "ip_address": snapshot.ip_address,
            "preshared_key": snapshot.preshared_key,
            "dns": snapshot.dns,
            "mtu": snapshot.mtu,
            "keepalive": snapshot.keepalive,
        }
        interface_input: dict[str, object] = {
            "address_pool": f"0.0.0.0/{snapshot.address_prefix_length}",
            "endpoint": snapshot.endpoint,
            "port": snapshot.port,
            "public_key": snapshot.server_public_key,
            "dns": None,
            "mtu": None,
            "keepalive": None,
        }
        return wireformat.build_client_config(
            peer_input,
            interface_input,
            ",".join(snapshot.allowed_ips),
        )
