class WgplException(Exception):
    """Base exception for all WGPL errors."""

    pass


class NoAvailableIpsError(WgplException):
    """Raised when there are no available IPs in the pool."""

    pass


class InvalidPeerIpError(WgplException):
    """Raised when a requested peer IP is invalid or outside the interface pool."""

    pass


class IpAlreadyInUseError(WgplException):
    """Raised when a requested peer IP is already assigned."""

    pass


class InvalidDnsError(WgplException):
    """Raised when a DNS server list is invalid."""

    pass


class InterfaceNotFoundError(WgplException):
    """Raised when an interface is not found in the database."""

    pass


class InterfaceAlreadyExistsError(WgplException):
    """Raised when attempting to add an interface that already exists (name collision)."""

    pass


class InterfaceConflictError(WgplException):
    """Raised when an interface port or address pool conflicts with an existing interface."""

    pass


class InterfaceHasPeersError(WgplException):
    """Raised when removing an interface that still has peers without --force."""

    pass


class PeerNotFoundError(WgplException):
    """Raised when a peer is not found in the database."""

    pass


class PeerInterfaceMismatchError(WgplException):
    """Raised when a peer does not belong to the requested interface."""

    pass


class InterfaceDisambiguationRequiredError(WgplException):
    """Raised when --interface is required to disambiguate peer resolution."""

    pass


class AmbiguousInterfaceError(WgplException):
    """Raised when an interface name matches multiple interfaces in the database."""

    pass


class AmbiguousPeerIdError(WgplException):
    """Raised when a peer ID prefix matches more than one peer."""

    pass


class PeerAlreadyExistsError(WgplException):
    """Raised when a peer name already exists in an interface."""

    pass


class NoUpdateFieldsError(WgplException):
    """Raised when an update command is invoked without any fields to change."""

    pass


class PeersOutsidePoolError(WgplException):
    """Raised when a new address pool would leave existing peers outside the CIDR."""

    def __init__(self, interface: str, conflicts: list[dict[str, str]]) -> None:
        self.interface = interface
        self.conflicts = conflicts
        details = ", ".join(f"{c['name']} ({c['ip_address']})" for c in conflicts)
        super().__init__(f"Peers outside pool for interface {interface}: {details}")


class WireguardConfigError(WgplException):
    """Raised when a WireGuard configuration command fails."""

    pass


class WgBinaryNotFoundError(WgplException):
    """Raised when the 'wg' command is not found on the system."""

    pass
