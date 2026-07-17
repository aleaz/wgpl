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


class NodeNotFoundError(WgplException):
    """Raised when a node (device identity) is not found in the database."""

    pass


class NodeAlreadyExistsError(WgplException):
    """Raised when creating a node whose name already exists (names are global)."""

    pass


class NodeHasPeersError(WgplException):
    """Raised when removing a node that still has attachments without --force."""

    pass


class AmbiguousNodeIdError(WgplException):
    """Raised when a node ID prefix matches more than one node."""

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
    """Raised when an active peer attachment conflicts on an interface.

    Covers node-already-attached, duplicate peer display name, and (via
    subclasses) routed-network overlaps. IP collisions use
    :class:`IpAlreadyInUseError` instead.
    """

    pass


class NodeAlreadyAttachedError(PeerAlreadyExistsError):
    """Raised when a node is already attached to the interface as an active peer."""

    pass


class RoutedNetworkOverlapError(PeerAlreadyExistsError):
    """Raised when subnet-router routed_networks overlap an active peer's prefixes."""

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


class ValidationError(WgplException):
    """Base for all input/schema validation errors."""

    pass


class MutuallyExclusiveOptionsError(ValidationError):
    """Raised when mutually exclusive CLI options are provided together."""

    pass


class InvalidFieldValueError(ValidationError):
    """Raised when a field value fails format, range, or constraint checks."""

    pass


class ProjectionError(WgplException):
    """Base for internal projection dispatch and rendering failures."""

    pass


class UnknownProjectionError(ProjectionError):
    """Raised when an internal projection identifier is not registered."""

    pass


class ProjectionRenderError(ProjectionError):
    """Raised when a renderer fails outside the WGPL exception contract."""

    pass
