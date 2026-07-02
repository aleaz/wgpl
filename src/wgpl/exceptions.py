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
    """Raised when attempting to add an interface that already exists."""
    pass

class PeerNotFoundError(WgplException):
    """Raised when a peer is not found in the database."""
    pass

class AmbiguousPeerIdError(WgplException):
    """Raised when a peer ID prefix matches more than one peer."""
    pass

class PeerAlreadyExistsError(WgplException):
    """Raised when a peer name already exists in an interface."""
    pass

class WireguardConfigError(WgplException):
    """Raised when a WireGuard configuration command fails."""
    pass

class WgBinaryNotFoundError(WgplException):
    """Raised when the 'wg' command is not found on the system."""
    pass
