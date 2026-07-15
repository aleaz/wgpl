"""Input validation helpers for CLI and business operations."""

from __future__ import annotations

import base64
import ipaddress
import re

from . import wireformat
from .exceptions import InvalidDnsError, InvalidFieldValueError
from .fields import NAME_MAX_LEN, NAME_RE


def validate_dns(value: str) -> str:
    """Validate and normalize a DNS server list for WireGuard client config."""
    parts = [part.strip() for part in value.split(",") if part.strip()]
    if not parts:
        raise InvalidDnsError("DNS value cannot be empty")

    normalized: list[str] = []
    for part in parts:
        try:
            ipaddress.IPv4Address(part)
        except ValueError as exc:
            raise InvalidDnsError(
                f"Invalid DNS address '{part}' (WGPL supports IPv4 only)"
            ) from exc
        normalized.append(part)
    return ", ".join(normalized)


def validate_allowed_ips(allowed_ips: str) -> str:
    """Validate AllowedIPs for client configuration export."""
    return wireformat.validate_allowed_ips(allowed_ips)


def validate_endpoint(endpoint: str) -> str:
    """Validate that endpoint is a valid IPv4 address or FQDN (IPv6 not supported)."""
    endpoint = endpoint.strip()
    if not endpoint:
        raise InvalidFieldValueError("Endpoint cannot be empty")
    try:
        addr = ipaddress.ip_address(endpoint)
    except ValueError:
        addr = None
    if addr is not None:
        if isinstance(addr, ipaddress.IPv6Address):
            raise InvalidFieldValueError(
                f"Invalid endpoint '{endpoint}'. WGPL supports IPv4 endpoints only."
            )
        return endpoint

    hostname_re = re.compile(
        r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*"
        r"([A-Za-z0-9]|[A-Za-z0-9][a-zA-Z0-9\-]*[A-Za-z0-9])$"
    )
    if not hostname_re.match(endpoint):
        raise InvalidFieldValueError(
            f"Invalid endpoint '{endpoint}'. Must be a valid IPv4 address or hostname."
        )
    return endpoint


def validate_public_key(key: str) -> str:
    """Validate that key is a valid 32-byte Base64 WireGuard public key."""
    key = key.strip()
    if not key:
        raise InvalidFieldValueError("Public key cannot be empty")
    try:
        decoded = base64.b64decode(key.encode("utf-8"), validate=True)
        if len(decoded) != 32:
            raise InvalidFieldValueError(
                f"Invalid public key length: expected 32 decoded bytes, got {len(decoded)}"
            )
    except InvalidFieldValueError:
        raise
    except Exception as exc:
        raise InvalidFieldValueError(
            "Invalid public key: must be valid Base64"
        ) from exc
    return key


def validate_peer_name(name: str) -> str:
    """Validate and normalize peer/node/interface names used in DB and CLI output."""
    normalized = name.strip()
    if not normalized:
        raise InvalidFieldValueError("Name cannot be empty")
    if len(normalized) > NAME_MAX_LEN:
        raise InvalidFieldValueError("Name must be at most 64 characters")
    if not NAME_RE.match(normalized):
        raise InvalidFieldValueError(
            "Name contains invalid characters. Must start with alphanumeric and contain only alphanumerics, hyphens, and underscores."
        )
    return normalized
