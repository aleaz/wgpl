"""Input validation helpers for CLI and business operations."""

from __future__ import annotations

import base64
import ipaddress
import re

from . import wireformat
from .exceptions import InvalidDnsError


def validate_dns(value: str) -> str:
    """Validate and normalize a DNS server list for WireGuard client config."""
    parts = [part.strip() for part in value.split(",") if part.strip()]
    if not parts:
        raise InvalidDnsError("DNS value cannot be empty")

    normalized: list[str] = []
    for part in parts:
        try:
            ipaddress.ip_address(part)
        except ValueError as exc:
            raise InvalidDnsError(f"Invalid DNS address '{part}'") from exc
        normalized.append(part)
    return ", ".join(normalized)


def validate_allowed_ips(allowed_ips: str) -> str:
    """Validate AllowedIPs for client configuration export."""
    return wireformat.validate_allowed_ips(allowed_ips)


def validate_endpoint(endpoint: str) -> str:
    """Validate that endpoint is a valid IP address or FQDN."""
    endpoint = endpoint.strip()
    if not endpoint:
        raise ValueError("Endpoint cannot be empty")
    try:
        ipaddress.ip_address(endpoint)
        return endpoint
    except ValueError:
        pass

    hostname_re = re.compile(
        r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*"
        r"([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
    )
    if not hostname_re.match(endpoint):
        raise ValueError(
            f"Invalid endpoint '{endpoint}'. Must be a valid IP or hostname."
        )
    return endpoint


def validate_public_key(key: str) -> str:
    """Validate that key is a valid 32-byte Base64 WireGuard public key."""
    key = key.strip()
    if not key:
        raise ValueError("Public key cannot be empty")
    try:
        decoded = base64.b64decode(key.encode("utf-8"), validate=True)
        if len(decoded) != 32:
            raise ValueError(
                f"Invalid public key length: expected 32 decoded bytes, got {len(decoded)}"
            )
    except Exception as exc:
        raise ValueError("Invalid public key: must be valid Base64") from exc
    return key


def validate_peer_name(name: str) -> str:
    """Validate and normalize peer names used in DB and CLI output."""
    normalized = name.strip()
    if not normalized:
        raise ValueError("Name cannot be empty")
    if len(normalized) > 64:
        raise ValueError("Name must be at most 64 characters")
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$", normalized):
        raise ValueError(
            "Name contains invalid characters. Must start with alphanumeric and contain only alphanumerics, hyphens, and underscores."
        )
    return normalized
