import subprocess
from dataclasses import dataclass
import os
import base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from .exceptions import WgBinaryNotFoundError, WireguardConfigError

@dataclass
class Keypair:
    private_key: str
    public_key: str

def _get_wg_bin() -> str:
    """
    Resolves the wg binary path.
    SECURITY NOTE: If running as root (UID 0), we ignore WGPL_WG_BIN to prevent 
    Local Privilege Escalation (LPE) via environment injection when using `sudo -E`.
    """
    if os.getuid() == 0:
        return "wg"
    return os.environ.get("WGPL_WG_BIN", "wg")

def run_wg_command(*args: str) -> str:
    """Wrapper to run wg commands securely."""
    wg_bin = _get_wg_bin()
    cmd = [wg_bin] + list(args)

    try:
        result = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            check=True,
        )
        return result.stdout.strip()
    except FileNotFoundError:
        raise WgBinaryNotFoundError("The 'wg' command was not found. Make sure wireguard-tools is installed on the target system.")
    except subprocess.CalledProcessError as e:
        raise WireguardConfigError(f"wg command failed: {' '.join(cmd)}\nError: {e.stderr}")

def generate_keypair() -> Keypair:
    """Generates a WireGuard Curve25519 keypair entirely in Python memory."""
    private_key = x25519.X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return Keypair(
        private_key=base64.b64encode(private_bytes).decode('utf-8'),
        public_key=base64.b64encode(public_bytes).decode('utf-8')
    )

def generate_preshared_key() -> str:
    """Generates a 32-byte cryptographically secure random string base64 encoded."""
    return base64.b64encode(os.urandom(32)).decode('utf-8')

def syncconf(interface: str, conf_content: str) -> None:
    """Applies a declarative configuration to a WireGuard interface."""
    wg_bin = _get_wg_bin()
    cmd = [wg_bin, "syncconf", interface, "/dev/stdin"]
    
    try:
        subprocess.run(
            cmd,
            input=conf_content,
            text=True,
            capture_output=True,
            check=True,
        )
    except FileNotFoundError:
        raise WgBinaryNotFoundError("The 'wg' command was not found. Make sure wireguard-tools is installed on the target system.")
    except subprocess.CalledProcessError as e:
        raise WireguardConfigError(f"wg command failed: {' '.join(cmd)}\nError: {e.stderr}")
