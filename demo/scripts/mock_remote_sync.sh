#!/usr/bin/env bash
# Offline stand-in for: ssh hub 'sudo wg syncconf wg0 /dev/stdin'
# Reads WireGuard peer blocks from stdin and reports a successful remote sync.
set -euo pipefail

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
cat >"$tmpdir/peers.conf"
peers=$(grep -c '^\[Peer\]' "$tmpdir/peers.conf" || true)
echo "synced ${peers} peer(s) to hub.acme.example (wg syncconf)"
