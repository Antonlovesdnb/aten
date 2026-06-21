#!/usr/bin/env bash
# Build and ad-hoc-sign the `aten` daemon binary with the EndpointSecurity
# client entitlement, so `aten collect-macos` / `aten daemon` can create
# an ES client. Without this signing step es_new_client returns NOT_PERMITTED.
#
# Free-account lab mode: ad-hoc identity ("-") + the entitlement is honored only
# with SIP off + amfi_get_out_of_my_way set inside an isolated macOS VM or spare
# test Mac (see devsetup.sh). Do not relax those protections on a primary Mac.
# On a paid account, pass a real identity:
#   IDENTITY="Developer ID Application: …" ./sign-daemon.sh
#
# Run from anywhere; resolves the repo root relative to this script.
set -euo pipefail

cd "$(dirname "$0")/.."   # repo root

echo "==> ATEN macOS daemon signing"
echo "    Ad-hoc EndpointSecurity signing is for isolated lab VMs/test Macs only."
echo "    Keep SIP/AMFI enabled on primary Macs unless using Apple-granted entitlements."

PROFILE="${PROFILE:-release}"
IDENTITY="${IDENTITY:--}"   # "-" = ad-hoc
ENTITLEMENTS="macos/esf.entitlements"
CARGO_BIN="${CARGO_BIN:-cargo}"
if [ -x /opt/homebrew/opt/rustup/bin/cargo ]; then
  export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
fi
if ! command -v "$CARGO_BIN" >/dev/null 2>&1 && [ -x /opt/homebrew/opt/rustup/bin/cargo ]; then
  CARGO_BIN="/opt/homebrew/opt/rustup/bin/cargo"
fi

echo "==> cargo build --profile $PROFILE (with esf feature)"
# The macos collector's `esf` feature is on by default; build the daemon bin.
if [ "$PROFILE" = "release" ]; then
  "$CARGO_BIN" build --release -p aten-daemon
  BIN="target/release/aten"
else
  "$CARGO_BIN" build -p aten-daemon
  BIN="target/debug/aten"
fi

if [ ! -f "$BIN" ]; then
  echo "error: built binary not found at $BIN" >&2
  exit 1
fi

echo "==> codesign (identity: $IDENTITY) with $ENTITLEMENTS"
codesign --force --sign "$IDENTITY" \
  --entitlements "$ENTITLEMENTS" \
  --options runtime \
  "$BIN"

echo "==> verify"
codesign -dv --entitlements :- "$BIN" 2>&1 | sed 's/^/  /'

echo
echo "Signed: $BIN"
echo "Run:    sudo $BIN collect-macos --agents claude,codex"
echo "  (sudo is required for ESF; the netflow UDS lives in /var/run/aten.)"
