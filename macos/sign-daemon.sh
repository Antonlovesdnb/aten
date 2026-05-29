#!/usr/bin/env bash
# Build and ad-hoc-sign the `fishbowl` daemon binary with the EndpointSecurity
# client entitlement, so `fishbowl collect-macos` / `fishbowl daemon` can create
# an ES client. Without this signing step es_new_client returns NOT_PERMITTED.
#
# Free-account dev mode: ad-hoc identity ("-") + the entitlement is honored only
# with SIP off + amfi_get_out_of_my_way set (see devsetup.sh). On a paid account,
# pass a real identity:  IDENTITY="Developer ID Application: …" ./sign-daemon.sh
#
# Run from anywhere; resolves the repo root relative to this script.
set -euo pipefail

cd "$(dirname "$0")/.."   # repo root

PROFILE="${PROFILE:-release}"
IDENTITY="${IDENTITY:--}"   # "-" = ad-hoc
ENTITLEMENTS="macos/esf.entitlements"

echo "==> cargo build --profile $PROFILE (with esf feature)"
# The macos collector's `esf` feature is on by default; build the daemon bin.
if [ "$PROFILE" = "release" ]; then
  cargo build --release -p fishbowl-daemon
  BIN="target/release/fishbowl"
else
  cargo build -p fishbowl-daemon
  BIN="target/debug/fishbowl"
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
echo "  (sudo is required for ESF; the netflow UDS lives in /var/run/fishbowl.)"
