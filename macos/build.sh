#!/usr/bin/env bash
# Build the aten macOS network-extension app + system extension (dev mode).
#
# Prereqs (see devsetup.md): Xcode command-line tools, XcodeGen
# (`brew install xcodegen`), and the one-time host prep (SIP off, amfi boot-arg,
# `systemextensionsctl developer on`). Run from anywhere; paths are resolved
# relative to this script.
#
# Produces macos/build/Build/Products/Debug/AtenHost.app with the system
# extension embedded. Then:
#   open  macos/build/Build/Products/Debug/AtenHost.app   # activate + enable
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v xcodegen >/dev/null 2>&1; then
  echo "error: xcodegen not found. Install with: brew install xcodegen" >&2
  exit 1
fi

echo "==> Generating Aten.xcodeproj from project.yml"
xcodegen generate

echo "==> Building (ad-hoc signed)"
xcodebuild \
  -project Aten.xcodeproj \
  -scheme AtenHost \
  -configuration Debug \
  -derivedDataPath build \
  CODE_SIGN_IDENTITY="-" \
  CODE_SIGNING_REQUIRED=YES \
  CODE_SIGNING_ALLOWED=YES \
  build

APP="build/Build/Products/Debug/AtenHost.app"
echo "==> Built: $APP"
echo
echo "Embedded system extension:"
ls -1 "$APP/Contents/Library/SystemExtensions" 2>/dev/null || \
  echo "  (none found — check the embed step / signing)"
echo
echo "Verify signing + entitlements:"
codesign -dv --entitlements :- "$APP" 2>&1 | sed 's/^/  /' || true
echo
echo "Next: open \"$APP\" to activate the extension and enable the content filter."
echo "      (Approve in System Settings ▸ General ▸ Login Items & Extensions.)"
