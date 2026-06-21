#!/usr/bin/env bash
# Build the aten macOS network-extension app + system extension (lab mode).
#
# Prereqs (see devsetup.sh): full Xcode, XcodeGen
# (`brew install xcodegen`), and either Apple-granted production entitlements or
# the lab-only host prep described in devsetup.sh. Do not relax SIP/AMFI on a
# primary Mac for ad-hoc builds.
#
# Produces macos/build/Build/Products/Debug/AtenHost.app with the system
# extension embedded. For activation testing, copy the app bundle into
# /Applications and launch the app bundle with `open`; do not run
# Contents/MacOS/AtenHost directly.
set -euo pipefail

cd "$(dirname "$0")"

echo "==> ATEN macOS lab build"
echo "    Ad-hoc builds should be activated only in an isolated macOS VM or spare test Mac."
echo "    For a primary Mac, use a properly signed/notarized build with Apple-granted entitlements."

find_xcode_developer_dir() {
  if [ -n "${DEVELOPER_DIR:-}" ] && [ -x "$DEVELOPER_DIR/usr/bin/xcodebuild" ]; then
    DEVELOPER_DIR="$DEVELOPER_DIR" xcodebuild -version >/dev/null 2>&1 && {
      printf '%s\n' "$DEVELOPER_DIR"
      return 0
    }
  fi

  if xcodebuild -version >/dev/null 2>&1; then
    return 0
  fi

  for app in /Applications/Xcode*.app "$HOME"/Applications/Xcode*.app; do
    developer_dir="$app/Contents/Developer"
    [ -x "$developer_dir/usr/bin/xcodebuild" ] || continue
    DEVELOPER_DIR="$developer_dir" xcodebuild -version >/dev/null 2>&1 || continue
    printf '%s\n' "$developer_dir"
    return 0
  done

  return 1
}

if ! command -v xcodegen >/dev/null 2>&1; then
  echo "error: xcodegen not found. Install with: brew install xcodegen" >&2
  exit 1
fi

detected_developer_dir="$(find_xcode_developer_dir || true)"
if [ -n "$detected_developer_dir" ]; then
  export DEVELOPER_DIR="$detected_developer_dir"
  echo "==> Using Xcode: $DEVELOPER_DIR"
elif ! xcodebuild -version >/dev/null 2>&1; then
  echo "error: xcodebuild is not usable. Install full Xcode and select it with:" >&2
  echo "  sudo xcode-select -s /Applications/Xcode.app/Contents/Developer" >&2
  echo "or run with:" >&2
  echo "  DEVELOPER_DIR=/path/to/Xcode.app/Contents/Developer ./build.sh" >&2
  exit 1
fi

echo "==> Generating Aten.xcodeproj from project.yml"
xcodegen generate

echo "==> Building (signing disabled; ad-hoc signing manually afterward)"
xcodebuild \
  -project Aten.xcodeproj \
  -scheme AtenHost \
  -configuration Debug \
  -derivedDataPath build \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=NO \
  build

APP="build/Build/Products/Debug/AtenHost.app"
EMBEDDED_EXT="$APP/Contents/Library/SystemExtensions/AtenNetExt.systemextension"
STANDALONE_EXT="build/Build/Products/Debug/AtenNetExt.systemextension"
HOST_ENTITLEMENTS="${ATEN_HOST_ENTITLEMENTS:-AtenHost/AtenHost.entitlements}"
NETEXT_ENTITLEMENTS="${ATEN_NETEXT_ENTITLEMENTS:-AtenNetExt/AtenNetExt.entitlements}"

echo "==> Ad-hoc signing products"
if [ -d "$STANDALONE_EXT" ]; then
  codesign --force --sign "-" \
    --entitlements "$NETEXT_ENTITLEMENTS" \
    --options runtime \
    "$STANDALONE_EXT"
fi
if [ -d "$EMBEDDED_EXT" ]; then
  codesign --force --sign "-" \
    --entitlements "$NETEXT_ENTITLEMENTS" \
    --options runtime \
    "$EMBEDDED_EXT"
fi
codesign --force --sign "-" \
  --entitlements "$HOST_ENTITLEMENTS" \
  --options runtime \
  "$APP"

echo "==> Built: $APP"
echo
echo "Embedded system extension:"
ls -1 "$APP/Contents/Library/SystemExtensions" 2>/dev/null || \
  echo "  (none found — check the embed step / signing)"
echo
echo "Verify signing + entitlements:"
codesign -dv --entitlements :- "$APP" 2>&1 | sed 's/^/  /' || true
echo
echo "Next on the test Mac/VM:"
echo "      ditto \"$APP\" /Applications/AtenHost.app"
echo "      open /Applications/AtenHost.app"
echo "      Only do this on a lab VM/test Mac, or with a properly entitled production build."
echo "      Do not launch Contents/MacOS/AtenHost directly; activation must come from the app bundle."
echo "      (Approve in System Settings ▸ General ▸ Login Items & Extensions.)"
