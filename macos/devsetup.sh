#!/usr/bin/env bash
# aten macOS lab-mode setup + preflight checker.
#
# We build on a free Apple account (no paid Developer Program), so the
# entitlement-gated paths — EndpointSecurity (es_new_client) and the
# NEFilterDataProvider system extension — are honored only in a relaxed-security
# lab posture. Do not use this posture on a primary Mac. Use an isolated macOS
# VM or spare test Mac unless you have Apple-granted production entitlements.
#
# This script CHECKS that posture and prints the exact lab-only remediation for
# anything missing. The two SIP/boot-arg steps require Recovery Mode and a reboot,
# so they can't be fully automated from here; everything else is.
#
# Run:  ./devsetup.sh          # check + print what's needed
#
# One-time lab-host prep (do these once, in this order, only inside an isolated
# macOS VM or spare test Mac):
#
#   1. Disable SIP (Recovery Mode):
#        - Reboot holding the power button → Options → Utilities → Terminal
#        - `csrutil disable`
#        - Reboot.
#
#   2. Let ad-hoc entitlements be honored (so the ESF entitlement on an
#      ad-hoc-signed binary is trusted). In normal macOS:
#        sudo nvram boot-args="amfi_get_out_of_my_way=0x1"
#      then reboot. (Remove later with: sudo nvram -d boot-args)
#
#   3. Allow unnotarized/dev system extensions:
#        systemextensionsctl developer on
#
# After prep:  ./sign-daemon.sh  (sign the Rust daemon)  and  ./build.sh
# (build the Swift app + extension), then follow their printed next-steps.
set -uo pipefail

ok()   { printf "  \033[32m✓\033[0m %s\n" "$1"; }
bad()  { printf "  \033[31m✗\033[0m %s\n" "$1"; }
info() { printf "  \033[33m•\033[0m %s\n" "$1"; }

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

echo "aten macOS lab-mode preflight"
echo
echo "Safety: do not disable SIP or AMFI protections on your primary Mac."
echo "Use this ad-hoc path only inside an isolated macOS VM or spare test Mac."
echo "For real distribution, use Apple-granted ESF/NetworkExtension entitlements."
echo

# 1. SIP
echo "SIP status:"
sip="$(csrutil status 2>/dev/null || true)"
if echo "$sip" | grep -qi "disabled"; then
  ok "SIP disabled"
else
  bad "SIP is enabled — ad-hoc ESF + dev sysexts will be blocked."
  info "Lab-only path: boot the VM/test Mac to Recovery → Terminal → 'csrutil disable' → reboot."
fi
echo

# 2. amfi boot-arg
echo "AMFI boot-arg (honor ad-hoc entitlements):"
bootargs="$(nvram boot-args 2>/dev/null || true)"
if echo "$bootargs" | grep -qi "amfi_get_out_of_my_way"; then
  ok "amfi_get_out_of_my_way present in boot-args"
else
  bad "amfi_get_out_of_my_way not set."
  info "Lab-only path: sudo nvram boot-args=\"amfi_get_out_of_my_way=0x1\"  then reboot."
fi
echo

# 3. system-extension developer mode
echo "System-extension developer mode:"
sysext="$(systemextensionsctl developer 2>/dev/null || true)"
# `systemextensionsctl developer` with no arg prints current state on some
# versions; otherwise we just remind.
if echo "$sysext" | grep -qi "on"; then
  ok "developer mode on"
else
  info "Lab-only path: systemextensionsctl developer on"
fi
echo

# 4. tooling
echo "Tooling:"
if command -v cargo >/dev/null 2>&1 || [ -x /opt/homebrew/opt/rustup/bin/cargo ]; then
  ok "cargo"
else
  bad "cargo (install Rust, or put cargo/rustup on PATH)"
fi
xcode_developer_dir="$(find_xcode_developer_dir || true)"
if [ -n "$xcode_developer_dir" ]; then
  ok "xcodebuild ($xcode_developer_dir)"
  if [ "$xcode_developer_dir" != "${DEVELOPER_DIR:-}" ]; then
    info "build.sh will auto-use this Xcode via DEVELOPER_DIR."
  fi
elif xcodebuild -version >/dev/null 2>&1; then
  ok "xcodebuild"
else
  bad "xcodebuild (install full Xcode, then run: sudo xcode-select -s /Applications/Xcode.app/Contents/Developer)"
fi
command -v xcodegen  >/dev/null 2>&1 && ok "xcodegen"  || bad "xcodegen (brew install xcodegen)"
command -v codesign  >/dev/null 2>&1 && ok "codesign"  || bad "codesign"
echo

echo "When all green on the lab host: ./sign-daemon.sh && ./build.sh"
