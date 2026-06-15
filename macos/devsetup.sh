#!/usr/bin/env bash
# aten macOS dev-mode setup + preflight checker.
#
# We build on a free Apple account (no paid Developer Program), so the
# entitlement-gated paths — EndpointSecurity (es_new_client) and the
# NEFilterDataProvider system extension — are honored only in a relaxed-security
# dev posture. This script CHECKS that posture and prints the exact remediation
# for anything missing. The two SIP/boot-arg steps require Recovery Mode and a
# reboot, so they can't be fully automated from here; everything else is.
#
# Run:  ./devsetup.sh          # check + print what's needed
#
# One-time host prep (do these once, in this order):
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

echo "aten macOS dev-mode preflight"
echo

# 1. SIP
echo "SIP status:"
sip="$(csrutil status 2>/dev/null || true)"
if echo "$sip" | grep -qi "disabled"; then
  ok "SIP disabled"
else
  bad "SIP is enabled — ESF + dev sysexts will be blocked."
  info "Fix: reboot to Recovery Mode → Terminal → 'csrutil disable' → reboot."
fi
echo

# 2. amfi boot-arg
echo "AMFI boot-arg (honor ad-hoc entitlements):"
bootargs="$(nvram boot-args 2>/dev/null || true)"
if echo "$bootargs" | grep -qi "amfi_get_out_of_my_way"; then
  ok "amfi_get_out_of_my_way present in boot-args"
else
  bad "amfi_get_out_of_my_way not set."
  info "Fix: sudo nvram boot-args=\"amfi_get_out_of_my_way=0x1\"  then reboot."
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
  info "Run once: systemextensionsctl developer on"
fi
echo

# 4. tooling
echo "Tooling:"
command -v cargo     >/dev/null 2>&1 && ok "cargo"     || bad "cargo (install Rust)"
command -v xcodebuild>/dev/null 2>&1 && ok "xcodebuild" || bad "xcodebuild (install Xcode)"
command -v xcodegen  >/dev/null 2>&1 && ok "xcodegen"  || bad "xcodegen (brew install xcodegen)"
command -v codesign  >/dev/null 2>&1 && ok "codesign"  || bad "codesign"
echo

echo "When all green: ./sign-daemon.sh && ./build.sh"
