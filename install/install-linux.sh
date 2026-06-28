#!/usr/bin/env bash
set -euo pipefail

REPO="${ATEN_REPO:-Antonlovesdnb/aten}"
VERSION="${ATEN_VERSION:-latest}"
ASSET="${ATEN_ASSET:-aten-linux-x86_64.tar.gz}"
URL="${ATEN_URL:-}"
LOCAL_BINARY="${ATEN_LOCAL_BINARY:-}"
INSTALL_DIR="${ATEN_INSTALL_DIR:-/usr/local/bin}"
CONFIG_PATH="${ATEN_CONFIG_PATH:-/etc/aten/config.toml}"
EVENTS_PATH="${ATEN_EVENTS_PATH:-/var/log/aten/events.jsonl}"
AGENTS="${ATEN_AGENTS:-claude,codex}"
WATCH_DIRS="${ATEN_WATCH_DIRS:-}"
FORCE_CONFIG=0

usage() {
  cat <<'EOF'
Install ATEN on Linux.

This script installs an aten binary, writes /etc/aten/config.toml if it does
not already exist, then delegates to `aten install` for the systemd unit.

Usage:
  sudo install/install-linux.sh [options]

Options:
  --repo OWNER/REPO           GitHub repo for release downloads
                             default: Antonlovesdnb/aten
  --version VERSION           Release tag, or "latest"
                             default: latest
  --asset NAME                Release asset name
                             default: aten-linux-x86_64.tar.gz
  --url URL                   Download URL. Overrides --repo/--version/--asset
  --local-binary PATH         Install this already-built aten binary
  --install-dir PATH          Directory for the installed binary
                             default: /usr/local/bin
  --agents LIST               Comma-separated agent process names
                             default: claude,codex
  --watch-dirs LIST           Comma-separated transcript directories.
                             default: installing user's Claude/Codex dirs
  --events-path PATH          JSONL output path
                             default: /var/log/aten/events.jsonl
  --config PATH               Config path
                             default: /etc/aten/config.toml
  --force-config              Overwrite an existing config
  -h, --help                  Show this help

Environment variables mirror the long option names with ATEN_ prefixes, e.g.
ATEN_VERSION, ATEN_URL, ATEN_LOCAL_BINARY, ATEN_AGENTS, ATEN_WATCH_DIRS.

Examples:
  curl -fsSL https://raw.githubusercontent.com/Antonlovesdnb/aten/main/install/install-linux.sh \
    | sudo bash

  curl -fsSL https://raw.githubusercontent.com/Antonlovesdnb/aten/main/install/install-linux.sh \
    | sudo bash -s -- --version v0.1.0

  sudo install/install-linux.sh --local-binary target/release/aten
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

info() {
  echo "[aten install] $*"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo)
      REPO="${2:?missing value for --repo}"
      shift 2
      ;;
    --version)
      VERSION="${2:?missing value for --version}"
      shift 2
      ;;
    --asset)
      ASSET="${2:?missing value for --asset}"
      shift 2
      ;;
    --url)
      URL="${2:?missing value for --url}"
      shift 2
      ;;
    --local-binary)
      LOCAL_BINARY="${2:?missing value for --local-binary}"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="${2:?missing value for --install-dir}"
      shift 2
      ;;
    --agents)
      AGENTS="${2:?missing value for --agents}"
      shift 2
      ;;
    --watch-dirs)
      WATCH_DIRS="${2:?missing value for --watch-dirs}"
      shift 2
      ;;
    --events-path)
      EVENTS_PATH="${2:?missing value for --events-path}"
      shift 2
      ;;
    --config)
      CONFIG_PATH="${2:?missing value for --config}"
      shift 2
      ;;
    --force-config)
      FORCE_CONFIG=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  die "run as root, e.g. sudo install/install-linux.sh"
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

need_cmd install
need_cmd mkdir
need_cmd mktemp
need_cmd systemctl

if [ -z "$LOCAL_BINARY" ]; then
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    die "curl or wget is required for downloads; use --local-binary to skip downloading"
  fi
fi

tmp=""
cleanup() {
  if [ -n "$tmp" ] && [ -d "$tmp" ]; then
    rm -rf "$tmp"
  fi
}
trap cleanup EXIT

toml_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '%s' "$value"
}

toml_array_from_csv() {
  local csv="$1"
  local first=1
  local item
  printf '['
  IFS=',' read -r -a items <<< "$csv"
  for item in "${items[@]}"; do
    item="${item#"${item%%[![:space:]]*}"}"
    item="${item%"${item##*[![:space:]]}"}"
    [ -n "$item" ] || continue
    if [ "$first" -eq 0 ]; then
      printf ', '
    fi
    first=0
    printf '"%s"' "$(toml_escape "$item")"
  done
  printf ']'
}

real_user_home() {
  local user="${SUDO_USER:-}"
  if [ -n "$user" ] && [ "$user" != "root" ] && command -v getent >/dev/null 2>&1; then
    local home
    home="$(getent passwd "$user" | cut -d: -f6 || true)"
    if [ -n "$home" ]; then
      printf '%s' "$home"
      return
    fi
  fi
  if [ -n "$user" ] && [ "$user" != "root" ]; then
    printf '/home/%s' "$user"
    return
  fi
  printf '%s' "${HOME:-/root}"
}

download() {
  local source_url="$1"
  local dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --proto '=https' --tlsv1.2 "$source_url" -o "$dest"
  else
    wget -O "$dest" "$source_url"
  fi
}

resolve_download_url() {
  if [ -n "$URL" ]; then
    printf '%s' "$URL"
  elif [ "$VERSION" = "latest" ]; then
    printf 'https://github.com/%s/releases/latest/download/%s' "$REPO" "$ASSET"
  else
    printf 'https://github.com/%s/releases/download/%s/%s' "$REPO" "$VERSION" "$ASSET"
  fi
}

download_name_for_url() {
  if [ -n "$URL" ]; then
    local name="${URL%%\?*}"
    name="${name##*/}"
    if [ -n "$name" ]; then
      printf '%s' "$name"
      return
    fi
  fi
  printf '%s' "$ASSET"
}

find_aten_binary() {
  local root="$1"
  local found
  found="$(find "$root" -type f -name aten -print -quit)"
  if [ -z "$found" ]; then
    die "downloaded archive did not contain an aten binary"
  fi
  printf '%s' "$found"
}

tmp="$(mktemp -d)"
candidate=""

if [ -n "$LOCAL_BINARY" ]; then
  [ -f "$LOCAL_BINARY" ] || die "--local-binary not found: $LOCAL_BINARY"
  candidate="$LOCAL_BINARY"
else
  source_url="$(resolve_download_url)"
  download_name="$(download_name_for_url)"
  archive="$tmp/$download_name"
  info "downloading $source_url"
  download "$source_url" "$archive"
  case "$archive" in
    *.tar.gz|*.tgz)
      need_cmd tar
      mkdir -p "$tmp/extract"
      tar -xzf "$archive" -C "$tmp/extract"
      candidate="$(find_aten_binary "$tmp/extract")"
      ;;
    *)
      candidate="$archive"
      ;;
  esac
fi

mkdir -p "$INSTALL_DIR"
install -m 0755 "$candidate" "$INSTALL_DIR/aten"
ATEN_BIN="$INSTALL_DIR/aten"
info "installed binary to $ATEN_BIN"

config_dir="$(dirname "$CONFIG_PATH")"
mkdir -p "$config_dir" "$(dirname "$EVENTS_PATH")" /var/lib/aten

if [ -z "$WATCH_DIRS" ]; then
  home="$(real_user_home)"
  WATCH_DIRS="$home/.claude/projects,$home/.codex/sessions"
fi

if [ "$FORCE_CONFIG" -eq 1 ] || [ ! -f "$CONFIG_PATH" ]; then
  agents_array="$(toml_array_from_csv "$AGENTS")"
  watch_array="$(toml_array_from_csv "$WATCH_DIRS")"
  escaped_events="$(toml_escape "$EVENTS_PATH")"
  cat > "$CONFIG_PATH" <<EOF
# ATEN service config. Edit and restart the service:
#   sudo systemctl restart aten

[daemon]
agents = $agents_array

[transcripts]
# Recursively scanned for *.jsonl. Dialect (Claude / Codex) auto-detected per file.
watch_dirs = $watch_array

[output]
# sink: jsonl | eventlog | both. eventlog is Windows-only.
sink = "jsonl"
file_path = "$escaped_events"
EOF
  info "wrote config to $CONFIG_PATH"
else
  info "preserved existing config $CONFIG_PATH"
fi

"$ATEN_BIN" install

info "status:"
systemctl --no-pager status aten || true

info "recent logs:"
journalctl -u aten -n 20 --no-pager || true

cat <<EOF

ATEN Linux install complete.

Useful commands:
  sudo systemctl status aten
  sudo journalctl -u aten -f
  sudo tail -f "$EVENTS_PATH"
  sudo "$ATEN_BIN" uninstall
EOF
