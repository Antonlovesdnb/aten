# fishbowl-v2 deployment

How fishbowl-v2 reaches a user's endpoint and starts watching. The install story is the differentiator from AgentSight — *"Sysmon for AI agents, deployed like Sysmon"* only holds if the install really is one command.

## Sysmon parallel — the bar to clear

| Property | Sysmon | fishbowl-v2 |
|---|---|---|
| Install | `Sysmon.exe -i` | `apt install fishbowl-v2` (Linux) / `msiexec /i` (Windows) |
| Activates | Immediately | Immediately |
| Watches | All processes, all users | All enrolled agent processes, all users |
| Output | Windows Event Log | JSONL → configurable sink (stdout, file, syslog, Splunk HEC, OTel) |
| Survives reboots | Service | Service |
| Per-invocation wrapping required | No | No |

That last row is the entire AgentSight differentiation in one cell.

## Linux

### Install (target shape v1.0)

```bash
# Ubuntu / Debian
sudo apt install fishbowl-v2
sudo systemctl enable --now fishbowl
```

For early adopters before `.deb` packaging lands:

```bash
curl -fsSL https://github.com/Antonlovesdnb/fishbowl-v2/releases/latest/download/install.sh | sudo bash
```

(Document `curl | bash` as "try-it" only, never as the recommended path. Blue teams hate it. Real fleets use `.deb` via apt or a config-management push.)

### What gets installed

| Path | Purpose |
|---|---|
| `/usr/local/bin/fishbowl` | Daemon binary (static, ~5-10 MB) |
| `/etc/systemd/system/fishbowl.service` | Systemd unit |
| `/etc/fishbowl/config.toml` | Default config |
| `/var/lib/fishbowl/` | Per-session identifier indexes |
| `/var/log/fishbowl/events.jsonl` | Default event sink |

### Privileges

Daemon requires `CAP_BPF` + `CAP_SYS_ADMIN` + `CAP_PERFMON`. Easiest path: run as root via systemd. Hardened path: dedicated `fishbowl` user with `AmbientCapabilities=` set in the unit file. v0.x ships as root; document the hardened mode in v1.0.

### Sample systemd unit

```ini
[Unit]
Description=fishbowl-v2 AI agent telemetry daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/fishbowl daemon --config /etc/fishbowl/config.toml
Restart=on-failure
RestartSec=5s
# v0.x: root. v1.0: dedicated user with ambient caps.
User=root

[Install]
WantedBy=multi-user.target
```

### Uninstall

```bash
sudo systemctl disable --now fishbowl
sudo apt remove fishbowl-v2
sudo rm -rf /var/lib/fishbowl  # purge session state, optional
```

## Windows

### Install (target shape v1.0)

```powershell
# Signed MSI from a GitHub release
msiexec /i fishbowl-v2.msi /quiet

# Eventually:
winget install fishbowl-v2
```

### What gets installed

| Path | Purpose |
|---|---|
| `C:\Program Files\fishbowl\fishbowl.exe` | Daemon binary |
| `C:\ProgramData\fishbowl\config.toml` | Default config |
| `C:\ProgramData\fishbowl\sessions\` | Per-session identifier indexes |
| `C:\ProgramData\fishbowl\events.jsonl` | Default event sink |
| Windows Service `fishbowlsvc` | Auto-start, runs as `LocalSystem` |
| Registered ETW providers | `Microsoft-Windows-Kernel-Process`, `-Kernel-File`, `-Kernel-Network` consumers |

### Privileges

Service runs as `LocalSystem`. Hardening path: a dedicated service account with `SeAuditPrivilege`, `SeSystemProfilePrivilege`, `SeDebugPrivilege`. Document but do not ship hardened by default in v0.x.

### Code signing — flag this early

Unsigned MSIs trigger SmartScreen warnings and Defender attention. For an enterprise blue-team audience, a signed MSI is essentially mandatory.

- Sectigo OV code-signing cert: ~$200-400/yr
- Lead time: 1-3 weeks for OV; longer for EV
- Without a cert, the post's install step will need a "click through SmartScreen" caveat that undermines the pitch
- **Buy the cert before publishing.** Not before coding.

### Uninstall

```powershell
# Add/Remove Programs handles it, or:
msiexec /x fishbowl-v2.msi /quiet
```

## Configuration

`config.toml` shape (both platforms identical except path conventions):

```toml
[daemon]
# Agent CLIs to enroll. Watch process exec for these names + their descendants.
enrolled_agents = ["claude", "cursor", "codex", "claude.exe", "cursor.exe", "codex.exe"]

[transcript]
# Where the daemon finds Claude Code session JSONL files
# Linux: $HOME/.claude/projects/*/*.jsonl
# Windows: %USERPROFILE%\.claude\projects\*\*.jsonl
watch_dirs = ["~/.claude/projects"]

[output]
# Sink: stdout | file | syslog | splunk_hec | otel
sink = "file"
file_path = "/var/log/fishbowl/events.jsonl"  # or C:\ProgramData\fishbowl\events.jsonl

[output.splunk_hec]
url = "https://splunk.example.com:8088/services/collector"
token = "..."
index = "fishbowl"

[probes]
# Toggle individual probes. All enabled by default.
process_exec = true
credential_access = true
network_egress = true
file_write = false  # Off by default — agent-config-tampering probe, opt-in
```

## Distribution channels — rollout order

1. **v0.1 (private testing):** Built artifacts in GitHub Releases, manual download
2. **v0.5 (Linux post-ready):** `.deb` in GitHub Releases. Install script published. Linux flow polished.
3. **v0.9 (Windows post-ready):** Signed `.msi` in GitHub Releases. Code-signing cert active.
4. **v1.0 (post published):** Same as v0.9. After the post lands, push to `winget` and a `apt` repo (Cloudsmith or self-hosted).

## Build pipeline

`cargo` produces the binaries; `cargo-deb` and `cargo-wix` wrap them.

| Artifact | Built by | CI runner | Triggered on |
|---|---|---|---|
| `fishbowl-linux-x86_64.tar.gz` | `cargo build --release` | `ubuntu-22.04` | every push |
| `fishbowl-v2_<version>_amd64.deb` | `cargo deb` | `ubuntu-22.04` | `git tag v*` |
| `fishbowl-windows-x86_64.zip` | `cargo build --release` | `windows-2022` | every push |
| `fishbowl-v2-<version>.msi` | `cargo wix` + signtool | `windows-2022` | `git tag v*` |

Code signing for MSI happens in the Windows CI job with the cert stored as a GitHub Actions secret (`WINDOWS_CODESIGN_PFX_BASE64` + `WINDOWS_CODESIGN_PASSWORD`).

## What this affects in the schema/code

The unified event schema (`schema.md`) is unchanged by deployment shape. What changes:

- **`host_id`** envelope field needs a population strategy. Linux: `/etc/machine-id`. Windows: HKLM `MachineGuid`. Resolve once at daemon startup.
- **`user_id`** for kernel-side events. Linux: euid + username from passwd. Windows: SID + username from token.
- **`source.collector`** values become real: `linux_ebpf`, `windows_etw`, `transcript` (already in the prototype).
- **Per-session identifier index** lives at `/var/lib/fishbowl/sessions/<session-uuid>.idx.json` (Linux) or `C:\ProgramData\fishbowl\sessions\<session-uuid>.idx.json` (Windows). Daemon writes; collectors read.
