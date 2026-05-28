# Testing fishbowl-v2

How to install and exercise the daemon on a real Windows host. The
intended use is as a Windows service, installed once, then left running
while you use Claude Code / Codex normally — events accumulate to a
JSONL file you can inspect at any time.

## Install as a service (recommended)

From an **elevated PowerShell**:

```powershell
cargo build --release
.\target\release\fishbowl.exe install
```

That command:
1. Registers the service `fishbowlsvc` with the SCM, set to auto-start
2. Drops a default config at `C:\ProgramData\fishbowl\config.toml` (only
   if no config exists yet — re-running `install` preserves your edits)
3. Starts the service

Verify it's running:

```powershell
Get-Service fishbowlsvc
```

`Status: Running` means kernel events are being captured into
`C:\ProgramData\fishbowl\events.jsonl` whenever an enrolled agent
(by default `claude.exe`, `cursor.exe`, `codex.exe`) or one of its
descendants does something interesting.

## What gets detected

The service consumes three ETW kernel providers and emits one schema
event per matching syscall:

| Probe | Fires when |
|---|---|
| `process_exec` | An enrolled agent spawns (descendants don't emit their own exec; they're tracked via `parent_chain`) |
| `credential_access` | An enrolled agent or descendant opens a file whose path matches the credential classifier (`~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.kube/config`, `*.pem`, browser cookie stores, etc.) |
| `network_egress` | An enrolled agent or descendant makes an outbound TCP connection (loopback + link-local filtered out) |

Anything else — your browser, Notepad, an unenrolled Python REPL — is
invisible to fishbowl. That's the design: telemetry is bounded to the
agent's process tree.

## Use it ambiently

Once installed, just use Claude Code / Codex as you normally would. The
service is reading every agent session in `~/.claude/projects/` and
`~/.codex/sessions/` (the default config watch_dirs) and attributing
kernel events back to specific tool calls when timing and process tree
line up.

Inspect what's been captured:

```powershell
# Last 20 credential reads and network connects, in attribution order.
Get-Content C:\ProgramData\fishbowl\events.jsonl |
    ForEach-Object { $_ | ConvertFrom-Json } |
    Where-Object { $_.event_type -in 'credential_access','network_egress' } |
    Select-Object -Last 20 timestamp,
        event_type,
        @{n='process';e={ $_.process.name }},
        @{n='target';e={ if ($_.dest_ip) { "$($_.dest_ip):$($_.dest_port)" } else { $_.file_path } }},
        @{n='session';e={ if ($_.session_id) { $_.session_id.Substring(0,8) } else { '<unbound>' } }},
        @{n='tool_call';e={ $_.attribution.attributed_tool_call_id }} |
    Format-Table -AutoSize
```

A few honest test scenarios that exercise different parts of the
system. None require special harness:

1. **Direct prompt** — ask Claude Code "read `~/.aws/credentials` and
   summarize." Expect a `credential_access` event tied to the bash-tool
   `tool_call_id` that ran `cat`.
2. **Multi-event chain** — ask Claude to "ssh into the fishbowl VM and
   run uptime." Expect a `credential_access` on `~/.ssh/id_rsa` plus a
   `network_egress` to `192.168.1.215:22`, both bound to the same
   tool_call.
3. **Network only** — ask Claude to "fetch `https://example.com`."
   Expect a `network_egress`.
4. **Ambient noise** — leave the service running for an hour while you
   use Claude/Codex. Every time the agent's bash tool spawns a process
   that reads a creds-shaped file or opens a TCP connection, an event
   lands in the JSONL.

## Edit the config

`C:\ProgramData\fishbowl\config.toml` controls what's enrolled, where
transcripts are read from, and where events get written:

```toml
[daemon]
agents = ["claude.exe", "cursor.exe", "codex.exe"]

[transcripts]
watch_dirs = [
    "C:\\Users\\aovru\\.claude\\projects",
    "C:\\Users\\aovru\\.codex\\sessions",
]

[output]
file_path = "C:\\ProgramData\\fishbowl\\events.jsonl"
```

After editing, restart the service:

```powershell
sc.exe stop fishbowlsvc
sc.exe start fishbowlsvc
```

## Stop / start the service

```powershell
sc.exe stop fishbowlsvc          # pause capture
sc.exe start fishbowlsvc         # resume
Get-Service fishbowlsvc          # current state
```

## Uninstall

```powershell
.\target\release\fishbowl.exe uninstall
```

Stops the service if running, then deletes it from the SCM. Your
config + events JSONL are left in `C:\ProgramData\fishbowl\` for
inspection.

## Debugging

If the service won't start, or events aren't flowing:

```powershell
# Service-mode status messages (start, stop, errors). Anything that
# would have gone to stderr in CLI mode lands here.
Get-Content C:\ProgramData\fishbowl\service.log -Tail 30

# How many transcripts the engine has loaded.
Get-Content C:\ProgramData\fishbowl\service.log | Select-String "sessions"

# Event volume by type.
Get-Content C:\ProgramData\fishbowl\events.jsonl |
    ForEach-Object { ($_ | ConvertFrom-Json).event_type } |
    Group-Object | Format-Table Count, Name
```

## Manual / debug mode (no service)

For development iterations where you want to see live stderr from the
collector, run the daemon directly in an elevated PowerShell instead of
installing it. Same config + same kernel probes, just no SCM in front:

```powershell
# Single session, fixed window — useful for repeatable demos.
$session = Get-ChildItem "$env:USERPROFILE\.claude\projects\*\*.jsonl" |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
.\target\release\fishbowl.exe daemon --transcript $session.FullName --duration-secs 30 --out test.jsonl

# Multi-session, runs until Ctrl-C (same as service mode).
.\target\release\fishbowl.exe daemon `
    --watch-dir "$env:USERPROFILE\.claude\projects" `
    --watch-dir "$env:USERPROFILE\.codex\sessions" `
    --out test.jsonl

# Config file + CLI overrides combined.
.\target\release\fishbowl.exe daemon --config C:\ProgramData\fishbowl\config.toml --duration-secs 60
```

## Linux

Same daemon binary builds for Linux but uses eBPF instead of ETW. Live
testing is on the VM at `192.168.1.215`. The service-mode story on
Linux is `cargo-deb` + systemd unit — backlog item, not implemented yet
(see `deployment.md`).

## Unit tests

```powershell
cargo test --workspace
```

Expected: ~44 tests across the workspace. The Linux collector's tests
require Linux (skipped on Windows builds) and vice versa.
