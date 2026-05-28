# Testing fishbowl-v2

Hands-on recipes for verifying the collectors and the daemon end-to-end. All
commands assume a checkout at `~/Desktop/fishbowl-v2` and a release build at
`target/release/`.

## Windows: malicious-npm demo

The headline demo. A local npm `file:` dependency's `postinstall` reads
`~/.aws/credentials` and beacons to a literal IP. Running `npm install`
under an enrolled Claude Code session emits a `credential_access` and a
`network_egress` from the *same* `node.exe` PID, both bound to the
specific tool call that ran the install.

### Prerequisites

- **Elevated PowerShell** — ETW user traces require admin
- Node.js + npm in `PATH`
- A real Claude Code session running (so a transcript file exists)
- `cargo build --release` against `target/release/fishbowl.exe`

### Demo harness

Two-package layout under `~/Desktop/fishbowl-demo/`:

- `malicious-pkg/` — `package.json` with a `postinstall` script that runs
  `postinstall.js` (reads `%USERPROFILE%\.aws\credentials`, makes an HTTPS
  request to `1.1.1.1`)
- `victim-project/` — `package.json` with `"dependencies": { "fishbowl-demo-credstealer": "file:../malicious-pkg" }`

`npm install` in `victim-project` triggers the malicious package's
postinstall, which fires the credacc + beacon from a `node.exe` whose
parent chain reaches back to `claude.exe`.

### Recipe

```powershell
# 1. Find the most-recent Claude Code transcript for this project.
$session = Get-ChildItem "$env:USERPROFILE\.claude\projects\C--Users-aovru-Desktop-fishbowl-v2\*.jsonl" |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1

# 2. Reset the victim project so npm install fires postinstall fresh.
$victim = "$env:USERPROFILE\Desktop\fishbowl-demo\victim-project"
Remove-Item -Recurse -Force $victim\node_modules -ErrorAction SilentlyContinue
Remove-Item -Force $victim\package-lock.json -ErrorAction SilentlyContinue

# 3. Start the daemon (25s window, writes to Desktop).
$out = "$env:USERPROFILE\Desktop\fishbowl-test.jsonl"
Start-Process -NoNewWindow -FilePath "$env:USERPROFILE\Desktop\fishbowl-v2\target\release\fishbowl.exe" `
    -ArgumentList "daemon", "--transcript", $session.FullName,
                  "--agents", "claude.exe",
                  "--duration-secs", "25",
                  "--out", $out

# 4. Give the trace ~3s to initialize, then run the victim install.
Start-Sleep -Seconds 3
Set-Location $victim
npm install --foreground-scripts

# 5. After the 25s window closes, summarize the captured events.
Start-Sleep -Seconds 25
Get-Content $out | ForEach-Object { $_ | ConvertFrom-Json } |
    Where-Object { $_.event_type -in 'credential_access','network_egress' } |
    Select-Object event_type,
        @{n='target';e={ if ($_.dest_ip) { "$($_.dest_ip):$($_.dest_port)" } else { $_.file_path } }},
        @{n='process';e={ $_.process.name }},
        @{n='integrity';e={ $_.process.integrity_level }},
        @{n='tool_call';e={ $_.attribution.attributed_tool_call_id }} |
    Format-Table -AutoSize
```

### Expected output

```
event_type        target                              process  integrity tool_call
----------        ------                              -------  --------- ---------
credential_access C:\Users\aovru\.aws\credentials     node.exe high      toolu_01...
network_egress    1.1.1.1:443                         node.exe high      toolu_01...
```

Both rows share the same `tool_call` value — that's the cross-platform
"same query, both kernels" hook. The `file_path` is in Win32 drive-letter
form (not `\Device\HarddiskVolumeN\...`) thanks to the path-normalization
helper. `integrity_level: high` reflects that the postinstall ran under
the elevated PowerShell.

### Common gotchas

- **Empty JSONL.** The daemon must run from an *elevated* PowerShell. If
  not, `start_and_process` returns `Access is denied.` and exits cleanly
  with no events written.
- **Trace startup race.** Anything started *before* `fishbowl-etw: trace starting`
  prints is enrolled retroactively by the pre-trace rundown. Anything
  started after is enrolled via the live `ProcessStart` event. There's no
  in-between gap — except, very briefly, between `trace starting` and the
  rundown thread actually getting CPU time. Sleeping ~3 seconds before
  triggering the demo is a safe margin.
- **Stale `node_modules`.** npm short-circuits postinstall when packages
  are already present. Always remove `node_modules` + `package-lock.json`
  between runs.

## Linux: same demo via SSH

The Linux side is feature-complete on the VM at `192.168.1.215`. Same
malicious-npm scenario, with the kernel events sourced from eBPF
tracepoints instead of ETW. Build + test loop:

```bash
git push origin main
ssh fishbowl-vm "cd ~/src/fishbowl-v2 && git pull --ff-only && ~/.cargo/bin/cargo test --workspace"
```

A live run on the VM (under root) would be the natural cross-platform
side-by-side once the post is being written.

## Transcript reader

The `fishbowl transcript <path>` subcommand reads a session JSONL and
emits the schema events + identifier-origin index. It auto-detects the
dialect from the path:

- `~/.claude/projects/...` → Claude Code reader
- `~/.codex/sessions/.../rollout-*.jsonl` → Codex reader

```powershell
# Claude Code session
target\release\fishbowl.exe transcript $env:USERPROFILE\.claude\projects\C--Users-aovru-Desktop-fishbowl-v2\<uuid>.jsonl

# Codex session
target\release\fishbowl.exe transcript $env:USERPROFILE\.codex\sessions\2026\03\07\rollout-<uuid>.jsonl
```

Both emit the same schema event types (`prompt`, `tool_call`, `tool_result`)
and write `<stem>.events.jsonl` + `<stem>.idx.json` next to the input.

## Unit tests

```powershell
cargo test --workspace
```

Expected: ~40 tests across `fishbowl-collector-linux`, `fishbowl-collector-windows`,
`fishbowl-transcript`, `fishbowl-attribution`. Cross-platform crates
(`fishbowl-schema`, `fishbowl-transcript`) run on both hosts; collectors
are platform-gated and only build their tests on the matching OS.
