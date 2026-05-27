# fishbowl-v2 — plan

## What it is

An always-on, cross-platform telemetry daemon for AI agent activity on developer endpoints. Captures **prompts + tool calls + endpoint syscalls** and joins them by session + process tree, so detections can be written against the join — not against either layer alone.

Tagline: *"Sysmon for AI agents — but actually deployed like Sysmon."*

## Why this shape

- AgentSight (arxiv 2508.02736, `eunomia-bpf/agentsight`) proved the eBPF + TLS-intercept + correlation pattern works. But it's a wrap-the-agent research tool — you have to launch the agent through `agentsight exec`. Not transparent. Useless against the malicious skill the dev didn't know to monitor.
- Sysdig and ARMO do related work but are k8s/cloud DaemonSets, not dev-endpoint.
- **The unoccupied lane: always-on, transparent, cross-platform (Linux + Windows), SIEM-shaped output, blue-team-deployable.**
- AgentSight is Linux-only and can't be ported easily — ETW ≠ eBPF. Windows support is therefore a hard differentiator, not just a nice-to-have.

## Positioning relative to AgentSight

Cite as prior art and inspiration. We're the production deployment of the pattern, not the originator. Differentiators:

1. **Always-on daemon** (systemd / Windows Service), not per-invocation wrapper
2. **Cross-platform** — Linux (eBPF) and Windows (ETW) with one unified event schema
3. **SIEM-shaped output** from day 1 — Splunk queries from existing fishbowl blog translate directly
4. **Credential-classification layer** carried over from v1 (Azure/AWS/GCP fingerprints + Windows Credential Manager / DPAPI)
5. **Detection content as the primary artifact** — the tool exists to enable the blog series, not the other way around

## Publication plan — one post

***"Deep and delicious: rethinking telemetry in the age of agentic workflows"***

- Thesis: EDR can't see AI threats because it can't see the prompt, the reasoning, or the tool calls. Why correlation is the only answer. Cite AgentSight as the research. Introduce fishbowl-v2 as the always-on, cross-platform deployment form.
- Demo: malicious npm scenario from v1 blog, re-run with fishbowl-v2 daemon already running (no wrapping). Show the joined event stream on both Linux and Windows side-by-side. **Same Splunk query, same verdict, both platforms.** Sharper detection than v1's: *"credentials read by a child process not requested by any agent tool call or the user."*
- Windows coverage is the signature move — Linux-only research tools (AgentSight) leave the enterprise blue-team endpoint empty. The one-post format makes that gap the headline, not a follow-up.

## Scope

### Ripped from v1
- Docker container wrapping
- `-mount` flag and credential mount logic
- Host vs. container collector split
- `fishbowl run` / `fishbowl audit` CLI ceremony
- Pre-declared credential registry (replaced by broader heuristic classifier)

### Kept from v1
- Credential classification taxonomy (Azure, AWS, GCP fingerprints)
- Event types: `credential_access`, `network_egress`, `process_exec`
- JSONL output format (extended with new fields)
- Splunk query patterns from the existing blog

### Net-new
- Service/daemon lifecycle: systemd unit (Linux) + Windows Service
- Agent process auto-discovery: watch `execve` (eBPF) / `Microsoft-Windows-Kernel-Process` (ETW), enroll matching PIDs + descendants
- Prompt-layer ingester:
  - v1: read Claude Code transcripts from `~/.claude/projects/*/transcripts.jsonl` (cross-platform, trivial)
  - v2 (later): SSL_read/SSL_write uprobes (Linux) / Schannel hooks (Windows) for raw SDK traffic
- Unified cross-platform event schema with `session_id`, `tool_call_id`, `attributed_tool_call`
- Attribution engine: time-window + process-descent join from tool calls to syscalls
- Cross-platform credential classifier: Linux paths + Windows Credential Manager / DPAPI / Git Credential Helper

## Mechanics by platform

### Linux
- **Kernel layer:** eBPF — `execve`, `connect`, `openat2` (already in fishbowl v1)
- **Prompt layer:** read Claude Code transcripts.jsonl; SSL uprobes deferred
- **Service:** systemd unit, runs as root or `CAP_BPF` + `CAP_SYS_ADMIN`

### Windows
- **Kernel layer:** ETW
  - `Microsoft-Windows-Kernel-Process` → process exec, parent-child
  - `Microsoft-Windows-Kernel-File` or SACL audit → credential file access
  - `Microsoft-Windows-Kernel-Network` → outbound connections
- **Prompt layer:** read Claude Code transcripts from `%USERPROFILE%\.claude\projects\`; Schannel hooks deferred
- **Service:** Windows Service running as `LocalSystem`, starts at boot
- **Credential classifier additions:** Credential Manager (Win32 API), DPAPI stores, Git Credential Helper, browser cookie stores

## Detection that demos the join

The killer detection — unprovable by either layer alone:

```sql
index=fishbowl event=credential_access attributed_tool_call=null
| where parent_chain LIKE "%claude%" OR parent_chain LIKE "%cursor%"
| stats values(path) as creds, values(prompt_summary) as user_asked_for
        by session_id user_id
```

Plain English: *"In an AI session, something touched credentials that no agent tool call requested and the user never mentioned."* Catches postinstall scripts, malicious skills firing before tool-call attribution, anything riding the agent's process tree.

## Engineering stack

- **User-space daemon (both platforms): Rust.** `libbpf-rs` on Linux, `ferrisetw` on Windows. Single static binary per platform, no runtime dependencies — important for the "install like Sysmon" deployment pitch. Matches AgentSight's Rust+C structure for direct architectural comparison.
- **BPF programs: C** compiled to BPF bytecode via clang. Standard for both `libbpf-rs` and `cilium/ebpf` ecosystems.
- **Schema / event types / identifier index / attribution engine:** shared Rust crate consumed by both collectors. The Python transcript-reader prototype gets ported to Rust once the schema stabilizes.
- **Packaging:** `cargo-deb` produces the `.deb`; `cargo-wix` produces the Windows `.msi`. GitHub Actions matrix builds both on `git tag`. See `deployment.md`.

Why not Go: `cilium/ebpf` is more mature than `libbpf-rs`, but Go's ETW story is thin and the Go runtime is a deployment-shape liability for a daemon that pitches itself as drop-in. Why not C/C++: user-space side would be painful — manual JSON, no decent HTTP clients, manual cross-platform abstraction.

## Engineering effort estimate

- Unified schema + attribution engine + Claude Code log reader: ~2 weeks
- Linux daemon refactor (rip container, add service, agent auto-discovery): ~2 weeks
- Windows ETW collector + service + Windows-specific classifier: ~4 weeks
- Cross-platform demo, scenario reruns, post drafting: ~2 weeks
- Single post ready to publish: **~8-10 weeks**

Longer time-to-publish than the two-post split, but a single artifact that lands the Windows differentiator in the headline instead of as a follow-up.

## Next step

Draft the unified event schema as the first artifact. Single doc with example events from both platforms for the malicious-npm scenario. Detection queries get sanity-checked against the schema before any code gets written.
