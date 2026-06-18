# ATEN

**A**gent **T**elemetry & **E**vent **N**otation — an always-on, cross-platform telemetry daemon for AI agent activity. *Sysmon for AI agents.*

ATEN captures what an AI coding agent (Claude Code, Cursor, Codex, …) **says it's doing** — prompts, tool calls, tool results — and what its process tree **actually does** to the endpoint — process exec, credential reads, network egress, DNS, sensitive file writes — and stitches the two together by session and process descent. Detections then fire on the *join*: not "a process read `~/.aws/credentials`" (noisy) and not "the agent ran a command" (meaningless alone), but "a descendant of an AI tool call touched credentials that nobody in the session ever asked for."

One unified event schema across Linux (eBPF), Windows (ETW), and macOS (EndpointSecurity). JSONL output, or — on Windows — a dedicated Sysmon-style Event Log channel (`ATEN/Operational`) for WEF/SIEM collection.

---

## Status

Working daemon on **Linux (eBPF)** and **Windows (ETW)** — both built and verified end-to-end. **macOS (EndpointSecurity + NetworkExtension)** is implemented but not yet verified on hardware. Schema is at **v0.5**.

ATEN is observe-only by design. It does not block, kill, or quarantine — the credential→exfil decision is a SIEM rule over the events it emits, not an inline action in the daemon.

Design working-notes (the schema rationale, attribution model, scenario walkthroughs, and prior-art landscape) live in the repo root (`schema.md`, `scenarios.md`, etc.) and are intentionally gitignored — they're drafts, not published docs.

---

## How it works

ATEN runs two collectors side by side and a small engine that joins them.

```
┌──────────────────────────┐         ┌─────────────────────────────────┐
│  Transcript reader        │        │  Kernel collector                │
│  (intent layer)           │        │  (action layer)                  │
│                           │        │                                  │
│  watches ~/.claude/…,     │        │  Linux  : eBPF tracepoints/uprobe │
│  ~/.codex/… JSONL files   │        │  Windows: ETW kernel providers    │
│                           │        │  macOS  : EndpointSecurity + NE   │
│  emits: prompt,           │        │  emits: process_exec,             │
│         tool_call,        │        │         credential_access,        │
│         tool_result       │        │         file_write, dns_query,    │
│                           │        │         network_egress            │
└────────────┬─────────────┘         └────────────────┬────────────────┘
             │                                         │
             │   identifier index + tool-call timeline │  raw kernel events
             ▼                                         ▼
        ┌──────────────────────────────────────────────────┐
        │              Attribution engine                    │
        │  binds each kernel event to the session + tool     │
        │  call it descends from, and fills the 5 booleans   │
        └───────────────────────┬───────────────────────────┘
                                 ▼
                  Unified JSONL  /  ATEN/Operational (Windows)
                                 ▼
                              SIEM
```

**1. The intent layer (transcript reader).** The agent CLI writes a JSONL transcript of every session (Claude Code under `~/.claude/projects/`, Codex under `~/.codex/sessions/`). ATEN tails those files and emits `prompt`, `tool_call`, and `tool_result` events. It also builds a per-session **identifier index**: for every file path, hostname, IP, and command string mentioned in the session, it records *where it first surfaced* — in a user message, an assistant (model) message, or a tool result. The agent CLI is never wrapped, patched, or made aware ATEN exists.

**2. The action layer (kernel collector).** A platform-native collector watches the endpoint and emits events only for **enrolled** processes — the agent CLIs you name, plus every descendant of one. A process becomes enrolled when its image basename matches an agent name (`claude`, `cursor`, `codex` by default); enrollment propagates down the process tree via exec, so a `bash` → `npm` → `node postinstall.js` chain under Claude Code is all attributed back to the same agent root. Everything else on the box is ignored at the collector, so the daemon stays quiet.

**3. The attribution engine.** This is ATEN's signature contribution. Every kernel event arrives carrying its process tree's `agent_root_pid`. The engine matches that root's working directory to a transcript session, then — within a confidence window — binds the event to the tool call it descends from and sets five independent booleans describing where the event's *primary identifier* (the file path, dest host, or command) first appeared in the session. Detections combine those booleans to carve out attack classes (see [Attribution model](#the-attribution-model)).

Because both layers serialize to the **same schema with the same field names on every platform**, a SIEM detection written once runs identically on Linux, Windows, and macOS.

### Runtime details an operator should know

- **Enrollment is by process descent, not argv interception.** PIDs are enrolled by watching exec; the agent is never wrapped. A long-running descendant that outlives its tool call keeps its attribution.
- **Attribution buffer.** Kernel events fire concurrently with the agent writing its transcript, so a kernel event can arrive before the triggering `tool_call` is even on disk. ATEN holds kernel events ~2 s before attributing, giving the transcript poll (~100 ms) time to catch up. This adds ~2 s of latency from action to JSONL line — negligible for security telemetry.
- **Confidence gate.** If the nearest tool call is more than 10 s before the event, `attributed_tool_call_id` / `triggering_command` are left null rather than guessing at a stale call. `triggering_prompt` (the most recent user prompt) is always populated when one exists, because user prompts don't have the transcript-flush race.
- **State persistence.** Emission cursors persist across restarts (`state.json`), so a service restart replays no history and drops nothing. Transcript history present at startup is folded into attribution context but not re-emitted.

---

## What it watches for

### Event types

Every event shares an envelope (`schema_version`, `event_id`, `timestamp`, `platform`, `host_id`, `agent_id`, `session_id`, `user_id`). Events with a PID also carry a `process` block (pid/ppid, path, cmdline, cwd, user, integrity level on Windows, parent chain, `agent_root_pid`) and an `attribution` block.

| Event | Layer | Linux | Windows | macOS | What it captures |
|---|---|:--:|:--:|:--:|---|
| `prompt` | intent | ✅ | ✅ | ✅ | A user/assistant/system message in the transcript |
| `tool_call` | intent | ✅ | ✅ | ✅ | The agent invoking a tool (`Bash`, `Read`, `WebFetch`, …) with its raw input |
| `tool_result` | intent | ✅ | ✅ | ✅ | The result returned to the agent, with kernel-side child PIDs observed during the call |
| `process_exec` | action | ✅ | ✅ | ✅ | An enrolled process or descendant spawning, with argv + selected env |
| `credential_access` | action | ✅ | ✅ | ✅ | A read/write/open of a credential-class path (classified at the collector) |
| `file_write` | action | ✅ | ✅ | — | A *sensitive* write: agent self-config or executable/script staging |
| `dns_query` | action | ✅ | ✅ | — | A name resolution by an enrolled process, with answers when observed |
| `network_egress` | action | ✅ | ✅ | ✅ | An outbound connect, with dest IP/port, host, and TLS SNI when seen |

(`process_exit` is reserved in the schema but no collector emits it yet. macOS does not yet emit `file_write`/`dns_query`.)

### Credential classes

`credential_access` events are classified at the collector into a typed `credential_class`, so detections never regex over file paths. The same enum is produced on every platform:

`aws_credentials`, `azure_credentials`, `gcp_credentials`, `ssh_private_key`, `git_credentials`, `dpapi_blob` (Windows), `credential_manager` (Windows), `browser_cookies`, `kube_config`, `generic_dotenv`.

Non-credential file reads return `none` and are dropped at the collector.

### Sensitive file-write classes

`file_write` is emitted only for writes worth alerting on; ordinary writes are dropped at the collector. Two classes:

- **`agent_config`** — writes to the agent's own configuration surface (`skills/`, `agents/`, `settings.json`, `.claude/`, `.codex/`). This is the self-modification / persistence vector.
- **`executable`** — writes of scripts or executables (`.sh`, `.ps1`, `.py`, `.exe`, `.bat`, …) — payload / exfil-script staging.

Credential-path *writes* are not a `file_write` class — they surface as `credential_access` with `access_type = write` (that event owns the credential taxonomy). Agent-root self-writes are **not** suppressed at the collector (that would blind you to an in-process-compromised agent); the SIEM filters expected self-writes with `pid == agent_root_pid`.

### DNS

`dns_query` carries the `query_name`, a typed `query_type` (`a`, `aaaa`, `txt`, …; `txt` is the classic tunnel/exfil carrier), and best-effort `answers`. Two jobs: surface DNS-based exfil, and recover the hostname behind a `network_egress` whose `dest_ip` would otherwise be an opaque shared-CDN address (join `dns_query.answers` → `network_egress.dest_ip`). On Linux the probe is a libc resolver uprobe, so it tags `query_type = other` and statically-linked or raw-DNS tools bypass it; Windows sees the wire qtype and answers.

---

## The attribution model

Every PID-bearing event carries an `attribution` block. The signal is five independent booleans (plus the bound tool-call id, time window, and human-readable `triggering_command` / `triggering_prompt`):

| Field | Meaning |
|---|---|
| `attributed_tool_call_id` | The tool call this event's process tree descends from (null if none active / below confidence) |
| `attributed_by_descent` | The process descends from the enrolled agent root, spawned inside a tool-call window |
| `requested_by_tool_call` | The event's identifier appears in the bound tool call's input |
| `requested_in_user_message` | The identifier appears in a user-typed message this session |
| `requested_in_assistant_message` | The identifier appears in an assistant/model message |
| `requested_in_tool_result` | The identifier appears in a prior tool result — **the prompt-injection signal** |

The booleans are independent on purpose. Descent alone is too loose (a postinstall script is always a descendant). Argument matching alone is too tight (the user might paraphrase). And collapsing "the user/model/tool asked for it" into one flag hides prompt injection — tool-result content is machine-generated, not user intent, even though it rides a "user-role" transcript record. Splitting origin lets one schema shape express many attack classes by picking a corner of the cube:

| Attack class | descent | tool args | user msg | asst msg | tool result |
|---|:--:|:--:|:--:|:--:|:--:|
| Malicious descendant (npm postinstall) | T | F | F | F | F |
| Prompt injection (fetched content) | T | T | F | T | T |
| Legitimate agent action | T | T | T | T | F |
| Model-invented credential read | T | T | F | T | F |

### Example detections (Splunk)

**Malicious-descendant credential read** — a tool call's process descendant touched credentials that *no one* in the session ever mentioned:

```spl
index=aten event_type=credential_access
| where attributed_tool_call_id != null
        AND requested_by_tool_call=false
        AND requested_in_user_message=false
        AND requested_in_assistant_message=false
        AND requested_in_tool_result=false
| stats values(file_path) as creds,
        values(triggering_prompt) as user_asked_for,
        values(process.path) as offender
        by session_id, user_id, host_id
```

**Prompt-injection credential read** (sibling rule, different corner) — a tool call read credentials because an upstream tool result told the agent to, and the user never asked:

```spl
index=aten event_type=credential_access
| where requested_by_tool_call=true
        AND requested_in_user_message=false
        AND requested_in_tool_result=true
| stats values(file_path) as creds,
        values(triggering_prompt) as user_asked_for,
        values(tool_call_id) as fooled_tool_call
        by session_id, user_id, host_id
```

Swap `event_type` and the identifier field (`file_path` → `dest_host` / `query_name` / `file_path`) to get the egress, DNS-exfil, and self-modification siblings of each rule.

---

## Deploying it

ATEN ships as a single `aten` binary. The kernel collectors need privilege: root or `CAP_BPF`+`CAP_PERFMON` on Linux, Administrator on Windows, root + the EndpointSecurity entitlement on macOS.

**Install as a service** (survives reboots; drops a default config if none exists):

```sh
# Windows (admin): registers the atensvc SCM service + the ATEN/Operational channel
aten install

# Linux (root): writes /etc/systemd/system/aten.service and enables it
sudo aten install
```

**Run in the foreground** (testing):

```sh
aten daemon --watch-dir ~/.claude/projects --watch-dir ~/.codex/sessions --out events.jsonl
aten daemon --sink eventlog          # Windows: write to ATEN/Operational instead of JSONL
aten version                          # print binary + schema version
```

**Configuration** (`/etc/aten/config.toml` on Linux, `%ProgramData%\aten\config.toml` on Windows). All fields optional; CLI flags override the file:

```toml
[daemon]
agents = ["claude", "cursor", "codex"]   # process basenames to enroll as agent roots

[transcripts]
watch_dirs = ["/home/anton/.claude/projects", "/home/anton/.codex/sessions"]
files = []                                # individual transcripts (single-session test mode)

[output]
file_path = "/var/log/aten/events.jsonl"
sink = "jsonl"                            # jsonl | eventlog | both   (eventlog/both = Windows only)
```

Default output: `/var/log/aten/events.jsonl` (Linux), `%ProgramData%\aten\events.jsonl` (Windows). On Windows, `sink = eventlog` writes to the `ATEN/Operational` Event Log channel for WEF/SIEM forwarding; `both` does JSONL and the channel.

---

## Relation to fishbowl v1

ATEN is the productized successor to fishbowl v1 ([Antonlovesdnb/fishbowl](https://github.com/Antonlovesdnb/fishbowl)) — the wrapper-style proof-of-concept with the original credential-auditing blog. v1 was a per-invocation wrapper; ATEN is the always-on daemon: cross-platform, blue-team-deployable. v1 Splunk queries port over with field renames only.

## Prior art

The eBPF + correlation architecture is from [AgentSight](https://github.com/eunomia-bpf/agentsight) ([arxiv:2508.02736](https://arxiv.org/abs/2508.02736)). ATEN ships it as an always-on daemon instead of a per-invocation wrapper, adds Windows ETW and macOS EndpointSecurity, and lands the SIEM-shaped unified schema and attribution model.
