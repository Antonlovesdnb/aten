# ATEN

**A**gent **T**elemetry & **E**vent **N**otation — *Sysmon for AI agents.*

An AI coding agent will read a file, run a command, open a socket — and from the kernel's seat all of it looks like ordinary `node` or `python` activity. ATEN watches two things at once: what the agent **says** it's doing (its prompts, tool calls, and tool results) and what its process tree **actually** does (exec, credential reads, DNS, egress, sensitive writes). It then stitches the two together by session and process descent, so a detection can fire on the gap between them — not on "a process read `~/.aws/credentials`" (every box does that) and not on "the agent ran a command" (meaningless alone), but on *a descendant of an agent tool call read credentials that nobody in the session ever named.*

One event schema across Linux (eBPF), Windows (ETW), and macOS (EndpointSecurity). Output is JSONL, or — on Windows — a Sysmon-style event-log channel (`ATEN/Operational`) for WEF/SIEM pickup.

## Status

Linux and Windows collectors are built and verified end-to-end. macOS (EndpointSecurity + a NetworkExtension) is written but not yet exercised on hardware. Schema is at **v0.5**.

ATEN observes; it does not block, kill, or quarantine. The credential→exfil call is a SIEM rule over the events it emits, deliberately not an inline action in the daemon. The design working-notes (`schema.md`, `scenarios.md`, …) sit in the repo root and are gitignored on purpose — drafts, not docs.

## How the join works

```
  intent layer ── transcript reader
  │  tails ~/.claude/projects and ~/.codex/sessions as the agent writes them
  │  emits   prompt · tool_call · tool_result
  │  builds  a per-session index of every path / host / IP / command and where
  │          it first surfaced — a user message, the model, or a tool result
  │
  action layer ── kernel collector   (eBPF · ETW · EndpointSecurity)
  │  watches enrolled agent processes and every descendant — nothing else
  │  emits   process_exec · credential_access · file_write · dns_query · network_egress
  │
  ▼
  attribution engine
  │  matches each action event to the session + tool_call its process tree
  │  descends from, then fills in the attribution block
  ▼
  one JSONL stream  →  your SIEM     (or ATEN/Operational on Windows)
```

The agent CLI is never wrapped, patched, or made aware ATEN is there. A process gets *enrolled* when its image name matches one you've named (`claude`, `cursor`, `codex` by default), and enrollment flows down the process tree on exec — so a `claude → bash → npm → node postinstall.js` chain is all traced back to the same agent root, while everything else on the host is dropped at the collector and never reaches your pipeline.

Because both layers serialize to the same field names everywhere, a detection you write once runs unchanged on Linux, Windows, and macOS.

A few things worth knowing before you deploy:

- Kernel events fire at the same instant the agent is still writing the matching `tool_call` to its transcript — sometimes before it hits disk. ATEN buffers each kernel event ~2s before attributing, so it binds to the *actual* triggering call rather than the previous one. Cost: ~2s from action to JSONL line, which no SIEM forwarder will notice.
- If the nearest tool call precedes the event by more than 10s, the binding is treated as untrustworthy: `attributed_tool_call_id` and `triggering_command` go null instead of pointing at a stale call. The origin booleans and `triggering_prompt` don't depend on that gate — they come from the session-wide index and stay valid regardless.
- Emission cursors persist (`state.json`), so a service restart replays no history and drops nothing in flight.

## What attribution actually buys you

Here's one real (abridged) event — the tail end of a malicious `npm` postinstall reading AWS keys:

```json
{
  "event_type": "credential_access",
  "platform": "linux",
  "session_id": "9f3c2-…-7bd",
  "process": {
    "name": "node",
    "cmdline": "node …/node_modules/lodash-utils-extra/postinstall.js",
    "parent_chain": [{"pid":31002,"name":"claude"}, {"pid":84211,"name":"npm"}],
    "agent_root_pid": 31002
  },
  "file_path": "/home/anton/.aws/credentials",
  "credential_class": "aws_credentials",
  "access_type": "read",
  "attribution": {
    "attributed_tool_call_id": "toolu_01ABC",
    "attributed_by_descent": true,
    "requested_by_tool_call": false,
    "requested_in_user_message": false,
    "requested_in_assistant_message": false,
    "requested_in_tool_result": false,
    "triggering_prompt": "install lodash-utils-extra please"
  }
}
```

`attributed_by_descent` is true — this ran under a tool call. But all four `requested_*` are false: not the tool call's arguments, not the user, not the model, not an upstream tool result ever named `~/.aws/credentials`. The credentials were read by something riding the agent's process tree that nobody in the conversation asked for. That's the postinstall fingerprint, and catching it is one `WHERE` clause:

```spl
index=aten event_type=credential_access
| where attributed_tool_call_id!=null
        AND requested_by_tool_call=false  AND requested_in_user_message=false
        AND requested_in_assistant_message=false  AND requested_in_tool_result=false
| stats values(file_path) as creds, values(triggering_prompt) as user_asked_for,
        values(process.path) as offender  by session_id, user_id, host_id
```

The point of splitting origin four ways instead of one "was it requested" flag is that flipping the booleans changes the attack class you're describing. Prompt injection is the *opposite* corner — the agent *was* told to read the file, but by content it fetched, not by the user:

```spl
index=aten event_type=credential_access
| where requested_by_tool_call=true AND requested_in_user_message=false
        AND requested_in_tool_result=true
| stats values(file_path) as creds, values(triggering_prompt) as user_asked_for,
        values(tool_call_id) as fooled_tool_call  by session_id, user_id, host_id
```

The full attribution block:

| field | what it tells you |
|---|---|
| `attributed_tool_call_id` | the tool call this event's process tree descends from (null if none / below confidence) |
| `attributed_by_descent` | spawned under the enrolled agent root, inside a tool-call window |
| `requested_by_tool_call` | the identifier appears in that tool call's input |
| `requested_in_user_message` | it appears in something the user typed this session |
| `requested_in_assistant_message` | it appears in the model's own output |
| `requested_in_tool_result` | it appears in an earlier tool result — **the injection tell** |
| `triggering_command` / `triggering_prompt` | the human-readable command and the user prompt behind it, denormalized onto the row so you don't need a temporal join to read intent |

The "identifier" each `requested_*` is matched against is the event's primary one: `file_path` for credential/file events, `dest_host`/`dest_ip` for egress, `query_name` for DNS, `cmdline` for exec. Pick a corner of the cube and you've described an attack class:

```
attack class                          descent  tool args  user  model  tool result
malicious descendant (postinstall)       T        F        F      F         F
prompt injection (fetched content)       T        T        F      T         T
legitimate agent action                  T        T        T      T         F
model-invented credential read           T        T        F      T         F
```

## Events and what's watched

**Intent layer**, read from the transcript: `prompt`, `tool_call`, `tool_result`. No process context — these come from the file the agent writes, not a running process.

**Action layer**, from the kernel, only for enrolled processes and their descendants:

- `process_exec` — a spawn, with argv and a selected slice of the environment.
- `credential_access` — a read/write/open of a credential path, classified at the collector into a typed `credential_class` so your rules never regex a path: `aws_credentials`, `azure_credentials`, `gcp_credentials`, `ssh_private_key`, `git_credentials`, `dpapi_blob`, `credential_manager`, `browser_cookies`, `kube_config`, `generic_dotenv`. Non-credential reads classify as `none` and are dropped.
- `file_write` — only the writes worth waking up for: `agent_config` (writes into the agent's own `skills/`, `agents/`, `settings.json`, `.claude/`, `.codex/` — the self-modification / persistence vector) and `executable` (`.sh`, `.ps1`, `.py`, `.exe`, …— payload staging). Ordinary writes are dropped. A *write* to a credential path stays on `credential_access` with `access_type=write`, which owns that taxonomy. Agent-root self-writes are emitted, not suppressed — filter them SIEM-side with `pid==agent_root_pid` so an in-process-compromised agent can't hide in a collector blind spot.
- `dns_query` — `query_name`, a typed `query_type` (`txt` being the classic tunnel carrier), and best-effort `answers`. Doubles as the way to recover the hostname behind a `network_egress` whose `dest_ip` is just a shared-CDN address — join `dns_query.answers → network_egress.dest_ip`. On Linux the probe is a libc resolver uprobe, so it reports `query_type=other` and statically-linked or raw-DNS tools slip past; Windows sees the wire qtype and the answers.
- `network_egress` — outbound connect with dest IP/port, hostname, and TLS SNI when observed.

Every action event also carries a `process` block (pid/ppid, path, cmdline, cwd, user, Windows integrity level, the PID-tagged `parent_chain`, and `agent_root_pid`) and the envelope shared by all events (`schema_version`, `event_id`, `timestamp`, `platform`, `host_id`, `agent_id`, `session_id`, `user_id`).

Coverage today: the full action set is live on Linux and Windows; macOS emits `process_exec`, `credential_access`, and `network_egress` but not yet `file_write` or `dns_query`. `process_exit` is reserved in the schema and not emitted by any collector yet.

## Running it

ATEN is one `aten` binary. The collectors need privilege — root or `CAP_BPF`+`CAP_PERFMON` on Linux, Administrator on Windows, root plus the EndpointSecurity entitlement on macOS.

```sh
# install as a service (survives reboots, drops a default config if none exists)
aten install          # Windows: atensvc SCM service + the ATEN/Operational channel
sudo aten install     # Linux: /etc/systemd/system/aten.service, enabled

# or run in the foreground to try it
aten daemon --watch-dir ~/.claude/projects --watch-dir ~/.codex/sessions --out events.jsonl
aten daemon --sink eventlog     # Windows: emit to ATEN/Operational instead of JSONL
aten version
```

Config lives at `/etc/aten/config.toml` (Linux) or `%ProgramData%\aten\config.toml` (Windows). Every field is optional and any CLI flag overrides it:

```toml
[daemon]
agents = ["claude", "cursor", "codex"]   # image basenames to enroll as agent roots

[transcripts]
watch_dirs = ["/home/anton/.claude/projects", "/home/anton/.codex/sessions"]

[output]
file_path = "/var/log/aten/events.jsonl"
sink = "jsonl"                           # jsonl | eventlog | both  (eventlog/both: Windows only)
```

Default output is `/var/log/aten/events.jsonl` on Linux and `%ProgramData%\aten\events.jsonl` on Windows. On Windows `sink = eventlog` writes the `ATEN/Operational` channel for WEF forwarding; `both` does the file and the channel.

## Lineage

ATEN is the productized successor to **fishbowl v1** ([Antonlovesdnb/fishbowl](https://github.com/Antonlovesdnb/fishbowl)), the per-invocation wrapper PoC behind the original credential-auditing blog — v1's Splunk queries port over with field renames only. The eBPF-plus-correlation idea comes from **AgentSight** ([arxiv:2508.02736](https://arxiv.org/abs/2508.02736)); ATEN runs it as an always-on daemon rather than a wrapper, adds Windows ETW and macOS EndpointSecurity, and lands the one cross-platform schema and the attribution model.
