# fishbowl-v2 unified event schema (draft v0.2)

One JSONL envelope across Linux (eBPF) and Windows (ETW). Same field names on both platforms. Existing fishbowl v1 Splunk queries translate with field renames only.

The schema's job is to make this query work, identically, on both platforms:

```spl
index=fishbowl event_type=credential_access
| where attributed_tool_call_id != null
        AND requested_by_tool_call=false
        AND requested_in_user_message=false
        AND requested_in_assistant_message=false
        AND requested_in_tool_result=false
| stats values(file_path) as creds,
        values(prompt_summary) as user_asked_for,
        values(process_path) as offender
        by session_id, user_id, host_id
```

Plain English: *in an AI session, a tool call's process descendant touched credentials that no participant in the session — user, model, or upstream tool — ever mentioned.* Catches postinstall scripts, malicious skills firing before tool-call attribution, anything riding the agent's process tree.

A sibling rule covers **prompt injection** by flipping the booleans (see §9.2): same join, different corner of the attribution cube.

---

## 1. Design goals

1. **One schema, two platforms.** Field names and semantics identical. Platform-specific raw source (`source.linux_ebpf_probe`, `source.windows_etw_provider`) is recorded but never required by detection logic.
2. **JSONL on disk, one event per line.** Output format compatible with v1; field set extended, never narrowed.
3. **SIEM-shaped.** Flat where possible. Nested only for `process` (ubiquitous) and `source` (debug-only).
4. **Attribution is a first-class field, not derived at query time.** Three booleans (`requested_by_tool_call`, `requested_in_prompt`, `attributed_by_descent`) make the join explicit so detections aren't fragile correlated subqueries.
5. **Always-on, never wrapping.** The agent CLI must not know fishbowl exists. PIDs are enrolled by watching process exec, not by intercepting argv.

## 2. Envelope (every event has these fields)

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | `"0.1"` — bump on breaking changes |
| `event_id` | string (UUIDv7) | Time-ordered UUID, primary key |
| `event_type` | enum | `prompt`, `tool_call`, `tool_result`, `process_exec`, `process_exit`, `credential_access`, `network_egress`, `file_write` |
| `timestamp` | string (RFC 3339, ns precision) | Wall clock, UTC |
| `monotonic_ns` | int64 | Host-relative monotonic counter for intra-tick ordering |
| `platform` | enum | `linux`, `windows` |
| `host_id` | string | Stable host identifier (machine GUID on Windows, `/etc/machine-id` on Linux) |
| `agent_id` | string | `claude-code`, `cursor`, `codex`, ... — derived from enrolled root process |
| `session_id` | string (UUID) | Claude Code transcript session UUID. Foreign key for the join. |
| `user_id` | string | OS user (`uid`/`username` on Linux, `SID`/`username` on Windows) |
| `source` | object | `{ collector: "ebpf"\|"etw"\|"transcript", probe: "<probe-or-provider-name>", host_pid: <int> }` — debug only |

## 3. Process context (every event with a PID — `process_exec`, `credential_access`, `network_egress`, `file_write`, `tool_result`)

Nested under `process`:

| Field | Type | Notes |
|---|---|---|
| `pid` | int | |
| `ppid` | int | |
| `start_time` | string (RFC 3339) | Process creation time; disambiguates PID reuse |
| `name` | string | `node`, `node.exe`, `python`, `python.exe` |
| `path` | string | Absolute, OS-native. `/usr/bin/node` vs `C:\Program Files\nodejs\node.exe` |
| `cmdline` | string | Full command line, joined |
| `cwd` | string | |
| `user` | string | Effective user (euid on Linux, primary token user on Windows) |
| `integrity_level` | string\|null | Windows only: `low`/`medium`/`high`/`system`. `null` on Linux. |
| `parent_chain` | array of strings | Process names root→current, e.g. `["systemd","claude","bash","npm","node"]`. Capped at 16. |
| `agent_root_pid` | int | The enrolled agent process at the top of this descent tree |

## 4. Attribution block (every event with a PID)

Nested under `attribution`. This is the schema's signature contribution.

| Field | Type | Notes |
|---|---|---|
| `attributed_tool_call_id` | string\|null | The tool_call this event's process tree descends from. `null` if no active tool call when the process started. |
| `attributed_by_descent` | bool | True if `process.agent_root_pid != null` and a tool call was active when this process (or its ancestor up to the agent root) was spawned. |
| `requested_by_tool_call` | bool | True if the event's primary identifier (`file_path`, `dest_host`, `cmdline`) appears in the attributed tool call's `tool_input`. |
| `requested_in_user_message` | bool | True if the same identifier appears in any user-typed message in this session up to this timestamp. |
| `requested_in_assistant_message` | bool | True if it appears in any assistant message (model reasoning chains) up to this timestamp. |
| `requested_in_tool_result` | bool | True if it appears in any prior `tool_result` content in this session. **The prompt-injection signal.** |
| `time_window_ms` | int\|null | Milliseconds between the tool call's emit and this event. Null if no attribution. |

**The detection works because the booleans are independent signals.** Process descent alone is too loose (postinstall is always a descendant of the Bash tool call). Argument matching alone is too tight (the user might paraphrase). And — crucially — collapsing "prompt" into one boolean hides prompt-injection, because tool-result content is technically a "user-role" message in Claude Code transcripts but is machine-generated. Splitting by origin lets a single attribution shape express both malicious-npm and prompt-injection detections by picking different corners of the cube. See [`scenario-prompt-injection.md`](./scenario-prompt-injection.md) for the walkthrough that motivated the split.

## 5. Per-event-type fields

### 5.1 `prompt` (source: transcript reader)

| Field | Type |
|---|---|
| `role` | `user` \| `assistant` \| `system` |
| `prompt_text` | string |
| `prompt_summary` | string (≤200 chars, first sentence) |
| `message_id` | string |

No `process` block — prompt events are read from the transcript file, not from a running process.

### 5.2 `tool_call` (source: transcript reader)

| Field | Type |
|---|---|
| `tool_call_id` | string |
| `tool_name` | string — `Bash`, `Read`, `Edit`, `WebFetch`, ... |
| `tool_input` | object — raw tool args (JSON) |
| `tool_input_summary` | string (≤200 chars) |
| `parent_message_id` | string |

### 5.3 `tool_result` (source: transcript reader, optionally joined with kernel events)

| Field | Type |
|---|---|
| `tool_call_id` | string |
| `result_status` | `success` \| `error` |
| `result_summary` | string (≤200 chars) |
| `child_pids` | array of int — kernel-side PIDs observed during the tool call window |

### 5.4 `process_exec` (source: eBPF `execve` / ETW Kernel-Process)

| Field | Type |
|---|---|
| (process block) | see §3 |
| `exec_args` | array of strings — argv |
| `exec_envp_summary` | string — selected env vars only (`PATH`, `HOME`, `NODE_OPTIONS`, ...) |

### 5.5 `credential_access` (source: eBPF `openat2` / ETW Kernel-File + SACL)

| Field | Type |
|---|---|
| (process block) | see §3 |
| `file_path` | string |
| `access_type` | `read` \| `write` \| `open` |
| `credential_class` | enum — see §6 |
| `bytes_read` | int\|null |

### 5.6 `network_egress` (source: eBPF `connect` / ETW Kernel-Network)

| Field | Type |
|---|---|
| (process block) | see §3 |
| `dest_ip` | string |
| `dest_port` | int |
| `dest_host` | string\|null — DNS or TLS SNI if observed |
| `protocol` | `tcp` \| `udp` |
| `tls_sni` | string\|null |

### 5.7 `file_write` (source: eBPF `openat2`+`write` / ETW Kernel-File)

For tracking exfil staging and modification of agent config (skills/, agents/, settings.json).

| Field | Type |
|---|---|
| (process block) | see §3 |
| `file_path` | string |
| `bytes_written` | int |
| `is_agent_config` | bool — file path matches an enrolled agent's config tree |

## 6. Credential classifier taxonomy (carried from v1, extended)

Both platforms emit the same `credential_class` enum:

| Class | Linux signal | Windows signal |
|---|---|---|
| `aws_credentials` | `~/.aws/credentials`, `~/.aws/config` | `%USERPROFILE%\.aws\credentials` |
| `azure_credentials` | `~/.azure/`, env `AZURE_*` | `%USERPROFILE%\.azure\`, Credential Manager `MicrosoftAzure*` entries |
| `gcp_credentials` | `~/.config/gcloud/`, `GOOGLE_APPLICATION_CREDENTIALS` | `%APPDATA%\gcloud\` |
| `ssh_private_key` | `~/.ssh/id_*` (not `*.pub`) | `%USERPROFILE%\.ssh\id_*` |
| `git_credentials` | `~/.git-credentials`, `~/.config/git/credentials` | Git Credential Helper, `%USERPROFILE%\.git-credentials` |
| `dpapi_blob` | n/a | `%APPDATA%\Microsoft\Protect\<SID>\*`, DPAPI master key access |
| `credential_manager` | n/a | `vaultcli.dll` calls, `%LOCALAPPDATA%\Microsoft\Vault\` |
| `browser_cookies` | `~/.config/{google-chrome,chromium,BraveSoftware,Firefox}/.../Cookies` | `%LOCALAPPDATA%\Google\Chrome\User Data\*\Cookies`, Edge equivalents |
| `kube_config` | `~/.kube/config` | `%USERPROFILE%\.kube\config` |
| `generic_dotenv` | `**/.env`, `**/.env.*` | `**\.env`, `**\.env.*` |
| `none` | — | — (default for non-credential file accesses, suppressed at collector) |

Classifier runs at the collector, not at query time. The detection should never need a regex over `file_path`.

## 7. Worked example — malicious-npm scenario, Linux

User prompts Claude Code to install a package. The package's `postinstall` script reads AWS credentials and beacons out. Events in chronological order (abridged JSON, irrelevant envelope fields elided for readability):

**1. Prompt event** (from transcript reader, no PID)
```json
{
  "event_id": "01913e8b-...-a01",
  "event_type": "prompt",
  "timestamp": "2026-05-27T18:42:11.103Z",
  "platform": "linux",
  "session_id": "9f3c2-...-7bd",
  "user_id": "anton",
  "agent_id": "claude-code",
  "role": "user",
  "prompt_text": "install lodash-utils-extra please",
  "prompt_summary": "install lodash-utils-extra please",
  "message_id": "msg_01..."
}
```

**2. Tool call** (from transcript reader)
```json
{
  "event_id": "01913e8b-...-a02",
  "event_type": "tool_call",
  "timestamp": "2026-05-27T18:42:11.840Z",
  "session_id": "9f3c2-...-7bd",
  "tool_call_id": "toolu_01ABC",
  "tool_name": "Bash",
  "tool_input": { "command": "npm install lodash-utils-extra" },
  "tool_input_summary": "npm install lodash-utils-extra",
  "parent_message_id": "msg_02..."
}
```

**3. process_exec — npm spawns** (eBPF execve)
```json
{
  "event_id": "01913e8b-...-a03",
  "event_type": "process_exec",
  "timestamp": "2026-05-27T18:42:11.901Z",
  "platform": "linux",
  "session_id": "9f3c2-...-7bd",
  "process": {
    "pid": 84211, "ppid": 84102, "name": "npm",
    "path": "/usr/bin/npm",
    "cmdline": "npm install lodash-utils-extra",
    "parent_chain": ["systemd","claude","bash","npm"],
    "agent_root_pid": 31002, "user": "anton"
  },
  "exec_args": ["npm","install","lodash-utils-extra"],
  "attribution": {
    "attributed_tool_call_id": "toolu_01ABC",
    "attributed_by_descent": true,
    "requested_by_tool_call": true,
    "requested_in_user_message": true,
    "requested_in_assistant_message": true,
    "requested_in_tool_result": false,
    "time_window_ms": 61
  }
}
```

**4. process_exec — postinstall node script** (eBPF execve)
```json
{
  "event_id": "01913e8b-...-a04",
  "event_type": "process_exec",
  "timestamp": "2026-05-27T18:42:12.402Z",
  "process": {
    "pid": 84233, "ppid": 84211, "name": "node",
    "path": "/usr/bin/node",
    "cmdline": "node /home/anton/proj/node_modules/lodash-utils-extra/postinstall.js",
    "parent_chain": ["systemd","claude","bash","npm","node"],
    "agent_root_pid": 31002, "user": "anton"
  },
  "attribution": {
    "attributed_tool_call_id": "toolu_01ABC",
    "attributed_by_descent": true,
    "requested_by_tool_call": false,
    "requested_in_user_message": false,
    "requested_in_assistant_message": false,
    "requested_in_tool_result": false,
    "time_window_ms": 562
  }
}
```

Note: descent is true, but `postinstall.js` is a path neither the tool call nor any prompt mentioned. The next event is the smoking gun.

**5. credential_access — postinstall reads AWS creds** (eBPF openat2 + classifier)
```json
{
  "event_id": "01913e8b-...-a05",
  "event_type": "credential_access",
  "timestamp": "2026-05-27T18:42:12.481Z",
  "process": {
    "pid": 84233, "ppid": 84211, "name": "node",
    "path": "/usr/bin/node",
    "cmdline": "node .../postinstall.js",
    "parent_chain": ["systemd","claude","bash","npm","node"],
    "agent_root_pid": 31002
  },
  "file_path": "/home/anton/.aws/credentials",
  "access_type": "read",
  "credential_class": "aws_credentials",
  "bytes_read": 312,
  "attribution": {
    "attributed_tool_call_id": "toolu_01ABC",
    "attributed_by_descent": true,
    "requested_by_tool_call": false,
    "requested_in_user_message": false,
    "requested_in_assistant_message": false,
    "requested_in_tool_result": false,
    "time_window_ms": 641
  }
}
```

**6. network_egress — beacon to attacker** (eBPF connect)
```json
{
  "event_id": "01913e8b-...-a06",
  "event_type": "network_egress",
  "timestamp": "2026-05-27T18:42:12.503Z",
  "process": {
    "pid": 84233, "name": "node",
    "parent_chain": ["systemd","claude","bash","npm","node"],
    "agent_root_pid": 31002
  },
  "dest_ip": "203.0.113.42",
  "dest_port": 443,
  "dest_host": "telemetry.lodash-utils.dev",
  "protocol": "tcp",
  "tls_sni": "telemetry.lodash-utils.dev",
  "attribution": {
    "attributed_tool_call_id": "toolu_01ABC",
    "attributed_by_descent": true,
    "requested_by_tool_call": false,
    "requested_in_user_message": false,
    "requested_in_assistant_message": false,
    "requested_in_tool_result": false,
    "time_window_ms": 663
  }
}
```

## 8. Worked example — same scenario, Windows

Same events, ETW-sourced. Field names identical. Only the platform-specific values change.

**1. Prompt** — identical except `platform: "windows"` and transcript path differs at the source.

**2. Tool call** — identical, transcript-sourced.

**3. process_exec — npm.cmd spawns** (ETW Kernel-Process)
```json
{
  "event_id": "01913e8c-...-b03",
  "event_type": "process_exec",
  "timestamp": "2026-05-27T18:42:11.901Z",
  "platform": "windows",
  "session_id": "9f3c2-...-7bd",
  "process": {
    "pid": 9120, "ppid": 8204, "name": "npm.cmd",
    "path": "C:\\Program Files\\nodejs\\npm.cmd",
    "cmdline": "npm install lodash-utils-extra",
    "parent_chain": ["services.exe","claude.exe","cmd.exe","npm.cmd"],
    "agent_root_pid": 6840,
    "user": "DESKTOP-ABC\\anton",
    "integrity_level": "medium"
  },
  "attribution": {
    "attributed_tool_call_id": "toolu_01ABC",
    "attributed_by_descent": true,
    "requested_by_tool_call": true,
    "requested_in_user_message": true,
    "requested_in_assistant_message": true,
    "requested_in_tool_result": false,
    "time_window_ms": 61
  },
  "source": {
    "collector": "etw",
    "probe": "Microsoft-Windows-Kernel-Process",
    "host_pid": 9120
  }
}
```

**4. process_exec — postinstall node.exe** (ETW Kernel-Process)
```json
{
  "event_id": "01913e8c-...-b04",
  "event_type": "process_exec",
  "process": {
    "pid": 9151, "ppid": 9120, "name": "node.exe",
    "path": "C:\\Program Files\\nodejs\\node.exe",
    "cmdline": "node.exe C:\\Users\\anton\\proj\\node_modules\\lodash-utils-extra\\postinstall.js",
    "parent_chain": ["services.exe","claude.exe","cmd.exe","npm.cmd","node.exe"],
    "agent_root_pid": 6840,
    "integrity_level": "medium"
  },
  "attribution": {
    "attributed_tool_call_id": "toolu_01ABC",
    "attributed_by_descent": true,
    "requested_by_tool_call": false,
    "requested_in_user_message": false,
    "requested_in_assistant_message": false,
    "requested_in_tool_result": false,
    "time_window_ms": 562
  }
}
```

**5. credential_access — postinstall reads AWS creds** (ETW Kernel-File + SACL)
```json
{
  "event_id": "01913e8c-...-b05",
  "event_type": "credential_access",
  "process": {
    "pid": 9151, "name": "node.exe",
    "parent_chain": ["services.exe","claude.exe","cmd.exe","npm.cmd","node.exe"],
    "agent_root_pid": 6840
  },
  "file_path": "C:\\Users\\anton\\.aws\\credentials",
  "access_type": "read",
  "credential_class": "aws_credentials",
  "bytes_read": 312,
  "attribution": {
    "attributed_tool_call_id": "toolu_01ABC",
    "attributed_by_descent": true,
    "requested_by_tool_call": false,
    "requested_in_user_message": false,
    "requested_in_assistant_message": false,
    "requested_in_tool_result": false,
    "time_window_ms": 641
  },
  "source": {
    "collector": "etw",
    "probe": "Microsoft-Windows-Kernel-File",
    "host_pid": 9151
  }
}
```

Windows-specific bonus: a second credential_access can fire as `dpapi_blob` if the postinstall tries to decrypt browser cookies, with no extra detection-side code.

**6. network_egress — beacon** (ETW Kernel-Network)
```json
{
  "event_id": "01913e8c-...-b06",
  "event_type": "network_egress",
  "process": {
    "pid": 9151, "name": "node.exe",
    "parent_chain": ["services.exe","claude.exe","cmd.exe","npm.cmd","node.exe"],
    "agent_root_pid": 6840
  },
  "dest_ip": "203.0.113.42",
  "dest_port": 443,
  "dest_host": "telemetry.lodash-utils.dev",
  "protocol": "tcp",
  "tls_sni": "telemetry.lodash-utils.dev",
  "attribution": {
    "attributed_tool_call_id": "toolu_01ABC",
    "attributed_by_descent": true,
    "requested_by_tool_call": false,
    "requested_in_user_message": false,
    "requested_in_assistant_message": false,
    "requested_in_tool_result": false,
    "time_window_ms": 663
  }
}
```

## 9. Detections

### 9.1 Malicious-descendant credential read (the §1 killer query)

Run against the malicious-npm events:

- Event 5 (Linux) matches: `event_type=credential_access`, `attributed_tool_call_id=toolu_01ABC` (not null), all four `requested_*` are false.
- Event 5 (Windows) matches identically.
- Events 3 (npm spawn) and 4 (node postinstall spawn) are `process_exec`, filtered out by `event_type`.
- Event 6 (beacon) is `network_egress`, filtered out. Worth writing as a sibling — same WHERE clause, swap the event_type and `dest_host` for `file_path`.
- Verdict per session: one credential class read (`aws_credentials`), one offender (`node` / `node.exe`), the user's prompt was *"install lodash-utils-extra please"*.

**Negative case** — a legitimate "read AWS creds" tool call:

- Prompt: *"check my AWS profile"*
- Tool call: `Bash` with `tool_input.command = "cat ~/.aws/credentials"`
- credential_access event: `requested_by_tool_call=true` AND `requested_in_user_message=true`. Detection skips.

### 9.2 Prompt-injection credential read (sibling rule)

```spl
index=fishbowl event_type=credential_access
| where requested_by_tool_call=true
        AND requested_in_user_message=false
        AND requested_in_tool_result=true
| stats values(file_path) as creds,
        values(prompt_summary) as user_asked_for,
        values(tool_call_id) as fooled_tool_call
        by session_id, user_id, host_id
```

Plain English: *a tool call read credentials because an upstream tool result told the agent to — and the user never asked.* Walked through in `scenario-prompt-injection.md`.

### 9.3 Attribution-cube map

| Attack class                            | descent | tool args | user msg | asst msg | tool result |
|----------------------------------------|--------|-----------|----------|----------|-------------|
| Malicious-descendant (npm postinstall)  | T      | F         | F        | F        | F           |
| Prompt injection (fetched content)      | T      | T         | F        | T        | T           |
| Legitimate agent action                 | T      | T         | T        | T        | F           |
| Model-invented credential read          | T      | T         | F        | T        | F           |

Detection authors pick the corner.

## 10. Open questions / TODO

- **Identifier extraction from URL paths and query strings.** For `network_egress`, the primary identifier needs to include URL path + query, not just `dest_host`, or the prompt-injection exfil case won't match (`research.attacker.com/verify?token=AKIA...` — the host was in the user message, but the token wasn't). Surface during collector spec.
- **Identifier matching across encodings.** Attacker base64-encodes the path or splits it across multiple injections — exact substring matching loses. Out of scope for v0.x. The post should call this out as a known, honest limitation.
- **Multiple concurrent agent CLIs.** Anton might run Claude Code and Cursor in two terminals. `session_id` is per-agent-transcript so they're distinct, but the collector needs an enrollment table mapping `agent_root_pid → (agent_id, session_id, transcript_path)`. Spec separately.
- **Long-running tool calls vs. detached postinstall.** If a tool call ends and a descendant lingers, does the descendant keep `attributed_tool_call_id` or graduate to `null`? Current proposal: keep it; the join is "was this process spawned during a tool call," not "is the tool call still active."
- **Argument-match fuzziness.** Exact substring is the v1 rule. Need to handle `~` expansion, env-var substitution, absolute-vs-relative paths. Verify with `npm i lodash-utils-extra` (short form) that `requested_by_tool_call` still resolves correctly.
- **PID reuse.** `process.start_time` is the disambiguator; queries should match on `(pid, start_time)` not `pid` alone.
- **Schema versioning.** Bump `schema_version` on field semantic changes. Additive-only within `0.x`; first incompat bump goes to `1.0`. `0.1 → 0.2` for the prompt-origin split was strictly additive at the wire level (renamed/added fields, no removals from anything shipped) but is documented as a breaking change against the draft.

## 11. Resolved (from earlier drafts)

- ~~Validate the schema with a second, structurally different scenario.~~ Done: `scenario-prompt-injection.md`. Surfaced the `requested_in_prompt` collapse-of-origin bug; fixed in v0.2.
