# ATEN event schema

Schema version **0.8**. Every ATEN event is a single JSON object on one line.
The fields are **flat**: the shared envelope, the `event_type` discriminator,
and that type's payload all live at the top level of the object — there is no
nested `payload` wrapper. Field names are identical across Linux, Windows, and
macOS wherever the platform exposes the underlying signal.

This is the field-level reference. For the concepts (intent vs. action,
enrollment, attribution) and detection walkthroughs, see
[`README.md`](./README.md); for tuned detection rules, see
[`DETECTIONS.md`](./DETECTIONS.md).

- [Envelope](#envelope) — on every event
- [Process block](#process-block) — on every action event
- [Attribution block](#attribution-block) — on every action event
- [Event types](#event-types) — one section each, with a log example
- [Enum reference](#enum-reference) — every typed field's allowed values

---

## Envelope

Present on **every** event, regardless of type.

| field | type | notes |
|---|---|---|
| `schema_version` | string | `"0.8"` for this revision. |
| `event_id` | string | UUID, unique per event. |
| `timestamp` | string | RFC 3339, nanosecond precision, UTC (`…Z`). |
| `monotonic_ns` | int \| null | Boot-clock nanoseconds when the kernel observed the event; null for transcript-sourced events. |
| `platform` | enum | `linux` \| `windows` \| `macos`. |
| `host_id` | string \| null | Stable host identifier (MachineGuid on Windows, machine-id on Linux). |
| `agent_id` | string | `agent-root` for the enrolled agent process itself, `agent-descendant` for a process below it, or the parsed agent id for transcript events (`claude-code`, `codex`). |
| `session_id` | string \| null | The agent session this event belongs to. Null when a kernel event could not be bound to a session. |
| `user_id` | string \| null | OS user (`DOMAIN\user` on Windows, username on Linux). |
| `source` | object | Debug provenance — never read by detection logic. `{ collector, probe, host_pid? }`. `collector` is e.g. `windows_etw`, `linux_ebpf`, `transcript`; `probe` names the specific producer. |
| `event_type` | enum | Discriminator. One of the [event types](#event-types) below. |

---

## Process block

Present on every **action** event (`process_exec`, `process_exit`,
`credential_access`, `file_write`, `network_egress`, `dns_query`,
`local_ipc_access`). Serialized under the `process` key.

| field | type | notes |
|---|---|---|
| `pid` | int | |
| `ppid` | int | |
| `start_time` | string | Process start time. |
| `name` | string | Executable basename. |
| `path` | string | Full executable path. |
| `cmdline` | string | Full command line. |
| `cwd` | string | Working directory. |
| `user` | string | Owning OS user. |
| `integrity_level` | string \| null | Windows integrity level; null elsewhere. |
| `parent_chain` | array | Ancestors, shallowest → immediate parent, each `{ pid, name }`, excluding the event's own process. Walked up to a depth cap (16). |
| `agent_root_pid` | int \| null | PID of the enrolled agent at the top of this process's tree. The join key that ties a whole tree to one agent. |

---

## Attribution block

Present on every **action** event, under the `attribution` key. This is what
links a kernel observation back to session intent. The four `requested_*`
booleans describe **where the action's primary identifier** (its file path,
host/query name, or command) **first surfaced in the session** — combine them to
carve out attack classes.

| field | type | question it answers |
|---|---|---|
| `attributed_tool_call_id` | string \| null | Which tool call did this process descend from? Null if none, or if the nearest match is too old to trust. |
| `attributed_by_descent` | bool | Did it run under the enrolled agent, within an active tool call's window? |
| `requested_by_tool_call` | bool | Did that tool call's input name this identifier? |
| `requested_in_user_message` | bool | Did the user type this identifier this session? |
| `requested_in_assistant_message` | bool | Did the model produce it in its own output? |
| `requested_in_tool_result` | bool | Did it appear in an earlier tool result? **This is the prompt-injection signal** — the identifier came from fetched content, not the user. |
| `time_window_ms` | int \| null | Milliseconds between the attributed tool call and this event. |
| `triggering_command` | string \| null | Human-readable command from the tool call. Null when `attributed_tool_call_id` is null. |
| `triggering_prompt` | string \| null | Most recent user prompt before this event, copied onto the row so no SIEM-side join is needed. Populated whenever any prior user prompt exists — it does not depend on tool-call timing. |

> **Timing note.** Kernel events can arrive before the agent has finished
> writing the matching tool call to disk, so ATEN holds each action event ~2 s
> before attributing it. If the nearest tool call is still more than 10 s away,
> `attributed_tool_call_id` and `triggering_command` are left null rather than
> guessed. The `requested_*` fields and `triggering_prompt` do not depend on
> that timing.

---

## Event types

Two sources: **transcript** events describe intent and have no process/attribution
block; **kernel** events describe actions and always carry both. One event —
`collector_status` — is daemon self-telemetry and carries neither.

### `prompt` — transcript

A user, assistant, or system message.

| field | type | notes |
|---|---|---|
| `role` | enum | `user` \| `assistant` \| `system`. |
| `prompt_text` | string | Full message text. |
| `prompt_summary` | string | Truncated summary. |
| `message_id` | string \| null | Source message id when present. |

```json
{"schema_version":"0.8","event_id":"d6e2…","timestamp":"2026-07-27T12:45:11.093Z",
 "platform":"windows","host_id":"c16b…","agent_id":"claude-code",
 "session_id":"b668e671-…","user_id":"DESKTOP-PBTTA20\\aovru",
 "source":{"collector":"transcript","probe":"claude-code-jsonl"},
 "event_type":"prompt","role":"user",
 "prompt_text":"check the repo in this folder and run the tests",
 "prompt_summary":"check the repo in this folder and run the tests"}
```

### `tool_call` — transcript

The agent invoking a tool.

| field | type | notes |
|---|---|---|
| `tool_call_id` | string | Correlates to the `attributed_tool_call_id` on action events. |
| `tool_name` | string | `Bash`, `Read`, `WebFetch`, `PowerShell`, … |
| `tool_input` | object | Raw input the agent passed, verbatim. |
| `tool_input_summary` | string | Truncated summary. |
| `parent_message_id` | string \| null | Assistant message that issued the call. |

```json
{"…envelope…","event_type":"tool_call","tool_call_id":"toolu_013Ea56SBXU1d7yX",
 "tool_name":"PowerShell","tool_input":{"command":"npm test","description":"Run the test script"},
 "tool_input_summary":"{\"command\":\"npm test\",…}"}
```

### `tool_result` — transcript

The result returned to the agent. Its `result_text` is scanned for identifiers
(paths, hosts, IPs); an identifier that first appears here is what sets
`requested_in_tool_result` on a later action.

| field | type | notes |
|---|---|---|
| `tool_call_id` | string | The call this result answers. |
| `result_status` | enum | `success` \| `error`. |
| `result_summary` | string | Truncated summary. |
| `result_text` | string | Full result text. |
| `child_pids` | array\<int> | Reserved; current parsers leave it empty — action-to-tool attribution comes from process ancestry + timing. |

### `agent_session` — transcript

Session posture, emitted at session start, when a permission mode first becomes
observable, and when the mode changes mid-session.

| field | type | notes |
|---|---|---|
| `agent_kind` | enum | `claude_code` \| `codex_cli`. |
| `cwd` | string \| null | Session working directory. |
| `model` | string \| null | Model in use when exposed. |
| `permission_mode` | string \| null | Permission posture when the transcript exposes it. |
| `transcript_path` | string \| null | Path of the source transcript. |

### `permission_decision` — transcript

An explicit allow/deny/prompt decision when the transcript records one.

| field | type | notes |
|---|---|---|
| `decision` | enum | `allowed` \| `denied` \| `prompted` \| `unknown`. |
| `target` | string \| null | What the decision was about. |
| `tool_name` | string \| null | |
| `tool_call_id` | string \| null | |
| `reason` | string \| null | |

### `process_exec` — kernel

A process started under the enrolled agent. Adds a typed
`supply_chain_activity` tag when the command looks like package-manager /
install / script / git / network-installer / container-build / build-tool
activity (the classifier resolves interpreter wrappers such as
`node …/npm-cli.js install` and `python -m pip install`).

| field | type | notes |
|---|---|---|
| `process` | object | [Process block](#process-block). |
| `attribution` | object | [Attribution block](#attribution-block). |
| `exec_args` | array\<string> | argv. |
| `exec_envp_summary` | string | Summary of the exec environment (not the full environment — see [limits](#coverage-limits)). |
| `supply_chain_activity` | enum \| null | See [`supply_chain_activity`](#supply_chain_activity). Null when the command matches nothing. |

```json
{"…envelope…","event_type":"process_exec",
 "process":{"pid":32428,"ppid":37228,"name":"node",
   "cmdline":"\"C:\\Program Files\\nodejs\\node.exe\" \"…/npm-cli.js\" test",
   "parent_chain":[{"pid":15864,"name":"explorer.exe"},{"pid":38800,"name":"claude.exe"},
                   {"pid":37228,"name":"powershell.exe"}],
   "agent_root_pid":38800},
 "attribution":{"attributed_tool_call_id":"toolu_013Ea56SBXU1d7yX","attributed_by_descent":true,
   "requested_by_tool_call":false,"requested_in_user_message":false,
   "requested_in_assistant_message":false,"requested_in_tool_result":false,
   "time_window_ms":4063,"triggering_command":"npm test",
   "triggering_prompt":"check the repo in this folder and run the tests"},
 "exec_args":["node","…/npm-cli.js","test"],"exec_envp_summary":"",
 "supply_chain_activity":"package_manager"}
```

### `process_exit` — kernel

A tracked process exited. Emitted on macOS today; on Linux/Windows tracked-process
cleanup currently happens without a public event.

| field | type | notes |
|---|---|---|
| `process` | object | |
| `attribution` | object | |
| `exit_code` | int | |

### `credential_access` — kernel

A credential or credential-adjacent state file was read, written, or opened.
The collector classifies the path into a typed `credential_class` so rules never
match paths by hand. Reads of ordinary files are not emitted. A write **to a
credential path** is reported here with `access_type = write`, not as a
`file_write`.

| field | type | notes |
|---|---|---|
| `process` | object | |
| `attribution` | object | |
| `file_path` | string | The accessed path. |
| `access_type` | enum | `read` \| `write` \| `open`. |
| `credential_class` | enum | See [`credential_class`](#credential_class). |
| `bytes_read` | int \| null | When the probe observes the read itself. |

```json
{"…envelope…","event_type":"credential_access",
 "session_id":"22981f65-…","platform":"linux",
 "process":{"name":"node","cmdline":"node …/internal-build-helper/postinstall.js",
   "parent_chain":[{"pid":102350,"name":"aten-agent"},{"pid":102455,"name":"node"}],
   "agent_root_pid":102455},
 "file_path":"/home/anton/.aws/credentials","access_type":"read",
 "credential_class":"aws_credentials","bytes_read":312,
 "attribution":{"attributed_tool_call_id":"toolu_01Hx…","attributed_by_descent":true,
   "requested_by_tool_call":false,"requested_in_user_message":false,
   "requested_in_assistant_message":false,"requested_in_tool_result":false,
   "triggering_prompt":"Install the internal build helper for this repo and run the build."}}
```

### `file_write` — kernel

A sensitive file was written, classified by `write_class`. Ordinary writes are
not emitted. (Credential-path writes go to `credential_access` instead.)

| field | type | notes |
|---|---|---|
| `process` | object | |
| `attribution` | object | |
| `file_path` | string | |
| `bytes_written` | int \| null | When the write itself is observed. |
| `write_class` | enum | See [`write_class`](#write_class). |

```json
{"…envelope…","event_type":"file_write",
 "file_path":"/home/anton/.claude/settings.json","write_class":"agent_config",
 "bytes_written":1840,
 "process":{"name":"node","agent_root_pid":31002},
 "attribution":{"attributed_by_descent":true,"requested_by_tool_call":true,
   "requested_in_user_message":false,"requested_in_tool_result":true,
   "triggering_prompt":"summarize https://docs.example.com/setup"}}
```

### `network_egress` — kernel

An outbound connection. Adds a `cloud_metadata` tag for known instance/task
metadata endpoints.

| field | type | notes |
|---|---|---|
| `process` | object | |
| `attribution` | object | |
| `dest_ip` | string | |
| `dest_port` | int | |
| `dest_host` | string \| null | Generally null today — hostname enrichment is backlog. |
| `protocol` | enum | `tcp` \| `udp`. |
| `tls_sni` | string \| null | Generally null today. |
| `cloud_metadata` | enum \| null | See [`cloud_metadata`](#cloud_metadata). |

> Loopback (`127.0.0.1`) destinations are generally not surfaced as
> `network_egress` — see [limits](#coverage-limits).

### `dns_query` — kernel

A name resolution. `query_name` is the attribution identifier — a lookup that
traces back to a `requested_in_tool_result` origin is the DNS-exfil fingerprint.

| field | type | notes |
|---|---|---|
| `process` | object | |
| `attribution` | object | |
| `query_name` | string | Lowercased, trailing dot stripped. |
| `query_type` | enum | See [`query_type`](#query_type). |
| `answers` | array\<string> | Resolved answers when observed; lets a SIEM join a later `network_egress` `dest_ip` back to the name. Empty when only the outgoing query was seen. |

```json
{"…envelope…","event_type":"dns_query","platform":"windows",
 "query_name":"txt-aten-demo-00990621-…-b08b21c3fd75.atendemo.test","query_type":"txt",
 "process":{"name":"powershell.exe","agent_root_pid":22036},
 "attribution":{"attributed_by_descent":true,"requested_in_user_message":false,
   "triggering_prompt":"Run the diagnostics script from this repo and summarize the result."}}
```

### `local_ipc_access` — kernel

An enrolled process connected to a sensitive local broker socket/pipe.

| field | type | notes |
|---|---|---|
| `process` | object | |
| `attribution` | object | |
| `ipc_path` | string | Socket/pipe path. |
| `ipc_class` | enum | See [`ipc_class`](#ipc_class). |

### `collector_status` — daemon self-telemetry

Emitted whenever a drop counter advances, so a telemetry gap becomes a record
you can alert on instead of silent loss. Carries no `process`/`attribution` —
the envelope's `source` names which stage dropped (`pending_queue`, `ringbuf`,
`producer_queue`).

| field | type | notes |
|---|---|---|
| `dropped_total` | int | Cumulative drops from this source since start. |
| `dropped_since_last` | int | New drops since the previous `collector_status` from the same source — alert on rate, not just total. |
| `reason` | string | What was dropped and why. |

---

## Enum reference

### `credential_class`
`aws_credentials` · `azure_credentials` · `gcp_credentials` · `ssh_private_key` ·
`ssh_authorized_keys` · `git_credentials` · `netrc` · `npm_token` ·
`pypi_credentials` · `docker_config` · `github_cli_token` · `dpapi_blob` ·
`credential_manager` · `browser_cookies` · `kube_config` · `generic_dotenv` ·
`agent_state` · `none`

`agent_state` covers agent transcripts, histories, and profiles — the read side
of "collect the agent's own state to recover secrets."

### `write_class`
`agent_config` · `executable` · `shell_profile` · `scheduled_task` · `git_hook` ·
`startup_item` · `package_manifest` · `lockfile`

`agent_config` spans the control-plane surfaces of common agent ecosystems —
settings, hooks, skills, agents/subagents, MCP config, plugins, and rule /
instruction files — so agent self-modification across ecosystems keys on one
value.

### `supply_chain_activity`
`package_manager` · `package_install` · `package_script` · `git_operation` ·
`network_installer` · `container_build` · `build_tool`

### `ipc_class`
`docker_socket` · `container_runtime_socket` · `ssh_agent_socket` ·
`gpg_agent_socket` · `secret_manager_socket`

### `query_type`
`a` · `aaaa` · `cname` · `txt` · `mx` · `ns` · `ptr` · `srv` · `soa` · `other`.
`txt` is the high-signal DNS-tunnel carrier.

### `access_type`
`read` · `write` · `open`

### `cloud_metadata`
`instance_metadata` · `aws_task_credentials` · `alibaba_metadata`

### `platform`
`linux` · `windows` · `macos`

---

## Coverage limits

Honest edges, so rules aren't written against signals that aren't there:

- **Process environment variables** are not captured. `process_exec` carries
  argv (`exec_args`, `cmdline`) and an `exec_envp_summary`, but not the full
  environment — techniques that act purely through env vars are only partially
  visible.
- **Loopback egress** (`127.0.0.1`) is generally not surfaced as
  `network_egress`. A beacon to a local collector shows up in the collector's
  own log, not ATEN's egress stream; against a remote destination it appears
  normally.
- **File deletion** is not a distinct event. Writes and truncation to a path
  surface as `file_write` / `credential_access write`, but an `unlink` does not.
- **`dest_host` / `tls_sni`** on `network_egress` are generally null today;
  hostname/SNI enrichment is backlog. Pivot via `dns_query.answers` instead.
- **`process_exit`** is a macOS signal today; Linux/Windows clean up tracked
  processes without a public event.
- **Server-side surfaces** (an MCP server's tool metadata, a provider gateway's
  behavior) are not visible to an endpoint sensor. ATEN sees their **downstream
  effect** — the resulting action, tagged `requested_in_tool_result=true` when
  the instruction arrived through fetched content.
