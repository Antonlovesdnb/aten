# ATEN detection rules

A starting catalog of detections over ATEN events. Each rule is a query plus the reasoning behind it, the events and platforms it needs, and the false positives to expect. They are starting points, not drop-in production rules — baseline them against a week of normal agent activity in your environment and tune the thresholds before alerting.

The queries are written as **backend-agnostic pseudocode**, not a specific query language — translate them to Splunk SPL, KQL, OpenSearch, etc. Read them as:

- `FROM <event_type>` — the events to scan (ATEN's `event_type`, over whatever index/table holds ATEN's JSONL).
- `WHERE` — predicates on event fields. `field = value`, `field in (a, b)`, `is set` / `is null`, `matches /regex/`.
- `GROUP BY` — fields to aggregate by.
- `HAVING` — a predicate on an aggregate (`count(*)`, `distinct(field)`).
- `SELECT` — the fields to surface in the alert.

Field names are flat JSON keys, except the nested `process.*` and `attribution.*` blocks (the `attribution.*` fields are written here without the prefix, as they appear in most rules).

## How to read these rules

Most rules are one `event_type` filtered by the **attribution block** — the five signals ATEN attaches to every action event saying where the action's primary identifier (its file path, host, query name, or command) first appeared in the session. See the README for the full model; the short version:

| field | true when |
|---|---|
| `attributed_by_descent` | the process descends from the enrolled agent and ran during a tool call |
| `requested_by_tool_call` | the identifier appears in the triggering tool call's input |
| `requested_in_user_message` | the user typed it this session |
| `requested_in_assistant_message` | the model produced it |
| `requested_in_tool_result` | it appeared in an earlier tool result (i.e. it came from fetched content) |

The recurring idea: an action is suspicious not because of *what* it is but because of *who asked for it*. "Read AWS credentials" is benign when the user asked and alarming when nobody did. The rules below select that distinction.

Each action event's primary identifier, for reference:

| event_type | identifier matched by `requested_*` | also useful |
|---|---|---|
| `credential_access` | `file_path` | `credential_class`, `access_type` |
| `file_write` | `file_path` | `write_class` |
| `network_egress` | `dest_host` / `dest_ip` | `dest_port`, `tls_sni` |
| `dns_query` | `query_name` | `query_type`, `answers` |
| `process_exec` | `cmdline` | `exec_args` |

Severity is a suggestion: **high** = page someone, **medium** = queue for triage, **low** = enrich/hunt.

---

## Credential access

### CRED-1 — Credential read nobody in the session asked for
**Severity: high.** A process under the agent read a credential file, and the path was never named by the user, the model, the triggering tool call, or any tool result. This is the malicious-dependency / malicious-skill case — code riding the agent's process tree that the conversation never mentioned. MITRE T1552 (Unsecured Credentials).

```
FROM credential_access
WHERE access_type in (read, open)
  AND attributed_tool_call_id        is set
  AND requested_by_tool_call         = false
  AND requested_in_user_message      = false
  AND requested_in_assistant_message = false
  AND requested_in_tool_result       = false
GROUP BY session_id, user_id, host_id
SELECT file_path, credential_class, process.cmdline, triggering_prompt
```

**False positives:** legitimate tooling the agent invokes that reads credentials as a side effect (e.g. `aws`, `gcloud`, `kubectl`, `git` over HTTPS, a cloud SDK) when the user's request didn't literally name the file. Baseline which `credential_class` values are normal for which `process.name` on your hosts and exclude those pairs. Adding `time_window_ms < 5000` requires the tool-call binding to be recent and cuts stale matches.

### CRED-2 — Prompt-injection credential read
**Severity: high.** The tool call *did* name the credential file, but the user never did and the path traces back to a tool result — i.e. fetched content told the agent to read it. The opposite attribution corner from CRED-1. MITRE T1552 + prompt injection.

```
FROM credential_access
WHERE access_type in (read, open)
  AND requested_by_tool_call    = true
  AND requested_in_user_message = false
  AND requested_in_tool_result  = true
GROUP BY session_id, user_id, host_id
SELECT file_path, triggering_command, triggering_prompt, tool_call_id
```

**False positives:** lower than CRED-1, because requiring the identifier to appear in a tool result is specific. The main one is a tool result that legitimately contains a credential path the user then approves reading — check whether `requested_in_user_message` flips true on a later event in the same session.

### CRED-3 — Credential file written or planted
**Severity: medium.** A write to a credential path — overwriting `~/.aws/credentials`, dropping a new `~/.ssh/authorized_keys`, etc. Credential *writes* surface as `credential_access` with `access_type=write` (not `file_write`). Often a precursor to lateral movement or backdoor key injection.

```
FROM credential_access
WHERE access_type = write
GROUP BY session_id, user_id, host_id
SELECT file_path, credential_class, process.cmdline,
       requested_in_user_message, triggering_prompt
```

**False positives:** `aws configure`, `gcloud auth login`, `ssh-keygen`, credential-helper refreshes — all legitimately write credential paths. This rule is best as medium/triage; add `requested_in_user_message = false` to focus on writes the user never requested.

---

## Exfiltration

### EXFIL-1 — Egress to a destination nobody asked for
**Severity: medium.** An agent descendant opened a connection to a host that no one in the session named. The network sibling of CRED-1. MITRE T1041 (Exfiltration Over C2).

```
FROM network_egress
WHERE attributed_by_descent          = true
  AND requested_by_tool_call         = false
  AND requested_in_user_message      = false
  AND requested_in_assistant_message = false
  AND requested_in_tool_result       = false
GROUP BY session_id, user_id, host_id
SELECT dest_host, dest_ip, dest_port, process.cmdline, triggering_prompt
```

**False positives:** high without tuning — package registries, telemetry endpoints, CDNs, and update checks all fire here. Maintain an allowlist of expected destinations (npm/PyPI/crates mirrors, your proxy, etc.) and exclude them. For a higher-signal variant, scope to `dest_port` outside 80/443, or to direct-to-IP connections (`dest_host is null`).

### EXFIL-2 — DNS TXT lookups to an unrequested domain
**Severity: medium.** DNS-tunnel exfil shows up as a burst of `txt` lookups (often long, encoded labels) to a domain the user never typed. `query_type=txt` is the classic carrier.

```
FROM dns_query
WHERE query_type              = txt
  AND attributed_by_descent   = true
  AND requested_in_user_message = false
GROUP BY session_id, user_id, host_id
HAVING count(*) > 20 OR distinct(query_name) > 20
SELECT query_name, triggering_prompt
```

**False positives:** some legitimate services use TXT for SPF/DKIM lookups and verification flows, but rarely in volume from an agent descendant. Tune the count threshold to your baseline. Note the Linux probe reports `query_type=other` for libc resolver calls, so this TXT rule is most effective on Windows; on Linux, hunt on high-volume / high-entropy `query_name` regardless of type.

### EXFIL-3 — Credential read followed by egress (same process)
**Severity: high.** The fishbowl v1 signature, expressed natively: the same process that read a credential file then made an outbound connection. ATEN is observe-only by design, so this credential→exfil correlation is a SIEM rule, not an in-daemon action — the events already share `session_id` and `process.agent_root_pid` to join on.

```
FROM credential_access, network_egress           # both event types in one pass
WHERE (event_type = credential_access AND access_type in (read, open))
   OR  event_type = network_egress
GROUP BY session_id, host_id, process.pid, process.agent_root_pid
HAVING any(event_type = credential_access) AND any(event_type = network_egress)
SELECT creds_read  = credential_class where event_type = credential_access,
       egress_to   = dest_host        where event_type = network_egress,
       window_secs = last(timestamp) - first(timestamp)
```

**False positives:** cloud CLIs legitimately read credentials and then call an API — that is read-then-egress by design. Combine with the attribution signal: add the destination's `requested_*` flags, or require the credential read to match CRED-1 (unrequested), to separate "read keys, called AWS" from "read keys, called somewhere nobody mentioned." Narrow `window_secs` to reduce coincidental pairings.

---

## Persistence and self-modification

### PERSIST-1 — Write to the agent's own config not requested by the user
**Severity: high.** A write into the agent's configuration surface — a new skill, an edited `settings.json`, a `.claude/`/`.codex/` file — changes the agent's *future* behavior. ATEN tags these `file_write` with `write_class=agent_config`. When the user didn't ask for it, treat it as planted persistence. MITRE TA0003.

```
FROM file_write
WHERE write_class                = agent_config
  AND requested_in_user_message  = false
GROUP BY session_id, user_id, host_id
SELECT file_path, process.cmdline, requested_in_tool_result, triggering_prompt
```

**False positives:** the agent legitimately edits its own config when the user asks it to ("add a skill that…"). The `requested_in_user_message = false` filter removes most of those. `requested_in_tool_result = true` is the strongest signal that the change came from injection rather than intent. Self-writes by the agent process itself are emitted, not dropped — add `process.pid != process.agent_root_pid` to focus on writes by *descendants*.

### PERSIST-2 — Executable or script dropped under the agent
**Severity: medium.** A script or binary written by an agent descendant — payload staging. ATEN tags these `file_write` with `write_class=executable`.

```
FROM file_write
WHERE write_class             = executable
  AND attributed_by_descent   = true
  AND requested_in_user_message = false
GROUP BY session_id, user_id, host_id
SELECT file_path, process.cmdline, triggering_prompt
```

**False positives:** build steps and codegen legitimately write scripts (`./configure`, generated `.py`/`.sh`, compiled binaries) when the user asked the agent to build or scaffold. Baseline expected write paths (project build dirs) and exclude them; alert on writes to autostart/`bin`/profile locations.

---

## Execution

### EXEC-1 — Agent descendant that did not come from a tool call
**Severity: low (hunt).** A process whose `agent_root_pid` is set — it descends from the agent — but with no `attributed_tool_call_id`, meaning it was not spawned inside any observed tool-call window. Detached helpers, a postinstall that outlived its tool call, or something the agent backgrounded. Mostly investigative.

```
FROM process_exec
WHERE process.agent_root_pid  is set
  AND attributed_tool_call_id is null
GROUP BY session_id, host_id, process.agent_root_pid
SELECT process.cmdline, process.name, process.path
```

**False positives:** common and benign — shells, language servers, and helper daemons the agent starts outside a tool call all land here. Use it to hunt, or narrow to specific `process.name` values (interpreters, `curl`/`wget`, `nc`, `powershell`) for a higher-signal variant.

### EXEC-2 — Network/transfer tool run unrequested
**Severity: medium.** A known transfer or shell tool (`curl`, `wget`, `nc`, `scp`, `powershell -enc`, …) executed under the agent without the user naming it — a download-cradle or exfil primitive.

```
FROM process_exec
WHERE attributed_by_descent     = true
  AND requested_in_user_message = false
  AND ( process.name in (curl, wget, nc, ncat, scp, socat)
        OR process.cmdline matches /powershell.*-enc/i )
GROUP BY session_id, user_id, host_id
SELECT process.cmdline, triggering_prompt
```

**False positives:** agents use `curl`/`wget` constantly for legitimate fetches the user implicitly authorized ("check this API"). Pair with EXFIL-1 on the resulting connection, or require the destination in the command line to be unrequested, rather than alerting on the tool alone.

---

## Collector health

### HEALTH-1 — Telemetry gap (dropped events)
**Severity: medium.** ATEN emits a `collector_status` event when its bounded attribution buffer overflows and it has to drop kernel events. This is a *self-report of missing data* — every gap is a window where a real detection could have been silenced, so it's worth alerting on directly rather than discovering after an incident.

```
FROM collector_status
GROUP BY host_id
SELECT max(pending_dropped) as total_dropped, sum(dropped_since_last) as dropped_in_window
HAVING total_dropped > 0
```

**False positives:** none in the detection sense — this is ATEN telling you it dropped data. A steady stream of these means a host is producing events faster than the daemon can attribute and write them; investigate load (an unusually busy agent, a fork storm) or relax the bound. Note this covers only the daemon's pending-queue drops surfaced into the stream; collector-internal drops (eBPF ringbuf saturation, the macOS producer queue) are still reported only to the daemon's stderr.

---

## Tuning notes

- **Baseline first.** Run ATEN in an environment for a week and look at what CRED-1 and EXFIL-1 surface *normally*. The legitimate `(process.name, credential_class)` and `(process.name, dest_host)` pairs become your allowlists.
- **Use `time_window_ms`.** When attribution confidence matters, add `time_window_ms < 5000` to require the tool-call binding to be recent. Bindings null out past 10s by design, but tightening further reduces stale matches.
- **Read intent off the row.** `triggering_prompt` and `triggering_command` are denormalized onto every action event so an analyst can see what the user asked and what the agent ran without a separate join. Put them in every alert's output.
- **Join on the right keys.** `session_id` scopes to one agent session; `process.agent_root_pid` scopes to one agent instance; `(process.pid, process.start_time)` identifies one process across PID reuse. Use `host_id` + `user_id` to group by operator.

## Platform coverage

Not every event type is emitted on every platform yet, so some rules are platform-scoped:

| rule | needs | Linux | Windows | macOS |
|---|---|:--:|:--:|:--:|
| CRED-1/2/3 | `credential_access` | yes | yes | yes |
| EXFIL-1 | `network_egress` | yes | yes | yes |
| EXFIL-2 | `dns_query` | yes | yes | — |
| EXFIL-3 | both above | yes | yes | partial |
| PERSIST-1/2 | `file_write` | yes | yes | — |
| EXEC-1/2 | `process_exec` | yes | yes | yes |

macOS does not yet emit `dns_query` or `file_write`, so EXFIL-2 and the PERSIST rules don't apply there until those collectors land.
