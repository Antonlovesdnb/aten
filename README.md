# ATEN

**A**gent **T**elemetry & **E**vent **N**otation — an always-on, cross-platform telemetry daemon for AI agent activity. *Sysmon for AI agents.*

Captures **prompts + tool calls + endpoint syscalls** and joins them by session and process tree, so detections fire on the join — not on either layer alone. Linux (eBPF) and Windows (ETW), one unified event schema, SIEM-shaped output. On Windows, events can be written to a dedicated Sysmon-style Event Log channel (`ATEN/Operational`) for WEF/SIEM collection, JSONL, or both (`output.sink`).

## Status

Planning + prototype phase. No deployable build yet.

Design docs (direction/scope, the unified event schema + attribution model,
scenario walkthroughs, and the prior-art landscape) live as local working notes
in the repo root and aren't published.

- [`prototypes/transcript_reader/`](./prototypes/transcript_reader/) — Python prototype that reads Claude Code transcripts and emits schema-v0.2 events

## Relation to fishbowl v1

ATEN is the productized successor to fishbowl v1 ([Antonlovesdnb/fishbowl](https://github.com/Antonlovesdnb/fishbowl)) — the wrapper-style proof-of-concept with the original credential-auditing blog. v1 was a per-invocation wrapper; ATEN is the always-on daemon: cross-platform, blue-team-deployable.

## Prior art

The eBPF + TLS-intercept + correlation architecture is from [AgentSight](https://github.com/eunomia-bpf/agentsight) ([arxiv:2508.02736](https://arxiv.org/abs/2508.02736)). ATEN ships it as a daemon instead of a per-invocation wrapper, adds Windows ETW, and lands the SIEM-shaped output.
