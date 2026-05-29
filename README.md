# fishbowl-v2

Always-on, cross-platform telemetry daemon for AI agent activity. *Sysmon for AI agents.*

Captures **prompts + tool calls + endpoint syscalls** and joins them by session and process tree, so detections fire on the join — not on either layer alone. Linux (eBPF) and Windows (ETW), one unified event schema, SIEM-shaped output.

## Status

Planning + prototype phase. No deployable build yet.

Design docs (direction/scope, the unified event schema + attribution model,
scenario walkthroughs, and the prior-art landscape) live as local working notes
in the repo root and aren't published.

- [`prototypes/transcript_reader/`](./prototypes/transcript_reader/) — Python prototype that reads Claude Code transcripts and emits schema-v0.2 events

## Relation to v1

fishbowl v1 ([Antonlovesdnb/fishbowl](https://github.com/Antonlovesdnb/fishbowl)) is the wrapper-style proof-of-concept with the original credential-auditing blog. v2 is the productized successor: always-on daemon, cross-platform, blue-team-deployable.

## Prior art

The eBPF + TLS-intercept + correlation architecture is from [AgentSight](https://github.com/eunomia-bpf/agentsight) ([arxiv:2508.02736](https://arxiv.org/abs/2508.02736)). v2 ships it as a daemon instead of a per-invocation wrapper, adds Windows ETW, and lands the SIEM-shaped output.
