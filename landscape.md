# Landscape — agent telemetry / correlation tools as of 2026-05-27

Research findings that informed the fishbowl-v2 direction. Keep this current; update when new entrants appear.

## Direct architectural prior art

### AgentSight — `eunomia-bpf/agentsight`

- **Paper:** arxiv 2508.02736 (Aug 2025), ACM workshop publication
- **Code:** 6k lines Rust/C daemon + 3k TS frontend, open source
- **What it does:** eBPF uprobes on `SSL_read`/`SSL_write` for prompt capture, kernel syscalls (`openat2`, `connect`, `execve`), correlation via three signals: process lineage, temporal proximity (100-500ms window), argument matching (filenames/URLs/cmds from LLM response matched against syscalls). Two-stage engine: real-time heuristic linking + secondary "observer" LLM for semantic analysis.
- **Platform:** Linux only. Evaluated on Claude Code on Ubuntu 22.04, kernel 6.14.
- **Invocation:** `agentsight exec -- claude` (wraps) or `agentsight record -c claude` (attach by name). **Not a daemon. Not transparent.** Per-session monitoring tied to explicit invocation.
- **Gaps it explicitly leaves open:**
  - Source attribution (which input poisoned the agent's reasoning)
  - Causal reasoning paths (why this action vs. alternatives)
  - Confidence in agent responsibility (agent autonomy vs. injected instructions)
  - Cross-agent blame in multi-agent scenarios

**Why fishbowl-v2 still has room:** AgentSight is research-shaped. Fishbowl-v2 takes the same architectural pattern and ships it as an always-on daemon, cross-platform, SIEM-shaped output, blue-team-deployable.

## Adjacent commercial offerings

### Sysdig — managed Falco rules

- **What it does:** Runtime syscall-level monitoring via Falco. Behavioral patterns: agent installation events, unauthorized access to agent config dirs, safety-flag bypass, suspicious file/process activity.
- **What it explicitly doesn't do:** Quote — *"We do not attempt to interpret what an agent intends to do, or to classify prompts as malicious."* No prompt-to-syscall correlation.
- **Platform:** Linux. Cloud + k8s + dev VMs.
- **Not in fishbowl's exact lane** — behavioral-only, no prompt-layer correlation.

### ARMO — CADR platform

- **What it does:** eBPF DaemonSet + application-layer reconstruction. Claims five fields for security-grade tool call records: entity identity, intent context, authorization context, baseline context, downstream linkage.
- **Platform:** Kubernetes only (EKS/AKS/GKE). 1-2.5% CPU overhead per node.
- **Not in fishbowl's lane** — k8s posture, not dev endpoint.

## AI artifact scanners (different category, deprioritized direction)

These are sandbox/scanner tools for AI artifacts — different category from correlation telemetry. Lane is crowded as of May 2026:

- **Permiso SandyClaw** (2026-04-02) — *"First Dynamic Sandbox for AI Agent Skills and Prompts"*
- **Snyk agent-scan** — AI agents + MCP servers + skills
- **Cisco mcp-scanner**
- **Invariant Labs mcp-scan**
- **Enkrypt AI MCP Scanner**
- **mcpscan.ai**
- **MCP Playground Scanner**
- **@hailbytes/mcp-security-scanner**
- **MCP-Scan** now on Thoughtworks Tech Radar

Anton rejected entering this lane on 2026-05-26. fishbowl-v2 is telemetry/correlation, not sandbox/scanner.

## Gateways / middleware (also crowded, also deprioritized)

- **Lasso Security MCP Gateway**
- **IBM ContextForge**
- **AgentGateway**
- **NVIDIA NeMo Guardrails**
- **Meta LlamaFirewall**
- **Protect AI LLM Guard**
- **Guardrails AI**
- **Galileo Agent Control**
- **Cisco MCP security launch** (RSA 2026)

Not fishbowl's lane.

## LLM observability vendors (different category — application-layer, not endpoint)

- Datadog LLM Observability
- Langfuse / Helicone / Arize Phoenix / W&B Weave / LangSmith / Braintrust

These instrument the SDK server-side. They see prompts and tool calls but not endpoint syscalls. Not joined to behavior. Different audience (ML eng, not blue team).

## Cloud audit logs

- AWS Bedrock CloudTrail
- Azure OpenAI audit logs
- Anthropic / OpenAI enterprise audit APIs

API-level only. No endpoint join.

## Network-layer prompt scanning

- Zscaler / Netskope / Palo Alto AI Security SSE modules

Network egress inspection, not endpoint behavioral correlation.

## Summary — where the gap is

| Layer            | Linux dev endpoint | Windows dev endpoint | k8s/cloud         |
|------------------|-------------------|---------------------|-------------------|
| Behavioral only  | Sysdig/Falco      | EDR (no AI context) | ARMO, Sysdig      |
| Prompt only      | LLM observability vendors | LLM observability vendors | LLM observability vendors |
| **Correlated**   | **AgentSight (research, opt-in)** | **NOBODY**          | **ARMO**          |

The Windows dev endpoint cell is empty. That's where fishbowl-v2 lives.
