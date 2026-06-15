"""
ATEN transcript reader — prototype.

Reads a Claude Code session transcript (`~/.claude/projects/<encoded-cwd>/<session-uuid>.jsonl`)
and emits schema.md v0.2 events: `prompt`, `tool_call`, `tool_result`. Also builds a per-session
identifier-origin index that the eBPF/ETW collectors will consult to populate the
`requested_in_user_message` / `_assistant_message` / `_tool_result` attribution booleans on
kernel-side events.

Cross-platform by design — Claude Code uses the same JSONL layout on Linux and Windows.

Usage:
    python reader.py <path-to-transcript.jsonl>
        Writes <stem>.events.jsonl and <stem>.idx.json beside the input.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

SCHEMA_VERSION = "0.2"
COLLECTOR_NAME = "transcript"
PROBE_NAME = "claude-code-jsonl"
AGENT_ID = "claude-code"

PATH_PATTERNS = [
    re.compile(r'[A-Za-z]:\\[^\s"\'<>|*?]+'),
    re.compile(r'[A-Za-z]:/[^\s"\'<>|*?]+'),
    re.compile(r'(?<![A-Za-z0-9_/])/[A-Za-z][\w./\-]+'),
    re.compile(r'~/[\w./\-]+'),
]
URL_PATTERN = re.compile(r'https?://[^\s"\'<>)\]]+')


def extract_identifiers(text: str) -> set[str]:
    found: set[str] = set()
    for pat in PATH_PATTERNS:
        found.update(pat.findall(text))
    found.update(URL_PATTERN.findall(text))
    return found


def normalize_identifier(ident: str, home: str | None = None) -> str:
    """Canonical form for cross-platform comparison: lowercase, forward slashes, ~ expanded."""
    if ident.startswith(("http://", "https://")):
        return ident.lower()
    if home is None:
        home = os.path.expanduser("~")
    expanded = ident
    if expanded.startswith("~/") or expanded.startswith("~\\"):
        expanded = home + expanded[1:]
    expanded = expanded.replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", expanded):
        expanded = expanded.lower()
    return expanded


def make_event_id() -> str:
    # TODO: UUIDv7 for time-ordered IDs once stdlib (3.14) or third-party.
    return str(uuid.uuid4())


def envelope(rec: dict, event_type: str, platform: str) -> dict:
    ts = rec.get("timestamp") or datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": make_event_id(),
        "event_type": event_type,
        "timestamp": ts,
        "monotonic_ns": None,
        "platform": platform,
        "host_id": None,
        "agent_id": AGENT_ID,
        "session_id": rec.get("sessionId"),
        "user_id": None,
        "source": {"collector": COLLECTOR_NAME, "probe": PROBE_NAME},
    }


def parse_record(rec: dict, platform: str) -> Iterator[dict]:
    rtype = rec.get("type")
    msg = rec.get("message") or {}

    if rtype == "user" and isinstance(msg.get("content"), str):
        text = msg["content"]
        e = envelope(rec, "prompt", platform)
        e.update({
            "role": "user",
            "prompt_text": text,
            "prompt_summary": text[:200],
            "message_id": rec.get("uuid"),
        })
        yield e
        return

    if rtype == "user" and isinstance(msg.get("content"), list):
        for block in msg["content"]:
            if block.get("type") != "tool_result":
                continue
            content = block.get("content")
            if isinstance(content, list):
                content_text = "\n".join(
                    b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"
                )
            elif isinstance(content, str):
                content_text = content
            else:
                content_text = ""
            e = envelope(rec, "tool_result", platform)
            e.update({
                "tool_call_id": block.get("tool_use_id"),
                "result_status": "error" if block.get("is_error") else "success",
                "result_summary": content_text[:200],
                "result_text": content_text,
                "child_pids": [],
            })
            yield e
        return

    if rtype == "assistant":
        content = msg.get("content") or []
        text_chunks: list[str] = []
        tool_uses: list[dict] = []
        for block in content:
            btype = block.get("type")
            if btype == "text":
                text_chunks.append(block.get("text", ""))
            elif btype == "thinking":
                text_chunks.append(block.get("thinking", ""))
            elif btype == "tool_use":
                tool_uses.append(block)

        combined = "\n".join(t for t in text_chunks if t)
        if combined.strip():
            e = envelope(rec, "prompt", platform)
            e.update({
                "role": "assistant",
                "prompt_text": combined,
                "prompt_summary": combined[:200],
                "message_id": rec.get("uuid"),
            })
            yield e

        for tu in tool_uses:
            tool_input = tu.get("input", {})
            e = envelope(rec, "tool_call", platform)
            e.update({
                "tool_call_id": tu.get("id"),
                "tool_name": tu.get("name"),
                "tool_input": tool_input,
                "tool_input_summary": json.dumps(tool_input, default=str)[:200],
                "parent_message_id": rec.get("uuid"),
            })
            yield e
        return


def origin_for(event: dict) -> str | None:
    if event["event_type"] == "prompt":
        return "user_message" if event.get("role") == "user" else "assistant_message"
    if event["event_type"] == "tool_result":
        return "tool_result"
    return None


def build_identifier_index(events: list[dict], home: str | None = None) -> dict:
    index: dict[str, dict] = {}
    for ev in events:
        origin = origin_for(ev)
        if origin is None:
            continue
        text = ev.get("prompt_text") if ev["event_type"] == "prompt" else ev.get("result_text", "")
        if not text:
            continue
        for ident in extract_identifiers(text):
            norm = normalize_identifier(ident, home=home)
            entry = index.setdefault(norm, {
                "raw_first_form": ident,
                "first_seen_ts": ev["timestamp"],
                "first_seen_origin": origin,
                "mentions": [],
                "origins": set(),
            })
            entry["mentions"].append({
                "ts": ev["timestamp"],
                "origin": origin,
                "event_id": ev["event_id"],
            })
            entry["origins"].add(origin)

    for entry in index.values():
        entry["origins"] = sorted(entry["origins"])
    return index


def detect_platform() -> str:
    return "windows" if os.name == "nt" else "linux"


def read_transcript(path: Path, platform: str | None = None) -> list[dict]:
    platform = platform or detect_platform()
    events: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"line {lineno}: bad json: {e}", file=sys.stderr)
                continue
            events.extend(parse_record(rec, platform))
    return events


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("transcript", type=Path)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--idx", type=Path, default=None)
    args = ap.parse_args(argv)

    transcript: Path = args.transcript
    if not transcript.exists():
        print(f"transcript not found: {transcript}", file=sys.stderr)
        return 2

    out_path = args.out or transcript.with_suffix(".events.jsonl")
    idx_path = args.idx or transcript.with_suffix(".idx.json")

    events = read_transcript(transcript)

    with out_path.open("w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, default=str) + "\n")

    index = build_identifier_index(events)
    with idx_path.open("w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, default=str)

    by_type: dict[str, int] = {}
    for ev in events:
        by_type[ev["event_type"]] = by_type.get(ev["event_type"], 0) + 1
    print(f"wrote {len(events)} events to {out_path}", file=sys.stderr)
    for t, n in sorted(by_type.items()):
        print(f"  {t}: {n}", file=sys.stderr)
    print(f"wrote {len(index)} identifiers to {idx_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
