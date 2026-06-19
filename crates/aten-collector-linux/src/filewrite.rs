//! File-write classifier — maps a written path to the schema's
//! `FileWriteClass`, or `None` for writes that aren't worth emitting. Like the
//! `credentials` classifier, this runs at the collector so detections never
//! regex over `file_path`, and it's the single cross-platform source of truth:
//! both the Linux eBPF probe and the Windows ETW probe call into it.
//!
//! The emitted scope is "sensitive + executable drops" (see schema 0.5 notes):
//!   - **AgentConfig** — writes to the agent's own config surface
//!     (`settings.json`, `skills/`, `agents/`, `hooks`, `CLAUDE.md`). This is
//!     the agent-self-modification / persistence vector and ATEN's unique
//!     signal. Deliberately does NOT match the whole `.claude/` tree — the
//!     transcript JSONL and todo/history churn under `.claude/projects/` would
//!     be a firehose and is normal behavior.
//!   - **Executable** — writes of an executable/script by extension. Payload or
//!     exfil-script staging.
//!
//! Credential-path writes are intentionally NOT classified here: the
//! `credentials` classifier + `credential_access` event already own that path
//! taxonomy and carry an `access_type`, so a credential overwrite/plant is a
//! `credential_access` with `access_type = write`. Classifying it as a
//! `file_write` here would make the write-intent branch in the collectors
//! divert credential *reads* (e.g. an `O_RDWR` open) away from
//! `credential_access` and drop the exfil signal.
//!
//! Classification is by *path fragment* with Windows separators normalized to
//! `/`, matching the `credentials` module so one set of patterns works on every
//! platform.

use aten_schema::FileWriteClass;

/// Best-effort classification of a written path. Returns `None` for ordinary
/// writes the collector should drop *and* for credential paths (owned by
/// `credential_access`). Priority is AgentConfig → Executable.
///
/// Runs in the hot path (every write-intent open), so it normalizes in a single
/// allocation rather than `to_lowercase().replace()` (which allocated twice).
pub fn classify(path: &str) -> Option<FileWriteClass> {
    let p = normalize(path);

    if is_agent_config(&p) {
        return Some(FileWriteClass::AgentConfig);
    }
    if is_executable(&p) {
        return Some(FileWriteClass::Executable);
    }
    None
}

/// Lowercase + backslash→forward-slash in one pass / one allocation.
fn normalize(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if c == '\\' {
            out.push('/');
        } else {
            for lc in c.to_lowercase() {
                out.push(lc);
            }
        }
    }
    out
}

/// The agent's own configuration surface — the high-signal subset of an agent
/// home dir whose modification changes future-turn behavior. Input is already
/// lowercased and forward-slashed.
fn is_agent_config(p: &str) -> bool {
    // Settings files under either agent's config dir.
    if (p.contains("/.claude/") || p.contains("/.codex/"))
        && (p.ends_with("/settings.json")
            || p.ends_with("/settings.local.json")
            || p.ends_with("/config.toml")
            || p.ends_with("/config.json")
            || p.contains("/hooks"))
    {
        return true;
    }
    // Skills and subagent definitions, in either the user config dir or a
    // project-local `.claude/` / `.codex/` checkout.
    if p.contains("/.claude/skills/")
        || p.contains("/.claude/agents/")
        || p.contains("/.codex/skills/")
        || p.contains("/.codex/agents/")
    {
        return true;
    }
    // Project memory file the agent reads as instructions every session.
    if p.ends_with("/claude.md") || p.ends_with("/agents.md") {
        return true;
    }
    false
}

/// Executable / script by extension. Input is already lowercased. We can't see
/// a Unix shebang from the path alone, so extension-match is the v1 rule;
/// extensionless ELF drops are a documented gap.
fn is_executable(p: &str) -> bool {
    const EXEC_EXTS: &[&str] = &[
        // shells / interpreters
        ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".py", ".pyw",
        ".rb", ".pl", ".php", ".lua", ".js", ".mjs", ".cjs", ".ts", ".vbs", ".vbe", ".wsf", ".jse",
        // native / packaged
        ".exe", ".dll", ".com", ".scr", ".cpl", ".msi", ".jar", ".elf", ".so", ".dylib",
    ];
    let name = p.rsplit('/').next().unwrap_or(p);
    EXEC_EXTS.iter().any(|ext| name.ends_with(ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_config_settings_and_skills() {
        assert_eq!(
            classify("/home/anton/.claude/settings.json"),
            Some(FileWriteClass::AgentConfig)
        );
        assert_eq!(
            classify(r"C:\Users\anton\.claude\settings.local.json"),
            Some(FileWriteClass::AgentConfig)
        );
        assert_eq!(
            classify("/home/anton/.claude/skills/evil/SKILL.md"),
            Some(FileWriteClass::AgentConfig)
        );
        assert_eq!(
            classify("/home/anton/proj/.claude/agents/backdoor.md"),
            Some(FileWriteClass::AgentConfig)
        );
        assert_eq!(
            classify("/home/anton/proj/CLAUDE.md"),
            Some(FileWriteClass::AgentConfig)
        );
    }

    #[test]
    fn normal_claude_churn_is_dropped() {
        // Transcript JSONL and todo/history writes are normal — must NOT emit.
        assert_eq!(
            classify("/home/anton/.claude/projects/foo/session.jsonl"),
            None
        );
        assert_eq!(classify("/home/anton/.claude/todos/x.json"), None);
    }

    #[test]
    fn credential_paths_return_none() {
        // Credential paths are owned by credential_access (which carries
        // access_type), so file_write must NOT claim them — otherwise the
        // collector's write-intent branch would swallow credential reads.
        assert_eq!(classify("/home/anton/.aws/credentials"), None);
        assert_eq!(classify(r"C:\Users\anton\.ssh\planted_key"), None);
    }

    #[test]
    fn executable_drops() {
        assert_eq!(
            classify("/tmp/payload.sh"),
            Some(FileWriteClass::Executable)
        );
        assert_eq!(
            classify(r"C:\Users\anton\AppData\Local\Temp\stage.ps1"),
            Some(FileWriteClass::Executable)
        );
        assert_eq!(classify("/tmp/loader.py"), Some(FileWriteClass::Executable));
        assert_eq!(
            classify("/home/x/evil.exe"),
            Some(FileWriteClass::Executable)
        );
    }

    #[test]
    fn ordinary_writes_dropped() {
        assert_eq!(classify("/home/anton/proj/src/main.rs"), None);
        assert_eq!(classify("/home/anton/notes.txt"), None);
        assert_eq!(classify("/tmp/data.json"), None);
        assert_eq!(classify(r"C:\Users\anton\Documents\report.docx"), None);
    }
}
