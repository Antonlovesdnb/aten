//! Service-mode configuration. Loaded from a TOML file at startup; CLI
//! flags can override individual values per-invocation.
//!
//! Default config locations:
//! - Windows: `%ProgramData%\fishbowl\config.toml`
//! - Linux:   `/etc/fishbowl/config.toml`
//!
//! Every field is optional in the TOML so a partial config is valid — the
//! `Config::merge` semantics layer CLI overrides on top of file values on
//! top of these defaults. The defaults assume single-user Windows install
//! and discover transcripts under the current user's home; in service
//! mode (where the daemon runs as LocalSystem) the install step writes a
//! config that names the actual user's directories explicitly.

use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(default)]
    pub daemon: DaemonSection,
    #[serde(default)]
    pub transcripts: TranscriptsSection,
    #[serde(default)]
    pub output: OutputSection,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonSection {
    /// Process basenames to enroll as agent roots. Matched case-insensitively
    /// against the image basename of every ProcessStart + rundown entry.
    /// Defaults applied when not set: claude.exe / cursor.exe / codex.exe.
    #[serde(default)]
    pub agents: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptsSection {
    /// Directories scanned recursively for `*.jsonl` files. Dialect is
    /// auto-detected per file from path. Service-mode default points at
    /// `%USERPROFILE%\.claude\projects` and `\.codex\sessions`.
    #[serde(default)]
    pub watch_dirs: Vec<PathBuf>,
    /// Individual transcript files. Used by single-session test harnesses;
    /// service mode typically leaves this empty and uses watch_dirs.
    #[serde(default)]
    pub files: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSection {
    /// Append JSONL events to this file. Service mode defaults to
    /// `%ProgramData%\fishbowl\events.jsonl`. CLI test runs typically
    /// override to a temp path.
    pub file_path: Option<PathBuf>,
    /// Which sink(s) to write to: `jsonl` | `eventlog` | `both`. Defaults to
    /// `jsonl`. `eventlog`/`both` are Windows-only (the Fishbowl/Operational
    /// ETW channel); off Windows they fall back to `jsonl` with a warning.
    pub sink: Option<String>,
}

impl ConfigFile {
    /// Read a TOML config from `path`. Missing file is treated as
    /// `ConfigFile::default()` rather than an error — lets `--config` be
    /// optional in CLI mode.
    pub fn load_or_default(path: &std::path::Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => Ok(toml::from_str(&s)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }
}

/// The Windows ProgramData path where the install step writes config and
/// the service writes its events JSONL. Returned as a `PathBuf` so the
/// caller can `.join("config.toml")` / `.join("events.jsonl")`.
#[cfg(target_os = "windows")]
pub fn windows_program_data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("fishbowl")
}

/// Default config path on the host platform.
pub fn default_config_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        windows_program_data_dir().join("config.toml")
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/etc/fishbowl/config.toml")
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        PathBuf::from("./fishbowl.toml")
    }
}

/// Default events-JSONL output path. Service mode uses this when neither
/// the config file nor CLI flags name an output.
pub fn default_output_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        windows_program_data_dir().join("events.jsonl")
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/log/fishbowl/events.jsonl")
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        PathBuf::from("./fishbowl-events.jsonl")
    }
}
