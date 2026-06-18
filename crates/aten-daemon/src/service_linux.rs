//! Linux service mode — the systemd analog of the Windows SCM service in
//! `service.rs`.
//!
//! Two entry points, mirroring Windows:
//! - `install_service()` (`aten install`): writes a default config if none
//!   exists, drops `/etc/systemd/system/aten.service`, and
//!   `systemctl enable`s + restarts it. Needs root.
//! - `uninstall_service()` (`aten uninstall`): `systemctl disable --now`s
//!   the unit and removes it, leaving config + event log on disk.
//!
//! There is no `service` subcommand on Linux (unlike Windows' SCM dispatcher):
//! systemd invokes `aten daemon` directly per the unit's `ExecStart`.
//!
//! systemd is declarative, so re-running `install` is naturally idempotent —
//! the unit file is overwritten and `restart` picks up the new binary/config,
//! with no "already exists" special-casing.
//!
//! v0.x runs as root (the eBPF collector needs CAP_BPF + CAP_SYS_ADMIN +
//! CAP_PERFMON). The hardened path — a dedicated user with `AmbientCapabilities`
//! in the unit — is a follow-up (see deployment.md).

use anyhow::{bail, Context, Result};

const UNIT_NAME: &str = "aten.service";
const UNIT_PATH: &str = "/etc/systemd/system/aten.service";
const CONFIG_DIR: &str = "/etc/aten";
const CONFIG_PATH: &str = "/etc/aten/config.toml";
const LOG_DIR: &str = "/var/log/aten";
const STATE_DIR: &str = "/var/lib/aten";
const EVENTS_PATH: &str = "/var/log/aten/events.jsonl";

pub fn install_service() -> Result<()> {
    if !is_root() {
        bail!("`aten install` needs root (sudo) — it writes a systemd unit and the daemon needs CAP_BPF/CAP_SYS_ADMIN/CAP_PERFMON");
    }

    let exe = std::env::current_exe().context("locate own binary path")?;

    // Service-owned directories.
    for d in [CONFIG_DIR, LOG_DIR, STATE_DIR] {
        std::fs::create_dir_all(d).with_context(|| format!("create {d}"))?;
    }

    // Default config, discovering the invoking user's transcript dirs. The
    // service runs as root, so `SUDO_USER`'s home is the right place to watch,
    // not root's. Preserve an existing config.
    let cfg_path = std::path::Path::new(CONFIG_PATH);
    if cfg_path.exists() {
        eprintln!("[aten install] preserved existing config {CONFIG_PATH}");
    } else {
        let home = real_user_home();
        let body = format!(
            "# ATEN service config. Edit and restart the service:\n\
             #   sudo systemctl restart aten\n\
             \n\
             [daemon]\n\
             agents = [\"claude\", \"codex\"]\n\
             \n\
             [transcripts]\n\
             # Recursively scanned for *.jsonl. Dialect (Claude / Codex) auto-detected per file.\n\
             watch_dirs = [\n\
             {INDENT}\"{home}/.claude/projects\",\n\
             {INDENT}\"{home}/.codex/sessions\",\n\
             ]\n\
             \n\
             [output]\n\
             # sink: jsonl | eventlog | both. eventlog is Windows-only; on Linux\n\
             # use jsonl and forward the file to your SIEM (syslog/Splunk/OTel).\n\
             sink = \"jsonl\"\n\
             file_path = \"{EVENTS_PATH}\"\n",
            INDENT = "    ",
        );
        std::fs::write(cfg_path, body).with_context(|| format!("write {CONFIG_PATH}"))?;
        eprintln!("[aten install] wrote default config to {CONFIG_PATH}");
    }

    // The unit. ExecStart points at the current binary (matches the Windows
    // service, which registers its current_exe rather than copying). A `.deb`
    // would instead place the binary at /usr/local/bin — that's the packaging
    // layer's job, out of scope here.
    let unit = format!(
        "[Unit]\n\
         Description=ATEN AI agent telemetry daemon\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exe} daemon --config {CONFIG_PATH}\n\
         Restart=on-failure\n\
         RestartSec=5s\n\
         # v0.x: root (eBPF caps). v1.0: dedicated user with AmbientCapabilities.\n\
         User=root\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        exe = exe.display(),
    );
    std::fs::write(UNIT_PATH, unit).with_context(|| format!("write {UNIT_PATH}"))?;
    eprintln!("[aten install] wrote systemd unit {UNIT_PATH}");

    // Reload, enable (idempotent), and restart so a re-install picks up the new
    // binary/config (restart == start when stopped).
    systemctl(&["daemon-reload"]);
    systemctl(&["enable", UNIT_NAME]);
    if systemctl(&["restart", UNIT_NAME]) {
        eprintln!("[aten install] service 'aten' enabled and started");
    } else {
        eprintln!(
            "[aten install] unit installed but start failed — inspect with: \
             journalctl -u aten -e"
        );
    }
    Ok(())
}

pub fn uninstall_service() -> Result<()> {
    if !is_root() {
        bail!("`aten uninstall` needs root (sudo)");
    }
    // disable --now stops the service and removes the WantedBy symlink.
    systemctl(&["disable", "--now", UNIT_NAME]);
    match std::fs::remove_file(UNIT_PATH) {
        Ok(()) => eprintln!("[aten uninstall] removed {UNIT_PATH}"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => eprintln!("[aten uninstall] could not remove {UNIT_PATH}: {e} (non-fatal)"),
    }
    systemctl(&["daemon-reload"]);
    eprintln!(
        "[aten uninstall] service 'aten' removed; left {CONFIG_DIR}, {STATE_DIR}, and \
         {LOG_DIR} in place"
    );
    Ok(())
}

/// True when running as root (euid 0). systemd unit + eBPF both require it.
fn is_root() -> bool {
    // SAFETY: geteuid is always safe and never fails.
    unsafe { libc::geteuid() == 0 }
}

/// Run `systemctl <args>`, returning whether it exited 0. Output goes to the
/// terminal so systemd's own diagnostics are visible.
fn systemctl(args: &[&str]) -> bool {
    std::process::Command::new("systemctl")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The home directory of the human installing this, even under `sudo` (where
/// `$HOME` is root's). Prefers `SUDO_USER` → `/home/<user>`, then `$HOME`, then
/// `/root`. Used only to seed the default config's watch dirs.
fn real_user_home() -> String {
    if let Ok(user) = std::env::var("SUDO_USER") {
        if !user.is_empty() && user != "root" {
            return format!("/home/{user}");
        }
    }
    std::env::var("HOME").unwrap_or_else(|_| "/root".to_string())
}
