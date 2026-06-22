//! Supply-chain activity classifier for process starts.
//!
//! This is a derived tag on `process_exec`, not a separate detector. The goal is
//! to make SIEM rules cheap and readable: "agent ran a package installer" or
//! "agent changed dependency state" without regexing every command line.

use aten_schema::SupplyChainActivity;

pub fn classify_process(name: &str, cmdline: &str, args: &[String]) -> Option<SupplyChainActivity> {
    // Prefer argv[0] (the actual program) over the kernel `comm`: `comm` is
    // capped at 15 chars and, for scripts, reflects the interpreter (`node`,
    // `python3`) rather than the tool (`npm`, `pip`). Classifying off `comm`
    // alone silently misses package-manager invocations run under an
    // interpreter — the security-relevant false-negative. Fall back to `comm`
    // only when argv is empty.
    let exe_raw = args
        .first()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(name);
    let exe = normalize_token(exe_raw);
    let cmd = cmdline.to_lowercase();

    if is_network_installer(&exe, &cmd) {
        return Some(SupplyChainActivity::NetworkInstaller);
    }
    if is_container_build(&exe, &cmd) {
        return Some(SupplyChainActivity::ContainerBuild);
    }
    if is_git_supply_chain_op(&exe, args, &cmd) {
        return Some(SupplyChainActivity::GitOperation);
    }
    if is_package_script(&exe, args, &cmd) {
        return Some(SupplyChainActivity::PackageScript);
    }
    if is_package_manager(&exe) {
        if package_install_like(args, &cmd) {
            Some(SupplyChainActivity::PackageInstall)
        } else {
            Some(SupplyChainActivity::PackageManager)
        }
    } else if is_build_tool(&exe) {
        Some(SupplyChainActivity::BuildTool)
    } else {
        None
    }
}

fn basename(path: &str) -> Option<&str> {
    path.rsplit(['/', '\\']).next().filter(|s| !s.is_empty())
}

fn normalize_token(token: &str) -> String {
    basename(token)
        .unwrap_or(token)
        .trim_end_matches(".exe")
        .to_lowercase()
}

fn is_package_manager(exe: &str) -> bool {
    matches!(
        exe,
        "npm"
            | "npx"
            | "yarn"
            | "pnpm"
            | "bun"
            | "pip"
            | "pip3"
            | "uv"
            | "poetry"
            | "cargo"
            | "go"
            | "gem"
            | "bundle"
            | "bundler"
            | "composer"
            | "dotnet"
            | "nuget"
            | "mvn"
            | "gradle"
            | "brew"
    )
}

fn package_install_like(args: &[String], cmd: &str) -> bool {
    args.iter().skip(1).any(|arg| {
        matches!(
            arg.as_str(),
            "install"
                | "i"
                | "add"
                | "ci"
                | "sync"
                | "update"
                | "get"
                | "mod"
                | "restore"
                | "bundle"
        )
    }) || contains_word(cmd, "install")
        || contains_word(cmd, "add")
        || contains_word(cmd, "restore")
        || contains_word(cmd, "go get")
}

fn is_package_script(exe: &str, args: &[String], cmd: &str) -> bool {
    matches!(exe, "npm" | "yarn" | "pnpm" | "bun")
        && (args
            .iter()
            .any(|arg| matches!(arg.as_str(), "run" | "exec" | "dlx"))
            || contains_word(cmd, " postinstall")
            || contains_word(cmd, " preinstall")
            || contains_word(cmd, " prepare"))
}

fn is_git_supply_chain_op(exe: &str, args: &[String], cmd: &str) -> bool {
    exe == "git"
        && (args
            .iter()
            .any(|arg| matches!(arg.as_str(), "clone" | "submodule" | "remote" | "pull"))
            || contains_word(cmd, " submodule ")
            || contains_word(cmd, " remote ")
            || contains_word(cmd, " clone "))
}

fn is_network_installer(exe: &str, cmd: &str) -> bool {
    (matches!(
        exe,
        "sh" | "bash" | "zsh" | "fish" | "powershell" | "pwsh" | "cmd"
    ) && (cmd.contains("curl ") || cmd.contains("wget ") || cmd.contains("irm "))
        && (cmd.contains("| sh")
            || cmd.contains("| bash")
            || cmd.contains("| zsh")
            || cmd.contains("| sudo sh")
            || cmd.contains("| sudo bash")
            || cmd.contains("| sudo zsh")
            || cmd.contains("| iex")
            || cmd.contains("iex")
            || cmd.contains("invoke-expression")))
        || (matches!(exe, "curl" | "wget") && cmd.contains("|"))
}

fn is_container_build(exe: &str, cmd: &str) -> bool {
    matches!(exe, "docker" | "podman" | "nerdctl" | "buildah")
        && (contains_word(cmd, " build") || contains_word(cmd, " buildx "))
}

fn is_build_tool(exe: &str) -> bool {
    matches!(
        exe,
        "make" | "cmake" | "ninja" | "msbuild" | "xcodebuild" | "cargo" | "go" | "mvn" | "gradle"
    )
}

fn contains_word(haystack: &str, needle: &str) -> bool {
    haystack.contains(needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn package_install_commands_match() {
        assert_eq!(
            classify_process("npm", "npm install left-pad", &args(&["npm", "install"])),
            Some(SupplyChainActivity::PackageInstall)
        );
        assert_eq!(
            classify_process("cargo", "cargo build", &args(&["cargo", "build"])),
            Some(SupplyChainActivity::PackageManager)
        );
    }

    #[test]
    fn package_scripts_and_network_installers_match() {
        assert_eq!(
            classify_process(
                "npm",
                "npm run postinstall",
                &args(&["npm", "run", "postinstall"])
            ),
            Some(SupplyChainActivity::PackageScript)
        );
        assert_eq!(
            classify_process("sh", "sh -c curl https://x/install.sh | sh", &args(&["sh"])),
            Some(SupplyChainActivity::NetworkInstaller)
        );
        assert_eq!(
            classify_process(
                "bash",
                "bash -lc 'curl -fsSL https://x/install.sh | sudo bash'",
                &args(&["bash"])
            ),
            Some(SupplyChainActivity::NetworkInstaller)
        );
        assert_eq!(
            classify_process(
                "pwsh",
                "pwsh -c irm https://x/install.ps1 | iex",
                &args(&["pwsh"])
            ),
            Some(SupplyChainActivity::NetworkInstaller)
        );
    }

    #[test]
    fn git_and_container_builds_match() {
        assert_eq!(
            classify_process(
                "git",
                "git submodule update --init",
                &args(&["git", "submodule"])
            ),
            Some(SupplyChainActivity::GitOperation)
        );
        assert_eq!(
            classify_process("docker", "docker build .", &args(&["docker", "build"])),
            Some(SupplyChainActivity::ContainerBuild)
        );
    }
}
