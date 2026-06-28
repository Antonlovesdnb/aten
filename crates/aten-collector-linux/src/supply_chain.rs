//! Supply-chain activity classifier for process starts.
//!
//! This is a derived tag on `process_exec`, not a separate detector. The goal is
//! to make SIEM rules cheap and readable: "agent ran a package installer" or
//! "agent changed dependency state" without regexing every command line.

use aten_schema::SupplyChainActivity;

pub fn classify_process(name: &str, cmdline: &str, args: &[String]) -> Option<SupplyChainActivity> {
    // Prefer argv-derived identity over the kernel `comm`: `comm` is capped at
    // 15 chars, and package managers are often launched through interpreters
    // (`node .../npm-cli.js`, `python -m pip`). Resolve those wrappers to the
    // effective package-manager token when recognizable; fall back to `comm`
    // only when argv is empty.
    let exe_raw = args
        .first()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(name);
    let exe = effective_exe(exe_raw, args);
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

fn effective_exe(exe_raw: &str, args: &[String]) -> String {
    let exe = normalize_token(exe_raw);
    interpreter_wrapped_package_manager(&exe, args).unwrap_or(exe)
}

fn interpreter_wrapped_package_manager(exe: &str, args: &[String]) -> Option<String> {
    if is_node_interpreter(exe) {
        return args
            .iter()
            .skip(1)
            .filter_map(|arg| node_package_manager_entrypoint(arg))
            .next();
    }

    if is_python_interpreter(exe) {
        for pair in args.windows(2) {
            if pair[0] == "-m" {
                if let Some(pm) = python_package_manager_module(&pair[1]) {
                    return Some(pm);
                }
            }
        }
        return args
            .iter()
            .skip(1)
            .filter_map(|arg| python_package_manager_script(arg))
            .next();
    }

    if exe == "php" {
        return args
            .iter()
            .skip(1)
            .filter_map(|arg| {
                let token = normalize_token(arg);
                if token == "composer" || token == "composer.phar" {
                    Some("composer".to_string())
                } else {
                    None
                }
            })
            .next();
    }

    if exe == "ruby" {
        return args
            .iter()
            .skip(1)
            .filter_map(|arg| {
                let token = normalize_token(arg);
                if matches!(token.as_str(), "bundle" | "bundler") {
                    Some(token)
                } else {
                    None
                }
            })
            .next();
    }

    None
}

fn is_node_interpreter(exe: &str) -> bool {
    matches!(exe, "node" | "nodejs")
}

fn node_package_manager_entrypoint(arg: &str) -> Option<String> {
    let token = normalize_token(arg);
    match token.as_str() {
        "npm" | "npm-cli.js" | "npm-cli" => Some("npm".to_string()),
        "npx" | "npx-cli.js" | "npx-cli" => Some("npx".to_string()),
        "yarn" | "yarn.js" | "yarnpkg" => Some("yarn".to_string()),
        "pnpm" | "pnpm.cjs" | "pnpm.js" => Some("pnpm".to_string()),
        _ => None,
    }
}

fn is_python_interpreter(exe: &str) -> bool {
    exe == "python" || exe == "python3" || exe.starts_with("python3.")
}

fn python_package_manager_module(module: &str) -> Option<String> {
    let module = module.to_lowercase();
    match module.as_str() {
        "pip" | "pip3" | "pip._internal" => Some("pip".to_string()),
        "poetry" => Some("poetry".to_string()),
        "uv" => Some("uv".to_string()),
        _ => None,
    }
}

fn python_package_manager_script(arg: &str) -> Option<String> {
    let token = normalize_token(arg);
    match token.as_str() {
        "pip" | "pip3" => Some(token),
        "poetry" => Some("poetry".to_string()),
        "uv" => Some("uv".to_string()),
        _ => None,
    }
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
    fn interpreter_wrapped_package_managers_match() {
        assert_eq!(
            classify_process(
                "node",
                "node /usr/lib/node_modules/npm/bin/npm-cli.js install left-pad",
                &args(&[
                    "node",
                    "/usr/lib/node_modules/npm/bin/npm-cli.js",
                    "install",
                    "left-pad"
                ])
            ),
            Some(SupplyChainActivity::PackageInstall)
        );
        assert_eq!(
            classify_process(
                "node",
                "node /usr/lib/node_modules/npm/bin/npm-cli.js run postinstall",
                &args(&[
                    "node",
                    "/usr/lib/node_modules/npm/bin/npm-cli.js",
                    "run",
                    "postinstall"
                ])
            ),
            Some(SupplyChainActivity::PackageScript)
        );
        assert_eq!(
            classify_process(
                "python3",
                "python3 -m pip install requests",
                &args(&["python3", "-m", "pip", "install", "requests"])
            ),
            Some(SupplyChainActivity::PackageInstall)
        );
        assert_eq!(
            classify_process(
                "php",
                "php composer.phar install",
                &args(&["php", "composer.phar", "install"])
            ),
            Some(SupplyChainActivity::PackageInstall)
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
