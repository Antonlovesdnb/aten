//! Sensitive local IPC classifier.
//!
//! This is deliberately small and high-signal: local sockets / named pipes that
//! let an agent reach a privileged broker or secret-bearing agent without
//! making Internet egress. The Linux collector uses it for AF_UNIX connect()
//! paths; Windows uses it for named-pipe File/Create events; macOS can reuse it
//! for EndpointSecurity path opens if those surfaces appear there.

use aten_schema::LocalIpcClass;

pub fn classify(path: &str) -> Option<LocalIpcClass> {
    let p = normalize(path);

    if p.ends_with("/docker.sock")
        || p.contains("/docker.sock/")
        || p.ends_with("/pipe/docker_engine")
        || p.ends_with("\\pipe\\docker_engine")
        || p.contains("docker_engine")
    {
        return Some(LocalIpcClass::DockerSocket);
    }

    if p.contains("containerd.sock")
        || p.contains("podman.sock")
        || p.contains("crio.sock")
        || p.contains("cri-dockerd.sock")
        || p.contains("buildkit")
    {
        return Some(LocalIpcClass::ContainerRuntimeSocket);
    }

    if p.contains("ssh-agent") || p.contains("/agent.") || p.ends_with("/ssh_auth_sock") {
        return Some(LocalIpcClass::SshAgentSocket);
    }

    if p.contains("s.gpg-agent") || p.contains("gpg-agent") {
        return Some(LocalIpcClass::GpgAgentSocket);
    }

    if p.contains("1password")
        || p.contains("/op-")
        || p.contains("secretservice")
        || p.contains("keyring")
        || p.contains("keepass")
    {
        return Some(LocalIpcClass::SecretManagerSocket);
    }

    None
}

fn normalize(path: &str) -> String {
    path.to_lowercase().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aten_schema::LocalIpcClass;

    #[test]
    fn docker_and_container_runtime_sockets_match() {
        assert_eq!(
            classify("/var/run/docker.sock"),
            Some(LocalIpcClass::DockerSocket)
        );
        assert_eq!(
            classify(r"\\.\pipe\docker_engine"),
            Some(LocalIpcClass::DockerSocket)
        );
        assert_eq!(
            classify("/run/containerd/containerd.sock"),
            Some(LocalIpcClass::ContainerRuntimeSocket)
        );
        assert_eq!(
            classify("/run/user/501/podman/podman.sock"),
            Some(LocalIpcClass::ContainerRuntimeSocket)
        );
    }

    #[test]
    fn secret_broker_sockets_match() {
        assert_eq!(
            classify("/tmp/ssh-agent.abc/agent.123"),
            Some(LocalIpcClass::SshAgentSocket)
        );
        assert_eq!(
            classify("/run/user/1000/gnupg/S.gpg-agent"),
            Some(LocalIpcClass::GpgAgentSocket)
        );
        assert_eq!(
            classify("/run/user/1000/1Password/ipc.sock"),
            Some(LocalIpcClass::SecretManagerSocket)
        );
    }

    #[test]
    fn ordinary_sockets_do_not_match() {
        assert_eq!(classify("/tmp/language-server.sock"), None);
        assert_eq!(classify("/var/run/dbus/system_bus_socket"), None);
    }
}
