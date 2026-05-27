//! Credential classifier — maps a file path to the schema's `CredentialClass`
//! enum. Runs at the collector so detections never need to regex over
//! `file_path`. This is the Linux side of the cross-platform taxonomy from
//! `schema.md` §6.
//!
//! Classification is by *path fragment*, not by absolute path. `~/.aws/
//! credentials` and `/root/.aws/credentials` and any other user's
//! `~/.aws/credentials` all produce `AwsCredentials`. That makes the
//! classifier user-agnostic and lets the daemon work without resolving a
//! per-process HOME from /proc.

use fishbowl_schema::CredentialClass;

/// Best-effort classification. Returns `CredentialClass::None` for paths that
/// don't look like credentials — the caller should drop those events at the
/// collector rather than emitting `credential_class=none` to the SIEM.
pub fn classify(path: &str) -> CredentialClass {
    let p = path.to_lowercase();

    if p.ends_with("/.aws/credentials") || p.ends_with("/.aws/config") {
        return CredentialClass::AwsCredentials;
    }
    if p.contains("/.azure/") {
        return CredentialClass::AzureCredentials;
    }
    if p.contains("/.config/gcloud/") {
        return CredentialClass::GcpCredentials;
    }
    if let Some(idx) = p.find("/.ssh/") {
        let after = &p[idx + "/.ssh/".len()..];
        // Private key files start with "id_" and aren't the corresponding
        // .pub file. authorized_keys / known_hosts are non-secret.
        if let Some(name) = after.split('/').next() {
            if name.starts_with("id_") && !name.ends_with(".pub") {
                return CredentialClass::SshPrivateKey;
            }
        }
    }
    if p.ends_with("/.git-credentials") || p.ends_with("/.config/git/credentials") {
        return CredentialClass::GitCredentials;
    }
    if p.ends_with("/cookies")
        && (p.contains("/google-chrome/")
            || p.contains("/chromium/")
            || p.contains("/bravesoftware/")
            || p.contains("/firefox/"))
    {
        return CredentialClass::BrowserCookies;
    }
    if p.ends_with("/.kube/config") {
        return CredentialClass::KubeConfig;
    }
    if p.ends_with("/.env") || p.contains("/.env.") {
        return CredentialClass::GenericDotenv;
    }
    CredentialClass::None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_credentials_match() {
        assert_eq!(
            classify("/home/anton/.aws/credentials"),
            CredentialClass::AwsCredentials
        );
        assert_eq!(
            classify("/root/.aws/config"),
            CredentialClass::AwsCredentials
        );
    }

    #[test]
    fn ssh_private_only_not_pub() {
        assert_eq!(
            classify("/home/anton/.ssh/id_ed25519"),
            CredentialClass::SshPrivateKey
        );
        assert_eq!(
            classify("/home/anton/.ssh/id_rsa.pub"),
            CredentialClass::None
        );
        assert_eq!(
            classify("/home/anton/.ssh/authorized_keys"),
            CredentialClass::None
        );
    }

    #[test]
    fn dotenv_variants() {
        assert_eq!(
            classify("/home/anton/proj/.env"),
            CredentialClass::GenericDotenv
        );
        assert_eq!(
            classify("/home/anton/proj/.env.production"),
            CredentialClass::GenericDotenv
        );
    }

    #[test]
    fn non_credentials_classify_none() {
        assert_eq!(classify("/etc/hostname"), CredentialClass::None);
        assert_eq!(classify("/usr/bin/cat"), CredentialClass::None);
        assert_eq!(classify("/tmp/somefile"), CredentialClass::None);
    }

    #[test]
    fn browser_cookies() {
        assert_eq!(
            classify("/home/anton/.config/google-chrome/default/cookies"),
            CredentialClass::BrowserCookies
        );
    }

    #[test]
    fn kube_config() {
        assert_eq!(
            classify("/home/anton/.kube/config"),
            CredentialClass::KubeConfig
        );
    }
}
