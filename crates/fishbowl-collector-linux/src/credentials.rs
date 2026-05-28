//! Credential classifier — maps a file path to the schema's `CredentialClass`
//! enum. Runs at the collector so detections never need to regex over
//! `file_path`. This is the cross-platform taxonomy from `schema.md` §6;
//! both the Linux eBPF probe and the Windows ETW probe call into this
//! module.
//!
//! Classification is by *path fragment*, not by absolute path. `~/.aws/
//! credentials` and `/root/.aws/credentials` and any other user's
//! `~/.aws/credentials` all produce `AwsCredentials`. That makes the
//! classifier user-agnostic and lets the daemon work without resolving a
//! per-process HOME from /proc (Linux) or token user profile (Windows).
//!
//! Windows paths (`C:\Users\anton\.aws\credentials`,
//! `\Device\HarddiskVolume3\Users\anton\.aws\credentials`) are normalized
//! to forward-slash form before matching, so the same patterns work on both
//! platforms with one source of truth.
//!
//! Known v0.x false-positive: a directory literally named `.env`
//! (`C:\foo\.env.bak\unrelated.txt` or `/home/x/.env.bak/unrelated.txt`)
//! will classify as `GenericDotenv` because of the `.env.` substring match.
//! Accepted for v0.x; the false-positive rate is bounded by enrollment
//! filtering (only enrolled agent descendants are checked).

use fishbowl_schema::CredentialClass;

/// Best-effort classification. Returns `CredentialClass::None` for paths that
/// don't look like credentials — the caller should drop those events at the
/// collector rather than emitting `credential_class=none` to the SIEM.
pub fn classify(path: &str) -> CredentialClass {
    // Normalize Windows separators to POSIX so a single set of suffix patterns
    // works for both platforms. No-op for inputs that don't contain `\`.
    let p = path.to_lowercase().replace('\\', "/");

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

    // Windows path forms — both `C:\...` user-land and the
    // `\Device\HarddiskVolumeN\...` NT-namespace form that ETW Kernel-File
    // events deliver. Same patterns must match after backslash → forward-slash
    // normalization.
    #[test]
    fn windows_paths_match() {
        assert_eq!(
            classify(r"C:\Users\anton\.aws\credentials"),
            CredentialClass::AwsCredentials
        );
        assert_eq!(
            classify(r"\Device\HarddiskVolume3\Users\anton\.ssh\id_rsa"),
            CredentialClass::SshPrivateKey
        );
        assert_eq!(
            classify(r"C:\Users\anton\.kube\config"),
            CredentialClass::KubeConfig
        );
        assert_eq!(
            classify(r"C:\Users\anton\.azure\accessTokens.json"),
            CredentialClass::AzureCredentials
        );
        // `.pub` discriminator still holds after normalization.
        assert_eq!(
            classify(r"C:\Users\anton\.ssh\id_rsa.pub"),
            CredentialClass::None
        );
    }
}
