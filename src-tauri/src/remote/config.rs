//! Build configuration, the persisted device settings and relay token claims.
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Refresh once fewer than 7 days are left of the token's 30.
pub(crate) fn needs_refresh(token: &str, now: i64) -> bool {
    parse_token(token).is_some_and(|claims| claims.exp - now < 7 * 24 * 3600)
}
const FILE: &str = "remote.json";

/// The relay this build talks to. With a GitHub OAuth app's client ID, sign-in is the GitHub
/// device flow; without one it is the relay's access key (a private relay with no GitHub).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Build {
    pub relay: String,
    pub client_id: Option<String>,
}

fn setting(name: &str, built: Option<&'static str>) -> Option<String> {
    std::env::var(name).ok().or(built.map(str::to_owned)).map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

pub(crate) fn build() -> Option<Build> {
    parse_build(setting("PANDACODE_RELAY_URL", option_env!("PANDACODE_RELAY_URL")), setting("PANDACODE_GITHUB_CLIENT_ID", option_env!("PANDACODE_GITHUB_CLIENT_ID")))
}

pub(crate) fn parse_build(relay: Option<String>, client_id: Option<String>) -> Option<Build> {
    let relay = relay?.trim_end_matches('/').to_owned();
    // Only HTTPS relays: the token rides every request.
    let host = relay.strip_prefix("https://")?;
    if host.is_empty() || host.contains(char::is_whitespace) || client_id.as_deref().is_some_and(|id| !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')) {
        return None;
    }
    Some(Build { relay, client_id })
}

/// Names a certificate authority the relay's certificate may chain to, in addition to the public
/// ones, for a relay on a private network. A PEM file: this variable's path, else `relay-ca.pem`
/// in the app data folder.
pub(crate) const CA_ENV: &str = "PANDACODE_RELAY_CA";
const CA_FILE: &str = "relay-ca.pem";
const CA_LIMIT: u64 = 64 * 1024;
const CA_MAX_CERTIFICATES: usize = 8;

static DATA_DIR: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);

/// Tells the certificate lookup where the app data folder is.
pub(crate) fn use_data_dir(dir: &Path) {
    *DATA_DIR.lock().unwrap_or_else(|e| e.into_inner()) = Some(dir.to_owned());
}

/// The DER certificates of the extra trusted authorities, or none when nothing is configured.
/// A configured file that cannot be used is an error, never silently ignored: the relay would
/// then fail with a certificate error that says nothing about why.
pub(crate) fn relay_ca() -> Result<Vec<Vec<u8>>, String> {
    let dir = DATA_DIR.lock().unwrap_or_else(|e| e.into_inner()).clone();
    relay_ca_in(std::env::var(CA_ENV).ok(), dir.as_deref())
}

fn relay_ca_in(from_env: Option<String>, dir: Option<&Path>) -> Result<Vec<Vec<u8>>, String> {
    let from_env = from_env.map(|path| path.trim().to_owned()).filter(|path| !path.is_empty()).map(std::path::PathBuf::from);
    let path = match from_env {
        Some(path) => path,
        None => match dir.map(|dir| dir.join(CA_FILE)) {
            Some(path) if path.is_file() => path,
            _ => return Ok(Vec::new()),
        },
    };
    let unusable = |why: &str| format!("The relay certificate {} {why}.", path.display());
    let length = std::fs::metadata(&path).map_err(|_| unusable("cannot be read"))?.len();
    if length > CA_LIMIT {
        return Err(unusable("is too large to be a certificate file"));
    }
    let text = std::fs::read_to_string(&path).map_err(|_| unusable("cannot be read as text"))?;
    parse_pem_certificates(&text).map_err(|why| unusable(&why))
}

/// Every `CERTIFICATE` block in `text`, decoded. Other text and other block types are skipped.
pub(crate) fn parse_pem_certificates(text: &str) -> Result<Vec<Vec<u8>>, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut certificates = Vec::new();
    let mut body: Option<String> = None;
    for line in text.lines().map(str::trim) {
        if line == BEGIN {
            body = Some(String::new());
        } else if line == END {
            let encoded = body.take().ok_or("has an END line without a BEGIN line")?;
            let der = base64::engine::general_purpose::STANDARD.decode(encoded.as_bytes()).ok().filter(|der| !der.is_empty()).ok_or("has a certificate that is not valid base64")?;
            certificates.push(der);
            if certificates.len() > CA_MAX_CERTIFICATES {
                return Err(format!("has more than {CA_MAX_CERTIFICATES} certificates"));
            }
        } else if let Some(body) = body.as_mut() {
            body.push_str(line);
        }
    }
    if body.is_some() {
        return Err("has a certificate that never ends".into());
    }
    if certificates.is_empty() {
        return Err("holds no certificate in PEM format".into());
    }
    Ok(certificates)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Account {
    pub id: String,
    pub login: String,
    #[serde(default)]
    pub avatar_url: String,
}

/// Non-secret state in the app data dir. The token and private key are in `secrets.rs`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Settings {
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub host_enabled: bool,
    /// Sends a generic push when a hosted task needs attention or finishes; the relay's bridge
    /// delivers it to the account's phones. Payloads carry counts, never task content.
    #[serde(default)]
    pub notify_enabled: bool,
    /// Lets remote devices pick Full access (no approvals). Off: they get approving modes only.
    #[serde(default)]
    pub remote_full_access: bool,
    #[serde(default)]
    pub account: Option<Account>,
    /// Set once scoped pairing (`grants.rs`) has been set up for this install.
    #[serde(default)]
    pub grants_scoped: bool,
    /// Agents here may use linked computers (docs/machine-orchestration.md).
    #[serde(default)]
    pub orchestration: bool,
    /// Device id → what agents here may do there. Counts only while the device is a target
    /// with the key it was linked under.
    #[serde(default)]
    pub links: std::collections::BTreeMap<String, Link>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Access {
    Read,
    Ask,
    Full,
}

impl Access {
    pub(crate) fn parse(text: &str) -> Option<Self> {
        match text {
            "read" => Some(Self::Read),
            "ask" => Some(Self::Ask),
            "full" => Some(Self::Full),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Link {
    pub access: Access,
    /// When the user linked it, in milliseconds.
    #[serde(default)]
    pub at: i64,
    /// The device's public key when it was linked: a link belongs to the computer behind that
    /// key, so a changed (or missing) key makes it count for nothing.
    #[serde(default)]
    pub key: String,
    /// The device's name when it was linked, for Settings once it has left the account. Older
    /// links have none.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
}

impl Link {
    pub(crate) fn counts_for(&self, current_key: &str) -> bool {
        !self.key.is_empty() && self.key == current_key
    }
}

/// Reads the settings, creating the device id once. The first load after scoped pairing
/// shipped keeps the devices of a computer that already allowed remote control at full
/// access (`grants::seed_adopt`; only those in the first presence frame after it), so an
/// upgrade locks nobody out; anything newer waits for approval.
pub(crate) fn load(dir: &Path) -> Settings {
    let path = dir.join(FILE);
    let text = std::fs::read_to_string(&path).ok();
    let mut settings: Settings = text.as_deref().and_then(|text| serde_json::from_str(text).ok()).unwrap_or_default();
    let mut changed = false;
    if uuid::Uuid::parse_str(&settings.device_id).is_err() {
        settings.device_id = uuid::Uuid::new_v4().to_string();
        changed = true;
    }
    if !settings.grants_scoped {
        let upgraded = text.is_some() && settings.account.is_some() && settings.host_enabled;
        let seeded = if upgraded { super::grants::seed_adopt(dir) } else { Ok(()) };
        changed |= seeded.is_ok();
        settings.grants_scoped = seeded.is_ok();
        if let Err(error) = seeded {
            eprintln!("{error}");
        }
    }
    if changed {
        if let Err(error) = save(dir, &settings) {
            eprintln!("Could not save the remote access device id: {error}");
        }
    }
    settings
}

pub(crate) fn save(dir: &Path, settings: &Settings) -> crate::Result<()> {
    let text = serde_json::to_string_pretty(settings).map_err(|e| e.to_string())?;
    write_atomic(dir, text.as_bytes()).map_err(|e| format!("Could not save remote access settings: {e}"))
}

/// A unique 0600 temp file beside `remote.json`, fsynced, then renamed over it.
// ponytail: same steps as secret_store's private write_atomic; share it if that one is made pub(crate).
fn write_atomic(dir: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let temp = dir.join(format!("{FILE}.{}.tmp", uuid::Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let renamed = options
        .open(&temp)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|_| std::fs::rename(&temp, dir.join(FILE)));
    if renamed.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    renamed
}

/// The stored key, or a new one written once when none (or an unreadable value) is stored.
pub(crate) fn load_or_create_key(stored: Option<String>, write: impl FnOnce(&str) -> crate::Result<()>) -> crate::Result<x25519_dalek::StaticSecret> {
    if let Some(secret) = stored.and_then(|text| super::crypto::decode_secret(&text)) {
        return Ok(secret);
    }
    let secret = super::crypto::generate();
    write(&super::crypto::encode_secret(&secret))?;
    Ok(secret)
}

/// The payload half of a relay token. The signature is the relay's to check.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub(crate) struct Claims {
    pub acct: String,
    pub dev: String,
    pub iat: i64,
    pub exp: i64,
}

pub(crate) fn parse_token(token: &str) -> Option<Claims> {
    let (payload, signature) = token.split_once('.')?;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    if signature.is_empty() || signature.contains('.') || engine.decode(signature).is_err() {
        return None;
    }
    let claims: Claims = serde_json::from_slice(&engine.decode(payload).ok()?).ok()?;
    (claims.exp > claims.iat && !claims.acct.is_empty() && !claims.dev.is_empty()).then_some(claims)
}

/// A token is usable while it is unexpired (`exp` in seconds).
pub(crate) fn token_valid(token: &str, now_seconds: i64) -> bool {
    parse_token(token).is_some_and(|claims| claims.exp > now_seconds)
}

pub(crate) fn device_name() -> String {
    #[cfg(unix)]
    let name = {
        let mut buffer = [0u8; 256];
        // SAFETY: the buffer is valid for its length, and gethostname NUL-terminates within it.
        let ok = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } == 0;
        let end = buffer.iter().position(|&b| b == 0).unwrap_or(0);
        ok.then(|| String::from_utf8_lossy(&buffer[..end]).into_owned())
    };
    #[cfg(not(unix))]
    let name = std::env::var("COMPUTERNAME").ok();
    let name = name.unwrap_or_default();
    let name = name.trim().trim_end_matches(".local").chars().filter(|c| !c.is_control()).take(64).collect::<String>();
    if name.is_empty() { "This computer".into() } else { name }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(payload: &str) -> String {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!("{}.{}", engine.encode(payload), engine.encode([7u8; 32]))
    }

    #[test]
    fn tokens_parse_and_expire() {
        let good = token(r#"{"acct":"gh:1","dev":"d1","iat":100,"exp":200}"#);
        assert_eq!(parse_token(&good), Some(Claims { acct: "gh:1".into(), dev: "d1".into(), iat: 100, exp: 200 }));
        assert!(token_valid(&good, 150));
        assert!(!token_valid(&good, 200));
        assert_eq!(parse_token("nodot"), None);
        assert_eq!(parse_token(&format!("{}.", token(r#"{"acct":"a","dev":"d","iat":1,"exp":2}"#).split('.').next().unwrap())), None);
        assert_eq!(parse_token(&token(r#"{"acct":"","dev":"d","iat":1,"exp":2}"#)), None);
        assert_eq!(parse_token(&token("not json")), None);
    }

    #[test]
    fn tokens_refresh_in_their_last_week() {
        let day = 24 * 3600;
        let t = token(&format!(r#"{{"acct":"gh:1","dev":"d1","iat":0,"exp":{}}}"#, 30 * day));
        assert!(!needs_refresh(&t, 0));
        assert!(!needs_refresh(&t, 23 * day));
        assert!(needs_refresh(&t, 23 * day + 1));
        assert!(!needs_refresh("garbage", 0));
    }

    #[test]
    fn an_existing_key_is_never_replaced() {
        let written = std::cell::Cell::new(false);
        let write = |_: &str| {
            written.set(true);
            Ok(())
        };
        let existing = super::super::crypto::generate();
        let kept = load_or_create_key(Some(super::super::crypto::encode_secret(&existing)), write).unwrap();
        assert_eq!(kept.to_bytes(), existing.to_bytes());
        assert!(!written.get());
        load_or_create_key(None, write).unwrap();
        assert!(written.get());
    }

    #[test]
    fn build_config_needs_https_and_takes_an_optional_client_id() {
        let some = |s: &str| Some(s.to_owned());
        assert_eq!(parse_build(some("https://relay.example/"), some("Iv1.abc")), Some(Build { relay: "https://relay.example".into(), client_id: Some("Iv1.abc".into()) }));
        assert_eq!(parse_build(some("http://relay.example"), some("Iv1.abc")), None);
        assert_eq!(parse_build(some("http://relay.example"), None), None, "a private relay is still HTTPS only");
        assert_eq!(parse_build(some("https://relay.example"), None), Some(Build { relay: "https://relay.example".into(), client_id: None }), "no GitHub app means sign-in by access key");
        assert_eq!(parse_build(some("https://10.0.0.5:8443"), None).map(|build| build.relay), Some("https://10.0.0.5:8443".into()));
        assert_eq!(parse_build(None, some("x")), None);
        assert_eq!(parse_build(some("https://relay.example"), some("bad id")), None);
    }

    /// A real, self-signed CA (P-256, valid until 2126), as `openssl req -x509` writes it.
    pub(crate) const TEST_CA: &str = "-----BEGIN CERTIFICATE-----
MIIBrDCCAVGgAwIBAgIUGXkrBwBT1tvE/yQxkCr2Yb9ngIYwCgYIKoZIzj0EAwIw
IjEgMB4GA1UEAwwXUGFuZGFDb2RlIHRlc3QgcmVsYXkgQ0EwIBcNMjYxMTEyMTA1
NjQ1WhgPMjEyNjEwMTkxMDU2NDVaMCIxIDAeBgNVBAMMF1BhbmRhQ29kZSB0ZXN0
IHJlbGF5IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeOeBl2DZ0j517ZTk
GAJj5f/vh5FG3Cp9cUwn6hkrt9fasK4bY7+URhxo3AmgOd9e8s9PB796LfIt1gip
3SutAKNjMGEwHQYDVR0OBBYEFEy+L19HQhAKs9rWOvlaNg+KHtvuMB8GA1UdIwQY
MBaAFEy+L19HQhAKs9rWOvlaNg+KHtvuMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P
AQH/BAQDAgEGMAoGCCqGSM49BAMCA0kAMEYCIQDVx1aRQHqGp5LsxprwloaWmAR7
NirUNVyfqTRpXn0bDwIhAIQfGx9aXFzhwx41ZkBw73fEuffPLObr3e6AqArH+Jhv
-----END CERTIFICATE-----
";

    #[test]
    fn the_extra_authority_comes_from_the_variable_or_the_app_data_folder() {
        let dir = std::env::temp_dir().join(format!("pandacode-relay-ca-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        // Nothing configured: the public roots only, and no error.
        assert_eq!(relay_ca_in(None, Some(&dir)), Ok(Vec::new()));
        assert_eq!(relay_ca_in(Some("  ".into()), None), Ok(Vec::new()));
        // A relay-ca.pem in the app data folder is used with no variable.
        std::fs::write(dir.join(CA_FILE), TEST_CA).unwrap();
        assert_eq!(relay_ca_in(None, Some(&dir)).unwrap().len(), 1);
        // The variable wins, and names its file when it is unusable.
        let other = dir.join("other.pem");
        std::fs::write(&other, format!("{TEST_CA}{TEST_CA}")).unwrap();
        assert_eq!(relay_ca_in(Some(other.display().to_string()), Some(&dir)).unwrap().len(), 2);
        let missing = dir.join("missing.pem");
        let error = relay_ca_in(Some(missing.display().to_string()), Some(&dir)).unwrap_err();
        assert!(error.contains("missing.pem") && error.contains("cannot be read"), "{error}");
        std::fs::write(&other, "not a certificate").unwrap();
        assert!(relay_ca_in(Some(other.display().to_string()), None).unwrap_err().contains("no certificate"));
        std::fs::write(&other, vec![b'A'; 70_000]).unwrap();
        assert!(relay_ca_in(Some(other.display().to_string()), None).unwrap_err().contains("too large"));
        // A broken file in the app data folder is an error too, not a silent fallback.
        std::fs::write(dir.join(CA_FILE), "oops").unwrap();
        assert!(relay_ca_in(None, Some(&dir)).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn pem_certificates_are_read_and_bad_files_are_named() {
        let one = parse_pem_certificates(TEST_CA).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0][0], 0x30, "a DER SEQUENCE");
        let bundle = format!("# my CA\n{TEST_CA}\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n{}", TEST_CA.replace('\n', "\r\n"));
        assert_eq!(parse_pem_certificates(&bundle).unwrap().len(), 2, "other blocks and CRLF line ends are fine");
        assert!(parse_pem_certificates("").unwrap_err().contains("no certificate"));
        assert!(parse_pem_certificates("not a certificate").unwrap_err().contains("no certificate"));
        assert!(parse_pem_certificates("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----").unwrap_err().contains("base64"));
        assert!(parse_pem_certificates("-----BEGIN CERTIFICATE-----\nAAAA").unwrap_err().contains("never ends"));
        assert!(parse_pem_certificates("-----END CERTIFICATE-----").unwrap_err().contains("END line"));
        assert!(parse_pem_certificates(&TEST_CA.repeat(9)).unwrap_err().contains("more than"));
    }
    #[test]
    fn settings_keep_one_device_id_and_default_host_off() {
        let dir = std::env::temp_dir().join(format!("pandacode-remote-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = load(&dir);
        assert!(!first.host_enabled && !first.remote_full_access);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.join(FILE)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        save(&dir, &Settings { remote_full_access: true, ..first.clone() }).unwrap();
        assert!(load(&dir).remote_full_access);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "no temp files left behind");
        assert!(first.account.is_none());
        assert_eq!(load(&dir).device_id, first.device_id);
        let parsed: Settings = serde_json::from_str(r#"{"deviceId":"x","hostEnabled":true,"account":{"id":"gh:1","login":"a","avatarUrl":"u"},"trusted":{"old-device":"old-key"}}"#).unwrap();
        assert!(parsed.host_enabled);
        assert_eq!(parsed.account.as_ref().unwrap().avatar_url, "u");
        assert!(serde_json::to_value(&parsed).unwrap().get("trusted").is_none());
        assert!(!parsed.orchestration && parsed.links.is_empty(), "orchestration is off by default");
        let linked: Settings = serde_json::from_str(r#"{"orchestration":true,"links":{"d1":{"access":"full","at":5,"key":"k1"}}}"#).unwrap();
        assert_eq!(linked.links["d1"], Link { access: Access::Full, at: 5, key: "k1".into(), name: String::new() });
        assert!(serde_json::to_string(&linked).unwrap().contains(r#""links":{"d1":{"access":"full","at":5,"key":"k1"}}"#));
        assert!(serde_json::from_str::<Settings>(r#"{"links":{"d1":{"access":"root"}}}"#).is_err());
        let named = Link { name: "Studio".into(), ..linked.links["d1"].clone() };
        assert_eq!(serde_json::from_str::<Link>(&serde_json::to_string(&named).unwrap()).unwrap().name, "Studio");
        assert_eq!((Access::parse("ask"), Access::parse("admin")), (Some(Access::Ask), None));
        assert!(linked.links["d1"].counts_for("k1") && !linked.links["d1"].counts_for("k2"), "a changed key drops the link");
        let keyless: Settings = serde_json::from_str(r#"{"links":{"d1":{"access":"ask"}}}"#).unwrap();
        assert!(!keyless.links["d1"].counts_for(""), "a link saved without a key counts for nothing");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn only_an_upgraded_host_adopts_its_devices() {
        let dir = |text: Option<&str>| {
            let dir = std::env::temp_dir().join(format!("pandacode-remote-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            if let Some(text) = text {
                std::fs::write(dir.join(FILE), text).unwrap();
            }
            dir
        };
        let grants = |dir: &Path| dir.join("connect-grants.json").exists();
        let fresh = dir(None);
        assert!(load(&fresh).grants_scoped && !grants(&fresh));
        let signed_in_off = dir(Some(r#"{"deviceId":"9b4f6f0e-6a53-4a38-9d6a-2f5a6b1b6a10","account":{"id":"gh:1","login":"a"}}"#));
        assert!(load(&signed_in_off).grants_scoped && !grants(&signed_in_off));
        let upgraded = dir(Some(r#"{"deviceId":"9b4f6f0e-6a53-4a38-9d6a-2f5a6b1b6a10","hostEnabled":true,"account":{"id":"gh:1","login":"a"}}"#));
        assert!(load(&upgraded).grants_scoped && grants(&upgraded));
        let later = dir(Some(r#"{"deviceId":"9b4f6f0e-6a53-4a38-9d6a-2f5a6b1b6a10","hostEnabled":true,"grantsScoped":true,"account":{"id":"gh:1","login":"a"}}"#));
        assert!(load(&later).grants_scoped && !grants(&later));
        for dir in [fresh, signed_in_off, upgraded, later] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}
