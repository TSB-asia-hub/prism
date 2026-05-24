use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use walkdir::WalkDir;

use crate::models::{ScanFinding, ScanVerdict};

const CALLBACK_HOST: &str = "127.0.0.1";
const DEFAULT_CALLBACK_PORT: u16 = 53177;
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(180);
const USER_AGENT: &str = concat!("Prism/", env!("CARGO_PKG_VERSION"), " account-inventory");

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AccountProvider {
    Discord,
    Roblox,
}

impl AccountProvider {
    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "discord" => Ok(Self::Discord),
            "roblox" => Ok(Self::Roblox),
            other => Err(format!("Unsupported account provider: {}", other)),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Discord => "discord",
            Self::Roblox => "roblox",
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Discord => "Discord",
            Self::Roblox => "Roblox",
        }
    }

    fn callback_path(&self) -> &'static str {
        match self {
            Self::Discord => "/oauth/discord",
            Self::Roblox => "/oauth/roblox",
        }
    }
}

impl fmt::Display for AccountProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LinkedAccount {
    pub provider: String,
    pub id: String,
    pub username: String,
    pub verified: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AccountIdentity {
    pub provider: AccountProvider,
    pub id: String,
    pub username: String,
    pub display_name: Option<String>,
    pub profile_url: Option<String>,
    pub avatar_url: Option<String>,
    pub verified_at: DateTime<Utc>,
    pub source: String,
    pub linked_accounts: Vec<LinkedAccount>,
}

#[derive(Clone, Default)]
pub struct AccountStore(Arc<Mutex<Vec<AccountIdentity>>>);

impl AccountStore {
    pub fn add(&self, account: AccountIdentity) -> Result<(), String> {
        self.add_many(vec![account])
    }

    pub fn add_many(&self, new_accounts: Vec<AccountIdentity>) -> Result<(), String> {
        let mut accounts = self
            .0
            .lock()
            .map_err(|_| "Account store lock poisoned".to_string())?;
        for account in new_accounts {
            upsert_account(&mut accounts, account);
        }
        sort_accounts(&mut accounts);
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<AccountIdentity>, String> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "Account store lock poisoned".to_string())?
            .clone())
    }

    pub fn clear(&self) -> Result<(), String> {
        self.0
            .lock()
            .map_err(|_| "Account store lock poisoned".to_string())?
            .clear();
        Ok(())
    }
}

fn upsert_account(accounts: &mut Vec<AccountIdentity>, account: AccountIdentity) {
    if let Some(existing) = accounts
        .iter_mut()
        .find(|a| a.provider == account.provider && a.id == account.id)
    {
        // Prefer explicit OAuth records over local-file hints; otherwise use
        // the newest observation for the same provider/id pair.
        let existing_is_local = existing.source.starts_with("Local file");
        let account_is_local = account.source.starts_with("Local file");
        if !existing_is_local && account_is_local {
            return;
        }
        if existing_is_local && !account_is_local || account.verified_at > existing.verified_at {
            *existing = account;
        }
    } else {
        accounts.push(account);
    }
}

fn sort_accounts(accounts: &mut [AccountIdentity]) {
    accounts.sort_by(|a, b| {
        a.provider
            .as_str()
            .cmp(b.provider.as_str())
            .then_with(|| a.username.to_lowercase().cmp(&b.username.to_lowercase()))
            .then_with(|| a.id.cmp(&b.id))
    });
}

#[tauri::command]
pub async fn link_account(
    provider: String,
    store: tauri::State<'_, AccountStore>,
) -> Result<AccountIdentity, String> {
    let provider = AccountProvider::parse(&provider)?;
    let account = tokio::task::spawn_blocking(move || link_account_blocking(provider))
        .await
        .map_err(|e| format!("Account-link task failed: {}", e))??;
    store.add(account.clone())?;
    Ok(account)
}

#[tauri::command]
pub async fn verified_accounts(
    store: tauri::State<'_, AccountStore>,
) -> Result<Vec<AccountIdentity>, String> {
    store.list()
}

#[tauri::command]
pub async fn clear_verified_accounts(store: tauri::State<'_, AccountStore>) -> Result<(), String> {
    store.clear()
}

#[tauri::command]
pub async fn scan_local_accounts(
    store: tauri::State<'_, AccountStore>,
) -> Result<Vec<AccountIdentity>, String> {
    let local_accounts = tokio::task::spawn_blocking(discover_local_accounts)
        .await
        .map_err(|e| format!("Local account scan task failed: {}", e))?;
    store.add_many(local_accounts)?;
    store.list()
}

pub fn account_inventory(accounts: &AccountStore) -> Vec<AccountIdentity> {
    let mut merged = accounts.list().unwrap_or_default();
    for account in discover_local_accounts() {
        upsert_account(&mut merged, account);
    }
    sort_accounts(&mut merged);
    merged
}

pub fn account_inventory_findings(accounts: &[AccountIdentity]) -> Vec<ScanFinding> {
    accounts
        .iter()
        .map(|account| {
            let mut detail_parts = vec![
                format!("Provider: {}", account.provider.label()),
                format!("Account ID: {}", account.id),
                format!("Username: {}", account.username),
                format!("Verified at: {}", account.verified_at.to_rfc3339()),
                format!("Source: {}", account.source),
            ];
            if let Some(display_name) = account.display_name.as_deref().filter(|s| !s.is_empty()) {
                detail_parts.push(format!("Display: {}", display_name));
            }
            if let Some(profile_url) = account.profile_url.as_deref().filter(|s| !s.is_empty()) {
                detail_parts.push(format!("Profile: {}", profile_url));
            }
            if !account.linked_accounts.is_empty() {
                let linked = account
                    .linked_accounts
                    .iter()
                    .map(|linked| {
                        let verified = if linked.verified {
                            "verified"
                        } else {
                            "unverified"
                        };
                        format!(
                            "{}:{} ({}, {})",
                            linked.provider, linked.id, linked.username, verified
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                detail_parts.push(format!("Linked accounts: {}", linked));
            }

            let descriptor = if account.source.starts_with("Local file") {
                "Local account hint"
            } else {
                "Verified account"
            };
            ScanFinding::new(
                "account_inventory",
                ScanVerdict::Clean,
                format!(
                    "{} — {}: {}",
                    descriptor,
                    account.provider.label(),
                    account_label(account)
                ),
                Some(detail_parts.join(" | ")),
            )
        })
        .collect()
}

fn account_label(account: &AccountIdentity) -> String {
    match account
        .display_name
        .as_deref()
        .filter(|name| !name.is_empty())
    {
        Some(display_name) if display_name != account.username => {
            format!("{} (@{})", display_name, account.username)
        }
        _ => account.username.clone(),
    }
}

fn link_account_blocking(provider: AccountProvider) -> Result<AccountIdentity, String> {
    let config = OAuthConfig::for_provider(provider.clone())?;
    let listener = CallbackListener::bind(provider.clone(), &config.redirect_uri)?;
    tauri_plugin_opener::open_url(&config.auth_url, None::<&str>)
        .map_err(|e| format!("Could not open {} authorization URL: {}", provider, e))?;
    let callback = listener.wait()?;
    if callback.state != config.state {
        return Err(format!(
            "{} authorization state mismatch; refusing callback",
            provider
        ));
    }
    let code = callback
        .code
        .ok_or_else(|| format!("{} authorization callback did not include a code", provider))?;

    match provider {
        AccountProvider::Discord => complete_discord(config, code),
        AccountProvider::Roblox => complete_roblox(config, code),
    }
}

#[derive(Clone)]
struct LocalAccountRoot {
    provider: AccountProvider,
    path: PathBuf,
    label: &'static str,
}

#[derive(Clone)]
struct LocalAccountDraft {
    provider: AccountProvider,
    id: String,
    username: Option<String>,
    display_name: Option<String>,
    profile_url: Option<String>,
    paths: BTreeSet<String>,
    newest_modified: Option<SystemTime>,
}

pub fn discover_local_accounts() -> Vec<AccountIdentity> {
    let mut drafts: Vec<LocalAccountDraft> = Vec::new();
    for root in local_account_roots() {
        if !root.path.exists() {
            continue;
        }
        for path in recent_safe_files(&root.path) {
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            if bytes.is_empty() || bytes.len() > LOCAL_ACCOUNT_FILE_LIMIT_BYTES {
                continue;
            }
            let content = String::from_utf8_lossy(&bytes);
            let modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
            collect_local_candidates(
                &mut drafts,
                &root.provider,
                &content,
                &path,
                root.label,
                modified,
            );
        }
    }

    drafts.into_iter().map(local_draft_to_account).collect()
}

const LOCAL_ACCOUNT_FILE_LIMIT_BYTES: usize = 3 * 1024 * 1024;
const LOCAL_ACCOUNT_MAX_FILES_PER_ROOT: usize = 60;
const LOCAL_ACCOUNT_SCAN_DEPTH: usize = 4;

fn local_account_roots() -> Vec<LocalAccountRoot> {
    let mut roots = Vec::new();

    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            let appdata = PathBuf::from(appdata);
            for dir in [
                "discord",
                "discordptb",
                "discordcanary",
                "discorddevelopment",
            ] {
                roots.push(LocalAccountRoot {
                    provider: AccountProvider::Discord,
                    path: appdata.join(dir),
                    label: "Discord desktop",
                });
            }
        }
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            roots.push(LocalAccountRoot {
                provider: AccountProvider::Roblox,
                path: PathBuf::from(local_app_data).join("Roblox").join("logs"),
                label: "Roblox logs",
            });
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let home = PathBuf::from(home);
            for dir in [
                "discord",
                "discordptb",
                "discordcanary",
                "discorddevelopment",
            ] {
                roots.push(LocalAccountRoot {
                    provider: AccountProvider::Discord,
                    path: home.join("Library").join("Application Support").join(dir),
                    label: "Discord desktop",
                });
            }
            roots.push(LocalAccountRoot {
                provider: AccountProvider::Roblox,
                path: home.join("Library").join("Logs").join("Roblox"),
                label: "Roblox logs",
            });
            roots.push(LocalAccountRoot {
                provider: AccountProvider::Roblox,
                path: home.join("Library").join("Roblox").join("logs"),
                label: "Roblox logs",
            });
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let home = PathBuf::from(home);
            for dir in [
                "discord",
                "discordptb",
                "discordcanary",
                "discorddevelopment",
            ] {
                roots.push(LocalAccountRoot {
                    provider: AccountProvider::Discord,
                    path: home.join(".config").join(dir),
                    label: "Discord desktop",
                });
            }
        }
    }

    roots
}

fn recent_safe_files(root: &Path) -> Vec<PathBuf> {
    let mut files = WalkDir::new(root)
        .max_depth(LOCAL_ACCOUNT_SCAN_DEPTH)
        .follow_links(false)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| is_safe_account_hint_file(path))
        .filter_map(|path| {
            let metadata = std::fs::metadata(&path).ok()?;
            if metadata.len() > LOCAL_ACCOUNT_FILE_LIMIT_BYTES as u64 {
                return None;
            }
            let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            Some((path, modified))
        })
        .collect::<Vec<_>>();
    files.sort_by_key(|(_, modified)| std::cmp::Reverse(*modified));
    files
        .into_iter()
        .take(LOCAL_ACCOUNT_MAX_FILES_PER_ROOT)
        .map(|(path, _)| path)
        .collect()
}

fn is_safe_account_hint_file(path: &Path) -> bool {
    let lower_path = path.to_string_lossy().to_ascii_lowercase();
    // Explicitly avoid browser/Electron secret-bearing stores. We only scan
    // human-readable logs/config snapshots where account IDs can appear as
    // ordinary telemetry context; no cookie DBs, Local Storage LevelDB, or
    // encrypted credential stores are touched.
    let blocked_parts = [
        "local storage",
        "session storage",
        "leveldb",
        "cookies",
        "cookie",
        "network",
        "cache",
        "code cache",
        "gpucache",
        "blob_storage",
        "databases",
        "indexeddb",
    ];
    if blocked_parts.iter().any(|part| lower_path.contains(part)) {
        return false;
    }

    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if matches!(file_name.as_str(), "local state" | "settings.json") {
        return true;
    }
    matches!(
        path.extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .as_deref(),
        Some("log" | "txt" | "json")
    )
}

fn collect_local_candidates(
    drafts: &mut Vec<LocalAccountDraft>,
    provider: &AccountProvider,
    content: &str,
    path: &Path,
    label: &str,
    modified: Option<SystemTime>,
) {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(content) {
        collect_json_candidates(drafts, provider, &value, path, label, modified);
    }
    collect_line_candidates(drafts, provider, content, path, label, modified);
}

fn collect_json_candidates(
    drafts: &mut Vec<LocalAccountDraft>,
    provider: &AccountProvider,
    value: &serde_json::Value,
    path: &Path,
    label: &str,
    modified: Option<SystemTime>,
) {
    match value {
        serde_json::Value::Object(obj) => {
            if let Some(id) = json_account_id(provider, obj) {
                let username = json_string_field(obj, &["username", "userName", "name"]);
                let display_name = json_string_field(
                    obj,
                    &[
                        "displayName",
                        "display_name",
                        "global_name",
                        "globalName",
                        "nickname",
                    ],
                );
                merge_local_draft(
                    drafts,
                    provider.clone(),
                    id,
                    username,
                    display_name,
                    path,
                    label,
                    modified,
                );
            }
            for child in obj.values() {
                collect_json_candidates(drafts, provider, child, path, label, modified);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                collect_json_candidates(drafts, provider, child, path, label, modified);
            }
        }
        _ => {}
    }
}

fn collect_line_candidates(
    drafts: &mut Vec<LocalAccountDraft>,
    provider: &AccountProvider,
    content: &str,
    path: &Path,
    label: &str,
    modified: Option<SystemTime>,
) {
    let lines = content.lines().collect::<Vec<_>>();
    for (idx, line) in lines.iter().enumerate() {
        let Some(id) = local_line_account_id(provider, line) else {
            continue;
        };
        let window_start = idx.saturating_sub(3);
        let window_end = (idx + 4).min(lines.len());
        let username = lines[window_start..window_end]
            .iter()
            .find_map(|candidate| local_line_username(candidate));
        let display_name = lines[window_start..window_end]
            .iter()
            .find_map(|candidate| local_line_display_name(candidate));
        merge_local_draft(
            drafts,
            provider.clone(),
            id,
            username,
            display_name,
            path,
            label,
            modified,
        );
    }
}

fn json_account_id(
    provider: &AccountProvider,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Option<String> {
    let keys: &[&str] = match provider {
        AccountProvider::Discord => &["id", "user_id", "userId", "currentUserId"],
        AccountProvider::Roblox => &["userId", "user_id", "userid", "id", "accountId"],
    };
    for key in keys {
        if let Some(id) = obj.get(*key).and_then(json_value_to_string) {
            if id_shape_matches(provider, &id) {
                return Some(id);
            }
        }
    }
    None
}

fn json_string_field(
    obj: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<String> {
    keys.iter()
        .find_map(|key| obj.get(*key).and_then(|v| v.as_str()))
        .map(clean_account_text)
        .filter(|s| !s.is_empty())
}

fn json_value_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn local_line_account_id(provider: &AccountProvider, line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let keys: &[&str] = match provider {
        AccountProvider::Discord => &[
            "user_id",
            "userid",
            "user id",
            "current_user",
            "current user",
            "discord user",
        ],
        AccountProvider::Roblox => &[
            "userid",
            "user_id",
            "user id",
            "user-id",
            "user id:",
            "accountid",
            "account id",
        ],
    };
    let key_match = keys
        .iter()
        .filter_map(|key| lower.find(key).map(|idx| (idx, key.len())))
        .min_by_key(|(idx, _)| *idx)?;
    let tail = &line[key_match.0 + key_match.1..];
    extract_digit_runs(tail)
        .into_iter()
        .find(|digits| id_shape_matches(provider, digits))
}

fn local_line_username(line: &str) -> Option<String> {
    extract_value_after_any_key(
        line,
        &["username", "user_name", "user name", "preferred_username"],
    )
}

fn local_line_display_name(line: &str) -> Option<String> {
    extract_value_after_any_key(
        line,
        &["displayname", "display_name", "display name", "global_name"],
    )
}

fn extract_value_after_any_key(line: &str, keys: &[&str]) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let key = keys.iter().find(|key| lower.contains(**key))?;
    let start = lower.find(*key)? + key.len();
    let tail = &line[start..];
    let tail = tail.trim_start_matches(|c: char| {
        c.is_whitespace() || matches!(c, ':' | '=' | '-' | '>' | '"' | '\'')
    });
    let value = if let Some(rest) = tail.strip_prefix('"') {
        rest.split('"').next().unwrap_or_default()
    } else if let Some(rest) = tail.strip_prefix('\'') {
        rest.split('\'').next().unwrap_or_default()
    } else {
        tail.split(|c: char| c.is_whitespace() || matches!(c, ',' | '|' | ';' | ')' | '}'))
            .next()
            .unwrap_or_default()
    };
    let value = clean_account_text(value);
    (!value.is_empty()).then_some(value)
}

fn clean_account_text(value: &str) -> String {
    value
        .trim()
        .trim_matches(['"', '\'', ',', ':', ';', ')', '}', ']'])
        .chars()
        .take(80)
        .collect::<String>()
}

fn extract_digit_runs(line: &str) -> Vec<String> {
    let mut runs = Vec::new();
    let mut current = String::new();
    for c in line.chars() {
        if c.is_ascii_digit() {
            current.push(c);
        } else if !current.is_empty() {
            runs.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        runs.push(current);
    }
    runs
}

fn id_shape_matches(provider: &AccountProvider, id: &str) -> bool {
    id.chars().all(|c| c.is_ascii_digit())
        && match provider {
            AccountProvider::Discord => (17..=20).contains(&id.len()),
            AccountProvider::Roblox => (3..=12).contains(&id.len()),
        }
}

#[allow(clippy::too_many_arguments)]
fn merge_local_draft(
    drafts: &mut Vec<LocalAccountDraft>,
    provider: AccountProvider,
    id: String,
    username: Option<String>,
    display_name: Option<String>,
    path: &Path,
    label: &str,
    modified: Option<SystemTime>,
) {
    let source_path = format!("{}: {}", label, path.display());
    if let Some(existing) = drafts
        .iter_mut()
        .find(|draft| draft.provider == provider && draft.id == id)
    {
        if existing.username.is_none() {
            existing.username = username;
        }
        if existing.display_name.is_none() {
            existing.display_name = display_name;
        }
        existing.paths.insert(source_path);
        existing.newest_modified = newest_time(existing.newest_modified, modified);
        return;
    }
    let mut paths = BTreeSet::new();
    paths.insert(source_path);
    drafts.push(LocalAccountDraft {
        provider,
        id,
        username,
        display_name,
        profile_url: None,
        paths,
        newest_modified: modified,
    });
}

fn newest_time(a: Option<SystemTime>, b: Option<SystemTime>) -> Option<SystemTime> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn local_draft_to_account(draft: LocalAccountDraft) -> AccountIdentity {
    let username = draft.username.unwrap_or_else(|| draft.id.clone());
    let profile_url = match draft.provider {
        AccountProvider::Roblox => {
            Some(format!("https://www.roblox.com/users/{}/profile", draft.id))
        }
        AccountProvider::Discord => draft.profile_url,
    };
    let evidence = draft
        .paths
        .iter()
        .take(4)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    AccountIdentity {
        provider: draft.provider,
        id: draft.id,
        username,
        display_name: draft.display_name,
        profile_url,
        avatar_url: None,
        verified_at: draft
            .newest_modified
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(Utc::now),
        source: format!(
            "Local file scan (non-secret logs/config only): {}",
            evidence
        ),
        linked_accounts: Vec::new(),
    }
}

struct OAuthConfig {
    provider: AccountProvider,
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: String,
    state: String,
    code_verifier: Option<String>,
    auth_url: String,
}

impl OAuthConfig {
    fn for_provider(provider: AccountProvider) -> Result<Self, String> {
        let client_id = provider_env(&provider, "CLIENT_ID")?;
        let client_secret = provider_optional_env(&provider, "CLIENT_SECRET");
        let redirect_uri = redirect_uri(&provider);
        let state = random_hex_32();

        match provider {
            AccountProvider::Discord => {
                if client_secret.as_deref().unwrap_or_default().is_empty() {
                    return Err(
                        "Discord OAuth requires PRISM_DISCORD_CLIENT_SECRET or a broker-backed Discord app. Prism will not scrape local Discord tokens/cookies. Register redirect URI: http://127.0.0.1:53177/oauth/discord"
                            .to_string(),
                    );
                }
                let auth_url = format!(
                    "https://discord.com/oauth2/authorize?response_type=code&client_id={}&scope={}&state={}&redirect_uri={}&prompt=consent",
                    encode_query(&client_id),
                    encode_query("identify connections"),
                    encode_query(&state),
                    encode_query(&redirect_uri),
                );
                Ok(Self {
                    provider,
                    client_id,
                    client_secret,
                    redirect_uri,
                    state,
                    code_verifier: None,
                    auth_url,
                })
            }
            AccountProvider::Roblox => {
                let nonce = random_hex_32();
                let code_verifier = random_hex_32();
                let code_challenge = pkce_challenge(&code_verifier);
                let auth_url = format!(
                    "https://apis.roblox.com/oauth/v1/authorize?client_id={}&redirect_uri={}&scope={}&response_type=code&state={}&nonce={}&code_challenge={}&code_challenge_method=S256&prompt=select_account",
                    encode_query(&client_id),
                    encode_query(&redirect_uri),
                    encode_query("openid profile"),
                    encode_query(&state),
                    encode_query(&nonce),
                    encode_query(&code_challenge),
                );
                Ok(Self {
                    provider,
                    client_id,
                    client_secret,
                    redirect_uri,
                    state,
                    code_verifier: Some(code_verifier),
                    auth_url,
                })
            }
        }
    }
}

fn provider_env(provider: &AccountProvider, suffix: &str) -> Result<String, String> {
    let key = provider_env_key(provider, suffix);
    std::env::var(&key)
        .map(|v| v.trim().to_string())
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            format!(
                "{} is not configured. Set {} and register redirect URI {} before linking {} accounts.",
                key,
                key,
                redirect_uri(provider),
                provider.label()
            )
        })
}

fn provider_optional_env(provider: &AccountProvider, suffix: &str) -> Option<String> {
    std::env::var(provider_env_key(provider, suffix))
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn provider_env_key(provider: &AccountProvider, suffix: &str) -> String {
    format!(
        "PRISM_{}_{}",
        provider.as_str().to_ascii_uppercase(),
        suffix
    )
}

fn redirect_uri(provider: &AccountProvider) -> String {
    let port = std::env::var("PRISM_OAUTH_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(DEFAULT_CALLBACK_PORT);
    format!(
        "http://{}:{}{}",
        CALLBACK_HOST,
        port,
        provider.callback_path()
    )
}

struct CallbackListener {
    listener: TcpListener,
    provider: AccountProvider,
}

struct OAuthCallback {
    code: Option<String>,
    state: String,
}

impl CallbackListener {
    fn bind(provider: AccountProvider, redirect_uri: &str) -> Result<Self, String> {
        let addr = redirect_uri
            .strip_prefix("http://")
            .and_then(|rest| rest.split('/').next())
            .ok_or_else(|| format!("Unsupported redirect URI: {}", redirect_uri))?;
        let listener = TcpListener::bind(addr).map_err(|e| {
            format!(
                "Could not bind OAuth callback listener at {}: {}. Close any existing Prism auth flow or set PRISM_OAUTH_PORT to the registered callback port.",
                addr, e
            )
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("Could not configure OAuth callback listener: {}", e))?;
        Ok(Self { listener, provider })
    }

    fn wait(self) -> Result<OAuthCallback, String> {
        let deadline = Instant::now() + CALLBACK_TIMEOUT;
        loop {
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 8192];
                    let n = stream
                        .read(&mut buf)
                        .map_err(|e| format!("Could not read OAuth callback: {}", e))?;
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let first_line = request.lines().next().unwrap_or_default();
                    let result = parse_callback_request(first_line, &self.provider);
                    let body = callback_html(&result, &self.provider);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(), body
                    );
                    let _ = stream.write_all(response.as_bytes());
                    return result;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(format!(
                            "Timed out waiting for {} authorization callback",
                            self.provider
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(150));
                }
                Err(e) => {
                    return Err(format!("OAuth callback listener failed: {}", e));
                }
            }
        }
    }
}

fn parse_callback_request(
    first_line: &str,
    provider: &AccountProvider,
) -> Result<OAuthCallback, String> {
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    if method != "GET" || target.is_empty() {
        return Err("OAuth callback was not a GET request".to_string());
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != provider.callback_path() {
        return Err(format!(
            "Unexpected OAuth callback path: {} (expected {})",
            path,
            provider.callback_path()
        ));
    }
    let params = parse_query(query);
    if let Some(error) = params.get("error") {
        return Err(format!(
            "{} authorization failed: {}{}",
            provider,
            error,
            params
                .get("error_description")
                .map(|d| format!(" ({})", d))
                .unwrap_or_default()
        ));
    }
    let state = params
        .get("state")
        .cloned()
        .ok_or_else(|| "OAuth callback omitted state".to_string())?;
    Ok(OAuthCallback {
        code: params.get("code").cloned(),
        state,
    })
}

fn callback_html(result: &Result<OAuthCallback, String>, provider: &AccountProvider) -> String {
    let (title, message) = match result {
        Ok(_) => (
            format!("{} linked", provider),
            "Authorization received. You can return to Prism.".to_string(),
        ),
        Err(err) => (format!("{} link failed", provider), err.clone()),
    };
    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>{}</title><body style=\"font-family: system-ui; padding: 2rem;\"><h1>{}</h1><p>{}</p></body>",
        html_escape(&title),
        html_escape(&title),
        html_escape(&message)
    )
}

fn parse_query(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            Some((decode_query(key)?, decode_query(value)?))
        })
        .collect()
}

fn decode_query(value: &str) -> Option<String> {
    urlencoding::decode(value).ok().map(|v| v.into_owned())
}

fn encode_query(value: &str) -> String {
    urlencoding::encode(value).into_owned()
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn random_hex_32() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let mut bytes = [0u8; 32];
    for i in 0..4 {
        let mut h = RandomState::new().build_hasher();
        h.write_u64(i as u64);
        h.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        );
        h.write_usize(std::process::id() as usize);
        let v = h.finish();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&v.to_be_bytes());
    }
    hex::encode(Sha256::digest(bytes))
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    refresh_token: Option<String>,
    #[allow(dead_code)]
    token_type: Option<String>,
    #[allow(dead_code)]
    expires_in: Option<u64>,
    #[allow(dead_code)]
    scope: Option<String>,
}

#[derive(Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
    global_name: Option<String>,
    avatar: Option<String>,
}

#[derive(Deserialize)]
struct DiscordConnection {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    verified: bool,
}

#[derive(Deserialize)]
struct RobloxUserInfo {
    sub: String,
    name: Option<String>,
    nickname: Option<String>,
    preferred_username: Option<String>,
    profile: Option<String>,
    picture: Option<String>,
}

fn complete_discord(config: OAuthConfig, code: String) -> Result<AccountIdentity, String> {
    let secret = config
        .client_secret
        .as_deref()
        .ok_or_else(|| "Discord client secret missing".to_string())?;
    let client = http_client()?;
    let token: TokenResponse = post_form_json(
        &client,
        "https://discord.com/api/v10/oauth2/token",
        vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code),
            ("redirect_uri", config.redirect_uri.clone()),
            ("client_id", config.client_id.clone()),
            ("client_secret", secret.to_string()),
        ],
    )?;
    let user: DiscordUser = get_bearer_json(
        &client,
        "https://discord.com/api/v10/users/@me",
        &token.access_token,
    )?;
    let connections: Vec<DiscordConnection> = get_bearer_json(
        &client,
        "https://discord.com/api/v10/users/@me/connections",
        &token.access_token,
    )
    .unwrap_or_default();
    let linked_accounts = connections
        .into_iter()
        .filter(|connection| connection.kind == "roblox")
        .map(|connection| LinkedAccount {
            provider: connection.kind,
            id: connection.id,
            username: connection.name,
            verified: connection.verified,
        })
        .collect();
    let avatar_url = user.avatar.as_ref().map(|hash| {
        format!(
            "https://cdn.discordapp.com/avatars/{}/{}.png?size=128",
            user.id, hash
        )
    });

    Ok(AccountIdentity {
        provider: config.provider,
        id: user.id,
        username: user.username,
        display_name: user.global_name,
        profile_url: None,
        avatar_url,
        verified_at: Utc::now(),
        source: "Discord OAuth consent (identify connections)".to_string(),
        linked_accounts,
    })
}

fn complete_roblox(config: OAuthConfig, code: String) -> Result<AccountIdentity, String> {
    let client = http_client()?;
    let verifier = config
        .code_verifier
        .as_deref()
        .ok_or_else(|| "Roblox PKCE verifier missing".to_string())?;
    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code),
        ("redirect_uri", config.redirect_uri.clone()),
        ("client_id", config.client_id.clone()),
        ("code_verifier", verifier.to_string()),
    ];
    if let Some(secret) = config.client_secret.as_deref() {
        form.push(("client_secret", secret.to_string()));
    }
    let token: TokenResponse =
        post_form_json(&client, "https://apis.roblox.com/oauth/v1/token", form)?;
    let user: RobloxUserInfo = get_bearer_json(
        &client,
        "https://apis.roblox.com/oauth/v1/userinfo",
        &token.access_token,
    )?;
    let username = user
        .preferred_username
        .clone()
        .or(user.name.clone())
        .or(user.nickname.clone())
        .unwrap_or_else(|| user.sub.clone());

    Ok(AccountIdentity {
        provider: config.provider,
        id: user.sub,
        username,
        display_name: user.nickname.or(user.name),
        profile_url: user.profile,
        avatar_url: user.picture,
        verified_at: Utc::now(),
        source: "Roblox OAuth consent (openid profile)".to_string(),
        linked_accounts: Vec::new(),
    })
}

fn http_client() -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| format!("Could not create HTTP client: {}", e))
}

fn post_form_json<T: for<'de> Deserialize<'de>>(
    client: &Client,
    url: &str,
    form: Vec<(&str, String)>,
) -> Result<T, String> {
    let response = client
        .post(url)
        .form(&form)
        .send()
        .map_err(|e| format!("OAuth token request failed: {}", e))?;
    parse_json_response(response, "OAuth token request")
}

fn get_bearer_json<T: for<'de> Deserialize<'de>>(
    client: &Client,
    url: &str,
    access_token: &str,
) -> Result<T, String> {
    let response = client
        .get(url)
        .bearer_auth(access_token)
        .send()
        .map_err(|e| format!("OAuth user-info request failed: {}", e))?;
    parse_json_response(response, "OAuth user-info request")
}

fn parse_json_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::blocking::Response,
    context: &str,
) -> Result<T, String> {
    let status = response.status();
    let body = response
        .text()
        .map_err(|e| format!("{} returned unreadable response: {}", context, e))?;
    if !status.is_success() {
        return Err(format!(
            "{} failed with HTTP {}: {}",
            context,
            status.as_u16(),
            truncate_body(&body)
        ));
    }
    serde_json::from_str(&body).map_err(|e| {
        format!(
            "{} returned unexpected JSON: {} ({})",
            context,
            e,
            truncate_body(&body)
        )
    })
}

fn truncate_body(body: &str) -> String {
    const MAX: usize = 700;
    if body.len() <= MAX {
        body.to_string()
    } else {
        format!("{}…", &body[..MAX])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_account(provider: AccountProvider, id: &str, username: &str) -> AccountIdentity {
        AccountIdentity {
            provider,
            id: id.to_string(),
            username: username.to_string(),
            display_name: None,
            profile_url: None,
            avatar_url: None,
            verified_at: Utc::now(),
            source: "test".to_string(),
            linked_accounts: Vec::new(),
        }
    }

    #[test]
    fn account_store_dedupes_by_provider_and_id() {
        let store = AccountStore::default();
        store
            .add(test_account(AccountProvider::Discord, "1", "first"))
            .unwrap();
        store
            .add(test_account(AccountProvider::Discord, "1", "second"))
            .unwrap();
        let accounts = store.list().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].username, "second");
    }

    #[test]
    fn account_inventory_findings_are_clean_and_signed_report_friendly() {
        let findings = account_inventory_findings(&[test_account(
            AccountProvider::Roblox,
            "1516563360",
            "exampleuser",
        )]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].module, "account_inventory");
        assert_eq!(findings[0].verdict, ScanVerdict::Clean);
        assert!(findings[0]
            .description
            .contains("Verified account — Roblox"));
        assert!(findings[0]
            .details
            .as_deref()
            .unwrap()
            .contains("Account ID: 1516563360"));
    }

    #[test]
    fn local_line_scan_extracts_roblox_account_hint() {
        let mut drafts = Vec::new();
        collect_local_candidates(
            &mut drafts,
            &AccountProvider::Roblox,
            "2026 info username: EvPlayer\n2026 info userId: 1516563360\n",
            Path::new("/tmp/Roblox/logs/client.log"),
            "Roblox logs",
            None,
        );
        let accounts = drafts
            .into_iter()
            .map(local_draft_to_account)
            .collect::<Vec<_>>();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].provider, AccountProvider::Roblox);
        assert_eq!(accounts[0].id, "1516563360");
        assert_eq!(accounts[0].username, "EvPlayer");
        assert!(accounts[0].source.starts_with("Local file scan"));
    }

    #[test]
    fn local_scan_refuses_secret_bearing_storage_paths() {
        assert!(!is_safe_account_hint_file(Path::new(
            "/Users/ev/Library/Application Support/discord/Local Storage/leveldb/000003.log"
        )));
        assert!(!is_safe_account_hint_file(Path::new(
            "/Users/ev/Library/Application Support/discord/Cookies"
        )));
        assert!(is_safe_account_hint_file(Path::new(
            "/Users/ev/Library/Logs/Roblox/client.log"
        )));
    }

    #[test]
    fn parses_oauth_callback_query() {
        let parsed = parse_callback_request(
            "GET /oauth/roblox?code=abc&state=state%201 HTTP/1.1",
            &AccountProvider::Roblox,
        )
        .unwrap();
        assert_eq!(parsed.code.as_deref(), Some("abc"));
        assert_eq!(parsed.state, "state 1");
    }
}
