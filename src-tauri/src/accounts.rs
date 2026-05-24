use chrono::{DateTime, Utc};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use walkdir::WalkDir;

use crate::models::{ScanFinding, ScanVerdict};

const USER_AGENT: &str = concat!("Prism/", env!("CARGO_PKG_VERSION"), " account-inventory");

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AccountProvider {
    Discord,
    Roblox,
}

impl AccountProvider {
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
}

impl fmt::Display for AccountProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Kept as part of the public report schema for backwards compatibility
/// with already-exported reports. Always empty after the OAuth flow was
/// removed in v0.12.0 — the alt finder now relies on local non-secret
/// state, which doesn't expose cross-platform linkings.
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
        // Prefer the entry that has a real username over one where username
        // still equals the numeric ID (which happens when the local-file
        // walker found an ID but no surrounding name field). Otherwise the
        // newest observation wins.
        let existing_resolved = existing.username != existing.id && !existing.username.is_empty();
        let incoming_resolved = account.username != account.id && !account.username.is_empty();
        if existing_resolved && !incoming_resolved {
            return;
        }
        if (incoming_resolved && !existing_resolved) || account.verified_at > existing.verified_at {
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
pub async fn verified_accounts(
    store: tauri::State<'_, AccountStore>,
) -> Result<Vec<AccountIdentity>, String> {
    store.list()
}

#[tauri::command]
pub async fn clear_verified_accounts(store: tauri::State<'_, AccountStore>) -> Result<(), String> {
    store.clear()
}

pub fn account_inventory(accounts: &AccountStore) -> Vec<AccountIdentity> {
    // Pull the stored copy first so previously-resolved usernames act as
    // an enrichment cache: a fresh-discovered raw entry (username == id)
    // gets overwritten by its resolved counterpart via upsert_account.
    // This is what keeps the second `account_inventory` call inside the
    // same scan (partial → final) from re-hitting users.roblox.com.
    let mut merged = accounts.list().unwrap_or_default();
    for account in discover_local_accounts() {
        upsert_account(&mut merged, account);
    }
    // Best-effort, capped: resolve Roblox numeric IDs to usernames via the
    // unauthenticated public users API. Never touches an auth cookie or a
    // session token — it just turns a UserId into a profile name. The 30s
    // deadline inside enrich_roblox_accounts means even a large logged-in
    // history can't park the scan.
    enrich_roblox_accounts(&mut merged);
    // Persist enriched data back to the store so the next call (final
    // report emit, or another scan in this session) sees the resolved
    // usernames cached.
    let _ = accounts.add_many(merged.clone());
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
                format!("Observed at: {}", account.verified_at.to_rfc3339()),
                format!("Source: {}", account.source),
            ];
            if let Some(display_name) = account.display_name.as_deref().filter(|s| !s.is_empty()) {
                detail_parts.push(format!("Display: {}", display_name));
            }
            if let Some(profile_url) = account.profile_url.as_deref().filter(|s| !s.is_empty()) {
                detail_parts.push(format!("Profile: {}", profile_url));
            }

            ScanFinding::new(
                "account_inventory",
                ScanVerdict::Clean,
                format!(
                    "Logged-in account — {}: {}",
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
const MAX_NESTED_JSON_DEPTH: usize = 8;

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
            let local_app_data = PathBuf::from(local_app_data);
            roots.push(LocalAccountRoot {
                provider: AccountProvider::Roblox,
                path: local_app_data.join("Roblox").join("logs"),
                label: "Roblox logs",
            });
            roots.push(LocalAccountRoot {
                provider: AccountProvider::Roblox,
                path: local_app_data.join("Roblox").join("LocalStorage"),
                label: "Roblox app storage",
            });
            roots.push(LocalAccountRoot {
                provider: AccountProvider::Roblox,
                path: local_app_data.join("Bloxstrap"),
                label: "Bloxstrap state",
            });
            roots.push(LocalAccountRoot {
                provider: AccountProvider::Roblox,
                path: local_app_data.join("Fishstrap"),
                label: "Fishstrap state",
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
            let roblox_support = home.join("Library").join("Application Support").join("Roblox");
            roots.push(LocalAccountRoot {
                provider: AccountProvider::Roblox,
                path: roblox_support.join("logs"),
                label: "Roblox logs",
            });
            // Native Roblox player on macOS stores account-switcher state
            // (PreviousAccountsList, per-account UserId/Username/DisplayName)
            // at ~/Library/Roblox/LocalStorage/appStorage.json. The Electron-
            // style player's data under ~/Library/Application Support/Roblox/
            // "Local Storage" (with a space) is LevelDB and intentionally
            // refused by is_safe_account_hint_file.
            let roblox_native = home.join("Library").join("Roblox");
            roots.push(LocalAccountRoot {
                provider: AccountProvider::Roblox,
                path: roblox_native.join("LocalStorage"),
                label: "Roblox app storage",
            });
            roots.push(LocalAccountRoot {
                provider: AccountProvider::Roblox,
                path: roblox_native.join("logs"),
                label: "Roblox logs",
            });
            roots.push(LocalAccountRoot {
                provider: AccountProvider::Roblox,
                path: roblox_support.join("LocalStorage"),
                label: "Roblox app storage",
            });
            roots.push(LocalAccountRoot {
                provider: AccountProvider::Roblox,
                path: home.join("Library").join("Logs").join("Roblox"),
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
    // Explicitly avoid browser/Electron secret-bearing stores. The alt
    // finder only reads human-readable logs/config snapshots where account
    // IDs appear as ordinary telemetry context; no cookie DBs, browser
    // Local Storage LevelDB (note the space — distinct from Roblox's
    // `LocalStorage` directory, which is plain JSON), or encrypted
    // credential stores are touched. If you're tempted to relax this,
    // re-read CLAUDE.md — Prism ships to players, not just to staff.
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
        collect_json_candidates(drafts, provider, &value, path, label, modified, 0);
    }
    collect_line_candidates(drafts, provider, content, path, label, modified);
}

#[allow(clippy::too_many_arguments)]
fn collect_json_candidates(
    drafts: &mut Vec<LocalAccountDraft>,
    provider: &AccountProvider,
    value: &serde_json::Value,
    path: &Path,
    label: &str,
    modified: Option<SystemTime>,
    depth: usize,
) {
    match value {
        serde_json::Value::Object(obj) => {
            if let Some(id) = json_account_id(provider, obj) {
                let username = json_string_field(
                    obj,
                    &["Username", "username", "userName", "Name", "name"],
                );
                let display_name = json_string_field(
                    obj,
                    &[
                        "DisplayName",
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
                collect_json_candidates(drafts, provider, child, path, label, modified, depth + 1);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                collect_json_candidates(drafts, provider, child, path, label, modified, depth + 1);
            }
        }
        // Roblox's appStorage.json stores per-account state as keys whose
        // values are stringified JSON blobs (e.g. `LoginUser_<id>` →
        // `"{\"UserId\":...,\"Username\":\"...\"}"`). Treating strings that
        // look like JSON as another layer to walk recovers those entries
        // without a special-case parser.
        serde_json::Value::String(s) if depth < MAX_NESTED_JSON_DEPTH && looks_like_json(s) => {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(s) {
                collect_json_candidates(
                    drafts,
                    provider,
                    &parsed,
                    path,
                    label,
                    modified,
                    depth + 1,
                );
            }
        }
        _ => {}
    }
}

fn looks_like_json(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.len() < 2 {
        return false;
    }
    let bytes = trimmed.as_bytes();
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    (first == b'{' && last == b'}') || (first == b'[' && last == b']')
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
        AccountProvider::Discord => &[
            "id",
            "user_id",
            "userId",
            "userID",
            "currentUserId",
            "current_user_id",
        ],
        AccountProvider::Roblox => &[
            "UserId",
            "userId",
            "user_id",
            "userid",
            "Id",
            "id",
            "accountId",
            "AccountId",
        ],
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

#[derive(Deserialize)]
struct RobloxPublicUser {
    name: String,
    #[serde(default, rename = "displayName")]
    display_name: String,
}

fn enrich_roblox_accounts(accounts: &mut [AccountIdentity]) {
    let needs_enrichment: Vec<usize> = accounts
        .iter()
        .enumerate()
        .filter(|(_, account)| {
            account.provider == AccountProvider::Roblox
                && (account.username == account.id || account.username.is_empty())
        })
        .map(|(idx, _)| idx)
        .collect();
    if needs_enrichment.is_empty() {
        return;
    }
    let Ok(client) = enrichment_client() else {
        return;
    };
    // Overall budget so a large account-switcher history (or a flaky
    // network) can't park the scanner. Each individual request is also
    // capped at 6s inside `enrichment_client`.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    for idx in needs_enrichment {
        if std::time::Instant::now() >= deadline {
            break;
        }
        let id = accounts[idx].id.clone();
        let Ok(info) = fetch_roblox_public_user(&client, &id) else {
            continue;
        };
        if !info.name.is_empty() {
            accounts[idx].username = info.name;
        }
        if accounts[idx].display_name.is_none() && !info.display_name.is_empty() {
            accounts[idx].display_name = Some(info.display_name);
        }
    }
}

fn enrichment_client() -> Result<Client, String> {
    Client::builder()
        // Short, capped timeout so a flaky network can't park the
        // local-files scan. Enrichment is best-effort — if it fails we
        // still ship raw IDs.
        .timeout(Duration::from_secs(6))
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| format!("Could not create enrichment HTTP client: {}", e))
}

fn fetch_roblox_public_user(client: &Client, id: &str) -> Result<RobloxPublicUser, String> {
    // Unauthenticated public endpoint — does not require a cookie or any
    // session token. Returns just { name, displayName, description, ... }
    // for the supplied numeric ID.
    let url = format!("https://users.roblox.com/v1/users/{}", id);
    let response = client
        .get(url)
        .send()
        .map_err(|e| format!("Roblox user lookup failed: {}", e))?;
    if !response.status().is_success() {
        return Err(format!(
            "Roblox user lookup returned HTTP {}",
            response.status().as_u16()
        ));
    }
    response
        .json::<RobloxPublicUser>()
        .map_err(|e| format!("Roblox user lookup returned unexpected JSON: {}", e))
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
            .add_many(vec![test_account(AccountProvider::Discord, "1", "first")])
            .unwrap();
        store
            .add_many(vec![test_account(AccountProvider::Discord, "1", "second")])
            .unwrap();
        let accounts = store.list().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].username, "second");
    }

    #[test]
    fn account_store_prefers_resolved_username_over_numeric_id() {
        let store = AccountStore::default();
        let mut numeric = test_account(AccountProvider::Roblox, "1516563360", "1516563360");
        // Older timestamp than the resolved one — without the resolved-wins
        // rule the numeric placeholder would survive and the UI would show
        // a userId where a name should be.
        numeric.verified_at = "2026-05-24T10:00:00Z".parse().unwrap();
        store.add_many(vec![numeric]).unwrap();
        let mut resolved = test_account(AccountProvider::Roblox, "1516563360", "EvPlayer");
        resolved.verified_at = "2026-05-24T09:00:00Z".parse().unwrap();
        store.add_many(vec![resolved]).unwrap();
        assert_eq!(store.list().unwrap()[0].username, "EvPlayer");
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
            .contains("Logged-in account — Roblox"));
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
    fn roblox_app_storage_extracts_logged_in_users_from_stringified_json() {
        // appStorage.json keeps per-account state as values that are themselves
        // JSON-encoded strings — this regresses if the walker ever stops
        // recursing into stringified-JSON values.
        let content = r#"{
            "BrowserTrackerId": "ignored",
            "LoginUser_1234567890": "{\"UserId\":1234567890,\"Username\":\"foo\",\"DisplayName\":\"Foo Bar\"}",
            "MultipleLoginUser": "[{\"UserId\":1111111111,\"Username\":\"alt_one\",\"DisplayName\":\"Alt One\"},{\"UserId\":2222222222,\"Username\":\"alt_two\"}]"
        }"#;
        let mut drafts = Vec::new();
        collect_local_candidates(
            &mut drafts,
            &AccountProvider::Roblox,
            content,
            Path::new("/tmp/Roblox/LocalStorage/appStorage.json"),
            "Roblox app storage",
            None,
        );
        let accounts = drafts
            .into_iter()
            .map(local_draft_to_account)
            .collect::<Vec<_>>();
        let by_id: std::collections::BTreeMap<_, _> =
            accounts.iter().map(|a| (a.id.clone(), a)).collect();
        assert_eq!(by_id.len(), 3);
        assert_eq!(by_id["1234567890"].username, "foo");
        assert_eq!(
            by_id["1234567890"].display_name.as_deref(),
            Some("Foo Bar")
        );
        assert_eq!(by_id["1111111111"].username, "alt_one");
        assert_eq!(by_id["2222222222"].username, "alt_two");
    }

    #[test]
    fn roblox_previous_accounts_list_finds_each_logged_in_user() {
        // Mirrors the actual shape inside ~/Library/Roblox/LocalStorage/appStorage.json
        // on macOS: a stringified JSON object whose outer keys are user IDs
        // and whose values carry the canonical userId/username/displayName
        // triple. Earlier v0.12.0 builds shipped without the
        // ~/Library/Roblox root path AND without a test pinning this exact
        // schema, which is why "no logged-in accounts found" reproduced.
        let content = r#"{
            "AccountBlob": "",
            "PreviousAccountsList": "{\"4715965346\":{\"username\":\"EvelynStarRadio\",\"userId\":\"4715965346\",\"displayName\":\"EvelynStarRadio\"},\"8936002538\":{\"username\":\"AltOne\",\"userId\":\"8936002538\",\"displayName\":\"Alt One\"}}"
        }"#;
        let mut drafts = Vec::new();
        collect_local_candidates(
            &mut drafts,
            &AccountProvider::Roblox,
            content,
            Path::new("/tmp/Roblox/LocalStorage/appStorage.json"),
            "Roblox app storage",
            None,
        );
        let by_id: std::collections::BTreeMap<_, _> = drafts
            .into_iter()
            .map(local_draft_to_account)
            .map(|a| (a.id.clone(), a))
            .collect();
        assert_eq!(by_id.len(), 2);
        assert_eq!(by_id["4715965346"].username, "EvelynStarRadio");
        assert_eq!(
            by_id["4715965346"].display_name.as_deref(),
            Some("EvelynStarRadio")
        );
        assert_eq!(by_id["8936002538"].username, "AltOne");
        assert_eq!(by_id["8936002538"].display_name.as_deref(), Some("Alt One"));
    }

    #[test]
    fn local_scan_refuses_secret_bearing_storage_paths() {
        assert!(!is_safe_account_hint_file(Path::new(
            "/Users/ev/Library/Application Support/discord/Local Storage/leveldb/000003.log"
        )));
        assert!(!is_safe_account_hint_file(Path::new(
            "/Users/ev/Library/Application Support/discord/Cookies"
        )));
        // Roblox's LocalStorage (no space) is plain JSON and intentionally
        // allowed — the blocked match is the spaced "Local Storage".
        assert!(is_safe_account_hint_file(Path::new(
            "/Users/ev/Library/Application Support/Roblox/LocalStorage/appStorage.json"
        )));
        assert!(is_safe_account_hint_file(Path::new(
            "/Users/ev/Library/Logs/Roblox/client.log"
        )));
    }

    #[test]
    fn looks_like_json_only_matches_objects_and_arrays() {
        assert!(looks_like_json("{\"a\":1}"));
        assert!(looks_like_json("[1,2,3]"));
        assert!(looks_like_json("  { \"a\": 1 } "));
        assert!(!looks_like_json("plain string"));
        assert!(!looks_like_json("12345"));
        assert!(!looks_like_json("{ unterminated"));
    }
}
