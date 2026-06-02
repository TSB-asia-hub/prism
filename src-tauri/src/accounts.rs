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
    /// True when `username` came from a structured account field (a JSON
    /// `Username` sitting next to a `UserId`), false when it was scraped
    /// from a loose log line. A structured name outranks a loose guess so
    /// the authoritative account-switcher entry wins over telemetry noise.
    username_trusted: bool,
    display_name: Option<String>,
    /// Same trust semantics as `username_trusted`, tracked independently:
    /// username and display name can be filled in from different files
    /// (one source may have a `Username` but no `DisplayName`), so a single
    /// shared flag would let a loose display fragment outlive a structured
    /// one.
    display_trusted: bool,
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
    // If the file is valid JSON, only walk it as JSON. Running the line
    // scanner on a single-line minified JSON blob (Roblox's appStorage.json
    // and friends are exactly that) produces nonsense usernames: the
    // ±3-line window collapses to the whole file, so it picks up the first
    // "username" substring anywhere in the document — typically inside an
    // unrelated URL-encoded telemetry blob — and pulls the surrounding
    // fragment as the value.
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(content) {
        collect_json_candidates(drafts, provider, &value, path, label, modified, 0);
        return;
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
                let username = json_string_field(obj, username_keys(provider))
                    .filter(|candidate| is_plausible_username(candidate, provider));
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
                )
                .filter(|candidate| is_plausible_display_name(candidate));
                merge_local_draft(
                    drafts,
                    provider.clone(),
                    id,
                    username,
                    display_name,
                    path,
                    label,
                    modified,
                    // A `Username`/`UserId` pair inside a JSON object is the
                    // real account record — trust it over any log-line guess.
                    true,
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
        // Each candidate gets validated against the provider's actual
        // username charset. Without this, telemetry/URL fragments
        // (`%3a"...","CharacterFetchUrl"...`, `sEnabled\":false`) end up
        // in the username slot because they happen to follow the word
        // "username" inside an embedded URL or stringified JSON value.
        let username = lines[window_start..window_end]
            .iter()
            .find_map(|candidate| local_line_username(candidate))
            .filter(|candidate| is_plausible_username(candidate, provider));
        // Display names get the same fragment guard as usernames: log lines
        // routinely embed URL-encoded JSON (`\"%3a\"Name\"%2c\"CharacterFetch
        // Url\"...`) right after a `DisplayName` keyword, and the UI prefers
        // the display name over the username — so an unvalidated fragment is
        // exactly what surfaced as a garbage pill.
        let display_name = lines[window_start..window_end]
            .iter()
            .find_map(|candidate| local_line_display_name(candidate))
            .filter(|candidate| is_plausible_display_name(candidate));
        merge_local_draft(
            drafts,
            provider.clone(),
            id,
            username,
            display_name,
            path,
            label,
            modified,
            // Loose log-line scrape: lower trust than a structured JSON field.
            false,
        );
    }
}

/// JSON keys that actually carry an account *username* for each provider.
/// Deliberately excludes the bare `Name`/`name` keys: countless unrelated
/// JSON objects (OS/browser context blobs like `{"name":"macOS"}`, place
/// and asset records, telemetry events) carry a `name`, and when one of
/// those happens to sit next to an id-shaped field the old code emitted it
/// as a logged-in account. Real account records always use `Username`.
fn username_keys(provider: &AccountProvider) -> &'static [&'static str] {
    match provider {
        AccountProvider::Roblox => &["Username", "username", "userName"],
        AccountProvider::Discord => &["username", "Username", "userName"],
    }
}

/// Reject obvious garbage before it lands in the display slot. Display
/// names are looser than usernames (spaces and non-ASCII letters are
/// legitimate), so this is a *blocklist*: it only rejects the structural,
/// escape, and URL-encoding characters that appear when we accidentally
/// captured a JSON or URL fragment instead of a real name. Anything that
/// reads like a name — including Unicode display names — is kept.
fn is_plausible_display_name(value: &str) -> bool {
    let trimmed = value.trim();
    let count = trimmed.chars().count();
    if !(1..=40).contains(&count) {
        return false;
    }
    // A real name has at least one letter or digit; pure punctuation is a
    // fragment, not a display name.
    if !trimmed.chars().any(|c| c.is_alphanumeric()) {
        return false;
    }
    // These only show up when the captured value is really a slice of
    // serialized JSON or a percent-encoded URL.
    const BLOCKED: &[char] = &[
        '\\', '"', '%', '{', '}', '[', ']', '=', '<', '>', '|', '`',
    ];
    !trimmed
        .chars()
        .any(|c| BLOCKED.contains(&c) || c.is_control())
}

/// Reject obvious garbage before it lands in the username slot. Both
/// providers have well-known character constraints; if the candidate
/// can't even be a real username we'd rather show the resolved name
/// from the public API (Roblox) or just the numeric ID than a fragment
/// of URL-encoded JSON.
fn is_plausible_username(value: &str, provider: &AccountProvider) -> bool {
    let trimmed = value.trim();
    let count = trimmed.chars().count();
    match provider {
        // Roblox: 3–20 alphanumeric + underscore in current rules; legacy
        // names sometimes include extra characters but never `%`, `\`, `"`,
        // `:`, etc. — we keep the length bound a touch wider than canonical
        // (32) since the line scanner already trimmed punctuation.
        AccountProvider::Roblox => {
            (3..=32).contains(&count)
                && trimmed
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        // Discord: modern usernames are lowercase letters + digits + dot +
        // underscore; legacy usernames also allowed mixed case. Either
        // way, no JSON or URL syntax characters.
        AccountProvider::Discord => {
            (2..=32).contains(&count)
                && trimmed
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
        }
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
        // Strong user-id keys only. Bare `Id`/`id` is intentionally absent:
        // Roblox JSON is full of 3–12 digit place/asset/game ids that would
        // otherwise be read as user ids and then "resolved" by the public
        // users API into a real but unrelated person.
        AccountProvider::Roblox => &[
            "UserId",
            "userId",
            "userID",
            "user_id",
            "userid",
            "accountId",
            "AccountId",
            "accountid",
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
        .filter_map(|key| find_keyword(&lower, key).map(|idx| (idx, key.len())))
        .min_by_key(|(idx, _)| *idx)?;
    // Take the digit run that immediately follows the key (after the usual
    // `:`/`=`/quote separators) rather than the first shape-matching run
    // anywhere in the line. On a minified single-line blob the old "first
    // run anywhere" rule let a `UserId` substring pair with an unrelated
    // number thousands of characters away.
    let tail = &line[key_match.0 + key_match.1..];
    let digits = leading_id_digits(tail);
    id_shape_matches(provider, &digits).then_some(digits)
}

/// Find `key` inside an already-lowercased line, but only at an identifier
/// boundary, so `userid` does not match inside `debuguserid` /
/// `browseruserid` / `useridentifier`. The byte before must not be an ASCII
/// letter or digit and the byte after must not be an ASCII letter.
fn find_keyword(haystack_lower: &str, key: &str) -> Option<usize> {
    let bytes = haystack_lower.as_bytes();
    let mut from = 0;
    while let Some(rel) = haystack_lower[from..].find(key) {
        let idx = from + rel;
        let before_ok = idx == 0 || !bytes[idx - 1].is_ascii_alphanumeric();
        let after = idx + key.len();
        let after_ok = after >= bytes.len() || !bytes[after].is_ascii_alphabetic();
        if before_ok && after_ok {
            return Some(idx);
        }
        from = idx + 1;
    }
    None
}

fn leading_id_digits(tail: &str) -> String {
    tail.trim_start_matches(|c: char| {
        c.is_whitespace() || matches!(c, ':' | '=' | '-' | '>' | '"' | '\'' | '(' | ')' | '#')
    })
    .chars()
    .take_while(|c| c.is_ascii_digit())
    .collect()
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
    let (start_idx, key) = keys
        .iter()
        .filter_map(|key| find_keyword(&lower, key).map(|idx| (idx, *key)))
        .min_by_key(|(idx, _)| *idx)?;
    let start = start_idx + key.len();
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

fn id_shape_matches(provider: &AccountProvider, id: &str) -> bool {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // Real Roblox UserIds and Discord snowflakes are positive decimal
    // integers with no leading zero. Rejecting a leading zero drops padded
    // counters / sentinels (`000000`, `0123`) that the line scanner pairs
    // with a stray `UserId` substring inside a minified blob, without ever
    // risking a real id (which is a plain decimal integer).
    if id.as_bytes()[0] == b'0' {
        return false;
    }
    match provider {
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
    trusted: bool,
) {
    let source_path = format!("{}: {}", label, path.display());
    if let Some(existing) = drafts
        .iter_mut()
        .find(|draft| draft.provider == provider && draft.id == id)
    {
        // Take the incoming username/display when it fills an empty slot, or
        // when it is a structured (trusted) value replacing a loose log-line
        // guess. This keeps the appStorage account-switcher entry from being
        // clobbered by a plausible-but-wrong token harvested from a log.
        if username.is_some()
            && (existing.username.is_none() || (trusted && !existing.username_trusted))
        {
            existing.username = username;
            existing.username_trusted = trusted;
        }
        if display_name.is_some()
            && (existing.display_name.is_none() || (trusted && !existing.display_trusted))
        {
            existing.display_name = display_name;
            existing.display_trusted = trusted;
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
        username_trusted: trusted,
        display_name,
        display_trusted: trusted,
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
    fn is_plausible_username_rejects_garbage_but_keeps_alphanumerics() {
        // The four shapes observed in the v0.12.1 bad-pill screenshot.
        // None of them can be a real username; all of them previously
        // landed in the pill list because the line scanner pulled the
        // fragment after a "username" keyword inside URL-encoded JSON.
        assert!(!is_plausible_username(
            "%3a'PurpleBerY\"%2c\"CharacterFe",
            &AccountProvider::Roblox
        ));
        assert!(!is_plausible_username(
            "sEnabled\\\":false (@s\\\":true)",
            &AccountProvider::Roblox
        ));
        assert!(!is_plausible_username("a", &AccountProvider::Roblox));
        assert!(!is_plausible_username("ab", &AccountProvider::Roblox));
        assert!(!is_plausible_username(&"x".repeat(64), &AccountProvider::Roblox));
        // Real-looking usernames stay.
        assert!(is_plausible_username("PUBY270", &AccountProvider::Roblox));
        assert!(is_plausible_username("EvelynStarRadio", &AccountProvider::Roblox));
        assert!(is_plausible_username(
            "Underscore_Alt",
            &AccountProvider::Roblox
        ));
        assert!(is_plausible_username("ev.cookies", &AccountProvider::Discord));
        assert!(is_plausible_username("evelyn", &AccountProvider::Discord));
    }

    #[test]
    fn line_scanner_does_not_run_on_valid_json_files() {
        // Crafted to trip the line scanner if it ran: the same string has
        // a `userid:<digits>` substring that would yield a draft and a
        // `username:<garbage>` fragment with characters that are not in
        // the validator's charset. If the line scanner runs, we'd get one
        // bad draft with the URL-encoded mess as the username. With the
        // JSON-only short-circuit, only the clean JSON walker draft
        // survives.
        let json = r#"{"AccountList":{"trailing":{"userid":1234567890,"username":"%3aEv%22"}, "LoginUser_1234567890":"{\"UserId\":1234567890,\"Username\":\"EvelynStarRadio\"}"}}"#;
        let mut drafts = Vec::new();
        collect_local_candidates(
            &mut drafts,
            &AccountProvider::Roblox,
            json,
            Path::new("/tmp/Roblox/LocalStorage/appStorage.json"),
            "Roblox app storage",
            None,
        );
        let accounts = drafts
            .into_iter()
            .map(local_draft_to_account)
            .collect::<Vec<_>>();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, "1234567890");
        assert_eq!(accounts[0].username, "EvelynStarRadio");
    }

    #[test]
    fn display_name_validation_rejects_json_url_fragments() {
        // The exact display fragments the Roblox Player log line scanner
        // captured after a `DisplayName`/`UserName` keyword — these reached
        // the UI as garbage pills because the display slot was never
        // validated and the label prefers display over username.
        assert!(!is_plausible_display_name(
            "\\\"%3a\\\"EvelynStarRadio\\\"%2c\\\"CharacterFetchUrl"
        ));
        assert!(!is_plausible_display_name("sEnabled\\\":true"));
        assert!(!is_plausible_display_name("s\\\":true"));
        assert!(!is_plausible_display_name("")); // empty
        assert!(!is_plausible_display_name("   ")); // whitespace only
        assert!(!is_plausible_display_name(":)")); // pure punctuation, no alnum
        assert!(!is_plausible_display_name(&"x".repeat(41))); // too long
        // Legitimate display names — including spaces and non-ASCII — stay.
        assert!(is_plausible_display_name("EvelynStarRadio"));
        assert!(is_plausible_display_name("Alt One"));
        assert!(is_plausible_display_name("Foo Bar"));
        assert!(is_plausible_display_name("さくら"));
        assert!(is_plausible_display_name("O'Brien"));
    }

    #[test]
    fn id_shape_rejects_leading_zero_padding() {
        // `000000` is what the line scanner paired with a `DebugUserId`
        // substring inside the minified memProfStorage blob.
        assert!(!id_shape_matches(&AccountProvider::Roblox, "000000"));
        assert!(!id_shape_matches(&AccountProvider::Roblox, "0"));
        assert!(!id_shape_matches(&AccountProvider::Roblox, "0123456"));
        assert!(!id_shape_matches(&AccountProvider::Roblox, ""));
        assert!(!id_shape_matches(&AccountProvider::Roblox, "12")); // too short
        // Real ids — including repeated-digit placeholders used elsewhere in
        // these tests — still pass.
        assert!(id_shape_matches(&AccountProvider::Roblox, "4715965346"));
        assert!(id_shape_matches(&AccountProvider::Roblox, "1111111111"));
        assert!(id_shape_matches(&AccountProvider::Discord, "904287580865048597"));
        assert!(!id_shape_matches(&AccountProvider::Discord, "0904287580865048")); // leading zero
    }

    #[test]
    fn json_walk_ignores_generic_name_and_bare_id_objects() {
        // Negative test: objects that share the {id, name} / {id,
        // displayName} shape with an account but are NOT accounts — a place
        // record, an OS-context blob, an asset with a token-shaped name.
        // None of these may produce a logged-in-account pill.
        let json = r#"{
            "places": [{"id": 1818, "name": "Crossroads"}],
            "context": {"os": {"id": 12345, "name": "macOS"}},
            "asset": {"Id": 987654, "displayName": "Jacob", "name": "2h1gh4Uatm"}
        }"#;
        let mut drafts = Vec::new();
        collect_local_candidates(
            &mut drafts,
            &AccountProvider::Roblox,
            json,
            Path::new("/tmp/Roblox/LocalStorage/appStorage.json"),
            "Roblox app storage",
            None,
        );
        assert!(
            drafts.is_empty(),
            "generic id+name objects must not become accounts, got: {:?}",
            drafts.iter().map(|d| (&d.id, &d.username)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn line_scanner_ignores_debug_userid_substring() {
        // `DebugUserId":"0"` must not match the bare `userid` key, and the
        // immediate-token rule must not pair the key with a far-away digit
        // run. A real `userid:<id>` on the same line still resolves.
        assert_eq!(
            local_line_account_id(
                &AccountProvider::Roblox,
                r#""DebugUserId":"0","Counter":"000000""#
            ),
            None
        );
        assert_eq!(
            local_line_account_id(
                &AccountProvider::Roblox,
                "ateGame, placeid:10449761463, userid:4715965346"
            )
            .as_deref(),
            Some("4715965346")
        );
    }

    #[test]
    fn structured_username_outranks_loose_log_guess() {
        // A loose log line scrapes a plausible-but-wrong token first; the
        // structured appStorage entry seen afterwards must win.
        let mut drafts = Vec::new();
        merge_local_draft(
            &mut drafts,
            AccountProvider::Roblox,
            "4715965346".into(),
            Some("looseGuess".into()),
            Some("Loose Display".into()),
            Path::new("/tmp/Roblox/logs/client.log"),
            "Roblox logs",
            None,
            false, // untrusted (line scanner)
        );
        merge_local_draft(
            &mut drafts,
            AccountProvider::Roblox,
            "4715965346".into(),
            Some("EvelynStarRadio".into()),
            Some("Evelyn Star".into()),
            Path::new("/tmp/Roblox/LocalStorage/appStorage.json"),
            "Roblox app storage",
            None,
            true, // trusted (structured JSON)
        );
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].username.as_deref(), Some("EvelynStarRadio"));
        // Display name must upgrade to the trusted value too, not stay stuck
        // on the loose log-line guess that landed first.
        assert_eq!(drafts[0].display_name.as_deref(), Some("Evelyn Star"));
        // And the reverse order must not let the loose guess clobber it.
        let mut drafts = Vec::new();
        merge_local_draft(
            &mut drafts,
            AccountProvider::Roblox,
            "4715965346".into(),
            Some("EvelynStarRadio".into()),
            None,
            Path::new("/tmp/Roblox/LocalStorage/appStorage.json"),
            "Roblox app storage",
            None,
            true,
        );
        merge_local_draft(
            &mut drafts,
            AccountProvider::Roblox,
            "4715965346".into(),
            Some("looseGuess".into()),
            None,
            Path::new("/tmp/Roblox/logs/client.log"),
            "Roblox logs",
            None,
            false,
        );
        assert_eq!(drafts[0].username.as_deref(), Some("EvelynStarRadio"));
    }

    #[test]
    fn garbage_display_does_not_survive_into_label() {
        // End-to-end: a Player-log line with a clean username but a
        // URL-encoded display fragment must yield a pill labelled with the
        // username only — never the fragment.
        let line = r#"ticket={\"UserId\"%3a4715965346%2c\"UserName\"%3a\"EvelynStarRadio\"%2c\"DisplayName\"%3a\"%3a\"EvelynStarRadio\"%2c\"CharacterFetchUrl\"%3ahttps"#;
        let mut drafts = Vec::new();
        collect_local_candidates(
            &mut drafts,
            &AccountProvider::Roblox,
            &format!("userid:4715965346\n{line}\n"),
            Path::new("/tmp/Roblox/logs/0.721_Player.log"),
            "Roblox logs",
            None,
        );
        let accounts = drafts
            .into_iter()
            .map(local_draft_to_account)
            .collect::<Vec<_>>();
        assert_eq!(accounts.len(), 1);
        let label = account_label(&accounts[0]);
        assert!(
            !label.contains('%') && !label.contains('\\') && !label.contains('"'),
            "label leaked a fragment: {label:?}"
        );
    }

    #[test]
    fn screenshot_garbage_fragments_are_rejected_from_roblox_pills() {
        // Regression for the bad UI pill:
        // `ROBLOX sEnabled\\\":false (@s\\\":true)`. A nearby UserId may
        // still be useful, but escaped JSON fragments are never account names.
        let mut drafts = Vec::new();
        collect_local_candidates(
            &mut drafts,
            &AccountProvider::Roblox,
            "displayName: sEnabled\\\":false\nusername: s\\\":true\nuserId: 4715965346\n",
            Path::new("/tmp/Roblox/logs/0.721_Player.log"),
            "Roblox logs",
            None,
        );
        let accounts = drafts
            .into_iter()
            .map(local_draft_to_account)
            .collect::<Vec<_>>();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].username, "4715965346");
        assert_eq!(accounts[0].display_name, None);
        let label = account_label(&accounts[0]);
        assert!(!label.contains("sEnabled") && !label.contains("@s"));
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
