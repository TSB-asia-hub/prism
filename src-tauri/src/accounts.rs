use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
        let mut accounts = self
            .0
            .lock()
            .map_err(|_| "Account store lock poisoned".to_string())?;
        if let Some(existing) = accounts
            .iter_mut()
            .find(|a| a.provider == account.provider && a.id == account.id)
        {
            *existing = account;
        } else {
            accounts.push(account);
        }
        accounts.sort_by(|a, b| {
            a.provider
                .as_str()
                .cmp(b.provider.as_str())
                .then_with(|| a.username.to_lowercase().cmp(&b.username.to_lowercase()))
                .then_with(|| a.id.cmp(&b.id))
        });
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

            ScanFinding::new(
                "account_inventory",
                ScanVerdict::Clean,
                format!(
                    "Verified {} account: {}",
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
        assert!(findings[0].description.contains("Verified Roblox account"));
        assert!(findings[0]
            .details
            .as_deref()
            .unwrap()
            .contains("Account ID: 1516563360"));
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
