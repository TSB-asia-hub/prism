use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use tauri::Emitter;

use crate::accounts::{account_inventory_findings, AccountStore};
use crate::models::{ScanFinding, ScanReport};
use crate::reports::report_generator;
use crate::scanners;
use crate::scanners::progress::{CancelToken, ScanProgress};

/// Wire-format payload returned by `import_report`. Carries the parsed
/// report plus enough provenance metadata for the UI to surface a clear
/// "this is an imported file, not a live scan" banner. The frontend gets
/// the report unconditionally even when the signature/freshness check
/// fails — refusing to display old reports would prevent legitimate
/// review of historical scan output, which is one of the main reasons
/// import exists.
#[derive(Serialize)]
pub struct ImportedReport {
    pub report: ScanReport,
    pub signature_valid: bool,
    /// Age in seconds (negative if the report's timestamp is in the future).
    pub age_seconds: i64,
    /// True when `age_seconds` exceeds the validator's freshness window.
    pub stale: bool,
    /// Absolute path of the file the user picked. Surfaced so the operator
    /// can confirm which file is on screen.
    pub source_path: String,
}

/// Run all scanners and generate a signed scan report. The signed report is
/// returned to the frontend for display only — when the user exports, the
/// backend re-runs scanners rather than trusting the frontend copy (see
/// `save_report`). Progress events fire on the `scan-progress` topic so the
/// frontend can show per-scanner state live instead of a fake carousel.
///
/// `cancel` is the shared `CancelToken` from Tauri state — we reset it to
/// false at the start of every run so a previous Stop-button press doesn't
/// abort the next scan, and the Tauri command `cancel_scan` flips it back
/// to true to make the running scanners bail.
#[tauri::command]
pub async fn run_scan(
    app: tauri::AppHandle,
    cancel: tauri::State<'_, CancelToken>,
    accounts: tauri::State<'_, AccountStore>,
) -> Result<ScanReport, String> {
    cancel.reset();
    let reporter = ScanProgress::new(app.clone(), cancel.inner().clone());
    let account_store = accounts.inner().clone();
    let partial_account_store = account_store.clone();
    let findings = scanners::run_all_scans_with_partial_progress(reporter, move |findings| {
        let partial_report = report_generator::generate_report(with_account_inventory(
            findings,
            &partial_account_store,
        ));
        let _ = app.emit("scan-report-partial", partial_report);
    })
    .await;
    let report =
        report_generator::generate_report(with_account_inventory(findings, &account_store));
    Ok(report)
}

/// Request that the in-flight scan abort. Sets the shared `CancelToken`,
/// which every scanner's hot loop polls. Returns immediately — the actual
/// teardown happens inside `run_scan`'s task as scanners observe the flag.
#[tauri::command]
pub async fn cancel_scan(cancel: tauri::State<'_, CancelToken>) -> Result<(), String> {
    cancel.cancel();
    Ok(())
}

fn with_account_inventory(
    mut findings: Vec<ScanFinding>,
    accounts: &AccountStore,
) -> Vec<ScanFinding> {
    if let Ok(accounts) = accounts.list() {
        findings.extend(account_inventory_findings(&accounts));
    }
    findings
}

/// Save a freshly-generated, in-memory-signed report to disk. The frontend
/// CANNOT supply the report content — `save_report` re-runs scanners and
/// signs the result internally, so a tampered webview cannot persist a
/// forged "Clean" report. The `path` argument lets the frontend pass the
/// user's chosen destination from a native Save-As dialog; if it's `None`
/// or empty the report falls back to a timestamped file on the desktop.
/// Returns the absolute file path where the report was actually saved.
#[tauri::command]
pub async fn save_report(
    path: Option<String>,
    accounts: tauri::State<'_, AccountStore>,
) -> Result<String, String> {
    let findings = scanners::run_all_scans().await;
    let report =
        report_generator::generate_report(with_account_inventory(findings, accounts.inner()));
    report_generator::save_report(&report, path.as_deref())
}

/// Validate a report's HMAC signature AND its freshness window. A report
/// older than the configured age (~30 minutes) is rejected even if the
/// signature is valid, closing the trivial replay-attack vector where a
/// player keeps a one-time Clean report for future tournaments.
#[tauri::command]
pub async fn validate_report(json: String) -> Result<bool, String> {
    report_generator::validate_report(&json)
}

/// Read a previously-exported report file, parse it, and return the
/// report plus the signature / freshness verification result. Reading
/// happens in the backend (rather than the frontend's `readTextFile`) so
/// the Tauri permission surface stays minimal — the only path the UI
/// supplies is the one the user just chose in the native open dialog.
#[tauri::command]
pub async fn import_report(path: String) -> Result<ImportedReport, String> {
    let content =
        std::fs::read_to_string(&path).map_err(|e| format!("Could not read report file: {}", e))?;
    let report: ScanReport =
        serde_json::from_str(&content).map_err(|e| format!("Invalid report JSON: {}", e))?;
    let signature_valid = report.verify();
    let age_seconds = chrono::Utc::now()
        .signed_duration_since(report.timestamp)
        .num_seconds();
    let stale = age_seconds > 30 * 60;
    Ok(ImportedReport {
        report,
        signature_valid,
        age_seconds,
        stale,
        source_path: path,
    })
}

/// Reveal the evidence item for a file finding. Report details redact the
/// username as `<user>`; for this local-only action we resolve that placeholder
/// back to the current machine's home/profile path before opening the file
/// manager. Existing files are selected in their parent folder when the OS file
/// manager supports it; directories and stale/missing files fall back to opening
/// the relevant folder without opening the evidence file itself.
#[tauri::command]
pub async fn open_finding_folder(path: String) -> Result<(), String> {
    let resolved = resolve_redacted_user_path(path.trim())?;
    match finding_path_action(&resolved)? {
        FindingPathAction::RevealItem(target) => reveal_item(&target),
        FindingPathAction::OpenFolder(target) => open_folder(&target),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum FindingPathAction {
    RevealItem(PathBuf),
    OpenFolder(PathBuf),
}

fn finding_path_action(path: &Path) -> Result<FindingPathAction, String> {
    if path.is_file() {
        return Ok(FindingPathAction::RevealItem(path.to_path_buf()));
    }
    if path.is_dir() {
        return Ok(FindingPathAction::OpenFolder(path.to_path_buf()));
    }
    if let Some(parent) = path.parent().filter(|p| p.exists()) {
        return Ok(FindingPathAction::OpenFolder(parent.to_path_buf()));
    }
    Err(format!(
        "Path and parent folder do not exist: {}",
        path.display()
    ))
}

fn resolve_redacted_user_path(path: &str) -> Result<PathBuf, String> {
    let cleaned = path.trim().trim_matches('"');
    if cleaned.is_empty() {
        return Err("No path supplied".to_string());
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(profile) = std::env::var_os("USERPROFILE") {
            let profile = PathBuf::from(profile);
            let redacted = redacted_windows_user_prefix(&profile);
            if let Some(rest) = cleaned.strip_prefix(&redacted) {
                return Ok(profile.join(rest.trim_start_matches(|c| c == '\\' || c == '/')));
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Some(home) = std::env::var_os("HOME") {
            let home = PathBuf::from(home);
            for prefix in ["/Users/<user>", "/home/<user>"] {
                if let Some(rest) = cleaned.strip_prefix(prefix) {
                    return Ok(home.join(rest.trim_start_matches(|c| c == '/')));
                }
            }
        }
    }

    Ok(PathBuf::from(cleaned))
}

#[cfg(target_os = "windows")]
fn redacted_windows_user_prefix(profile: &Path) -> String {
    let profile = profile.to_string_lossy();
    if let Some((root, _)) = profile.rsplit_once("\\Users\\") {
        format!("{}\\Users\\<user>", root)
    } else {
        "C:\\Users\\<user>".to_string()
    }
}

fn reveal_item(path: &Path) -> Result<(), String> {
    tauri_plugin_opener::reveal_item_in_dir(path)
        .map_err(|e| format!("Could not reveal evidence file: {}", e))
}

#[cfg(target_os = "windows")]
fn open_folder(path: &Path) -> Result<(), String> {
    Command::new("explorer.exe")
        .arg(path)
        .spawn()
        .map_err(|e| format!("Could not open folder: {}", e))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn open_folder(path: &Path) -> Result<(), String> {
    Command::new("open")
        .arg(path)
        .spawn()
        .map_err(|e| format!("Could not open folder: {}", e))?;
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn open_folder(path: &Path) -> Result<(), String> {
    Command::new("xdg-open")
        .arg(path)
        .spawn()
        .map_err(|e| format!("Could not open folder: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmpdir() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("prism-command-test-{}", suffix));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn finding_path_action_reveals_existing_file() {
        let dir = tmpdir();
        let file = dir.join("ClientAppSettings.json");
        std::fs::write(&file, "{}").unwrap();

        assert_eq!(
            finding_path_action(&file).unwrap(),
            FindingPathAction::RevealItem(file.clone())
        );

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn finding_path_action_opens_existing_directory() {
        let dir = tmpdir();

        assert_eq!(
            finding_path_action(&dir).unwrap(),
            FindingPathAction::OpenFolder(dir.clone())
        );

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn finding_path_action_opens_parent_for_stale_path() {
        let dir = tmpdir();
        let stale_file = dir.join("deleted-fflags.json");

        assert_eq!(
            finding_path_action(&stale_file).unwrap(),
            FindingPathAction::OpenFolder(dir.clone())
        );

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn finding_path_action_errors_when_path_and_parent_are_missing() {
        let dir = tmpdir();
        let missing_parent = dir.join("gone");
        let missing_file = missing_parent.join("fflags.json");
        std::fs::remove_dir_all(&dir).ok();

        let err = finding_path_action(&missing_file).unwrap_err();
        assert!(err.contains("Path and parent folder do not exist"));
    }

    #[test]
    fn resolve_redacted_user_path_rejects_empty_paths() {
        assert_eq!(
            resolve_redacted_user_path("  \"\"  ").unwrap_err(),
            "No path supplied"
        );
    }
}
