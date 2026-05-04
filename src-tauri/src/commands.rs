use serde::Serialize;

use crate::models::ScanReport;
use crate::reports::report_generator;
use crate::scanners;
use crate::scanners::progress::ScanProgress;

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
#[tauri::command]
pub async fn run_scan(app: tauri::AppHandle) -> Result<ScanReport, String> {
    let reporter = ScanProgress::new(app);
    let findings = scanners::run_all_scans_with_progress(reporter).await;
    let report = report_generator::generate_report(findings);
    Ok(report)
}

/// Save a freshly-generated, in-memory-signed report to disk. The frontend
/// CANNOT supply the report content — `save_report` re-runs scanners and
/// signs the result internally, so a tampered webview cannot persist a
/// forged "Clean" report. The `path` argument lets the frontend pass the
/// user's chosen destination from a native Save-As dialog; if it's `None`
/// or empty the report falls back to a timestamped file on the desktop.
/// Returns the absolute file path where the report was actually saved.
#[tauri::command]
pub async fn save_report(path: Option<String>) -> Result<String, String> {
    let findings = scanners::run_all_scans().await;
    let report = report_generator::generate_report(findings);
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
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Could not read report file: {}", e))?;
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
