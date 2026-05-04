use crate::models::ScanReport;
use crate::reports::report_generator;
use crate::scanners;
use crate::scanners::progress::ScanProgress;

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
