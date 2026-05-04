use std::path::PathBuf;

use crate::models::{ScanFinding, ScanReport};

/// Generate a signed scan report from a collection of findings.
pub fn generate_report(findings: Vec<ScanFinding>) -> ScanReport {
    let mut report = ScanReport::new();

    for finding in findings {
        report.add_finding(finding);
    }

    // Ensure overall verdict is computed
    report.overall_verdict = report.compute_verdict();

    // Sign the report with HMAC
    report.sign();

    report
}

/// Save a scan report as JSON. If `target_path` is provided, the report is
/// written there verbatim (the frontend supplies the user's chosen file via
/// the native Save-As dialog). Otherwise the report falls back to a
/// timestamped file on the user's desktop, preserving the original behavior
/// for callers that don't prompt.
///
/// The caller (`commands::save_report`) generates the report from a fresh
/// in-process scan, so we own its provenance. We still verify the signature
/// here as a defense-in-depth check against bugs in the signing pipeline.
pub fn save_report(report: &ScanReport, target_path: Option<&str>) -> Result<String, String> {
    if !report.verify() {
        return Err(
            "Report HMAC signature is invalid — refusing to save (signing pipeline bug?)."
                .to_string(),
        );
    }

    let file_path: PathBuf = match target_path {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => {
            let desktop = get_desktop_path()
                .ok_or_else(|| "Could not determine desktop path".to_string())?;
            if !desktop.exists() {
                std::fs::create_dir_all(&desktop)
                    .map_err(|e| format!("Could not create desktop directory: {}", e))?;
            }
            let timestamp = report.timestamp.format("%Y%m%d_%H%M%S").to_string();
            desktop.join(format!("FlagCheck_Report_{}.json", timestamp))
        }
    };

    if let Some(parent) = file_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Could not create destination directory: {}", e))?;
        }
    }

    let json = report.to_json();
    std::fs::write(&file_path, &json).map_err(|e| format!("Could not write report file: {}", e))?;

    Ok(file_path.to_string_lossy().to_string())
}

/// Validate a report's HMAC signature AND its freshness window.
/// Returns Ok(true) on success; Ok(false) if signature/freshness fails;
/// Err if the JSON itself can't be parsed.
pub fn validate_report(json: &str) -> Result<bool, String> {
    let report: ScanReport =
        serde_json::from_str(json).map_err(|e| format!("Invalid report JSON: {}", e))?;

    Ok(report.verify_fresh().is_ok())
}

/// Get the user's desktop path.
fn get_desktop_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERPROFILE")
            .ok()
            .map(|p| PathBuf::from(p).join("Desktop"))
    }

    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME")
            .ok()
            .map(|p| PathBuf::from(p).join("Desktop"))
    }
}
