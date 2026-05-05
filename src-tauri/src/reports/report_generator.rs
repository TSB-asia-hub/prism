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
            let desktop =
                get_desktop_path().ok_or_else(|| "Could not determine desktop path".to_string())?;
            if !desktop.exists() {
                std::fs::create_dir_all(&desktop)
                    .map_err(|e| format!("Could not create desktop directory: {}", e))?;
            }
            let timestamp = report.timestamp.format("%Y%m%d_%H%M%S").to_string();
            desktop.join(format!("Prism_Report_{}.json", timestamp))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ScanFinding, ScanReport, ScanVerdict};
    use chrono::{Duration, Utc};

    fn test_finding(verdict: ScanVerdict) -> ScanFinding {
        ScanFinding::new("test_scanner", verdict, "test finding", None)
    }

    fn unique_temp_report_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "prism-report-test-{}-{}-{}.json",
            name,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ))
    }

    #[test]
    fn generate_report_computes_verdict_and_signs_output() {
        let report = generate_report(vec![
            test_finding(ScanVerdict::Clean),
            test_finding(ScanVerdict::Suspicious),
        ]);

        assert_eq!(report.overall_verdict, ScanVerdict::Suspicious);
        assert_eq!(report.findings.len(), 2);
        assert!(report.verify());
    }

    #[test]
    fn save_report_refuses_invalid_signature() {
        let report = ScanReport::new();
        let path = unique_temp_report_path("invalid-signature");

        let err = save_report(&report, Some(&path.to_string_lossy()))
            .expect_err("unsigned reports must not be saved");

        assert!(err.contains("HMAC signature is invalid"));
        assert!(!path.exists());
    }

    #[test]
    fn save_report_writes_signed_report_to_requested_path() {
        let report = generate_report(vec![test_finding(ScanVerdict::Clean)]);
        let path = unique_temp_report_path("valid-signature");

        let saved = save_report(&report, Some(&path.to_string_lossy()))
            .expect("signed report should save");

        assert_eq!(PathBuf::from(saved), path);
        let saved_json = std::fs::read_to_string(&path).expect("report file should exist");
        let decoded: ScanReport =
            serde_json::from_str(&saved_json).expect("saved report JSON should decode");
        assert!(decoded.verify());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn validate_report_rejects_invalid_json_invalid_signature_and_stale_reports() {
        assert!(validate_report("{not json").is_err());

        let mut unsigned = ScanReport::new();
        unsigned.hmac_signature = "00".repeat(32);
        assert_eq!(validate_report(&unsigned.to_json()), Ok(false));

        let mut stale = generate_report(vec![test_finding(ScanVerdict::Clean)]);
        stale.timestamp = Utc::now() - Duration::minutes(31);
        stale.sign();
        assert_eq!(validate_report(&stale.to_json()), Ok(false));
    }

    #[test]
    fn validate_report_accepts_fresh_signed_reports() {
        let report = generate_report(vec![test_finding(ScanVerdict::Clean)]);

        assert_eq!(validate_report(&report.to_json()), Ok(true));
    }
}
