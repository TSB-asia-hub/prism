pub mod client_settings_scanner;
pub mod file_scanner;
pub mod memory_scanner;
pub mod prefetch_scanner;
pub mod process_scanner;
pub mod progress;

use crate::models::ScanFinding;
use progress::ScanProgress;
use std::path::{Path, PathBuf};
use tokio::task::JoinHandle;

/// Run all scanners and collect findings, emitting live progress events
/// to `reporter`. Each scanner is dispatched via `spawn_blocking` so its
/// synchronous I/O (sysinfo, WalkDir, std::fs, winapi) does not stall the
/// tokio runtime worker — this also gives us real concurrency, not the
/// implicit serialization that `tokio::join!` of blocking-bodied async fns
/// would produce.
///
/// Progress events fire in this shape per scanner:
/// - `Started { scanner }` when the spawn_blocking is dispatched.
/// - `Heartbeat { ... }` only from memory_scanner, every ~500ms.
/// - `Done { scanner, findings }` when the task completes cleanly.
/// - `Errored { scanner, message }` when the task panics.
pub async fn run_all_scans_with_progress(reporter: ScanProgress) -> Vec<ScanFinding> {
    run_all_scans_with_partial_progress(reporter, |_| {}).await
}

/// Run every scanner, calling `on_non_memory_done` as soon as the faster
/// non-memory scanners have completed. The memory scanner is still running in
/// parallel while the callback fires, allowing UI callers to publish early
/// findings without waiting for the memory walk.
pub async fn run_all_scans_with_partial_progress<F>(
    reporter: ScanProgress,
    on_non_memory_done: F,
) -> Vec<ScanFinding>
where
    F: FnOnce(Vec<ScanFinding>),
{
    // Kick off all scanners in parallel, emitting Started as each is dispatched.
    let process_reporter = reporter.clone();
    let process_handle = {
        reporter.started("process_scanner");
        tokio::task::spawn_blocking(move || {
            let _ = process_reporter;
            futures_block_on(process_scanner::scan())
        })
    };

    let file_reporter = reporter.clone();
    let file_handle = {
        reporter.started("file_scanner");
        tokio::task::spawn_blocking(move || {
            futures_block_on(file_scanner::scan(&file_reporter))
        })
    };

    let client_reporter = reporter.clone();
    let client_handle = {
        reporter.started("client_settings_scanner");
        tokio::task::spawn_blocking(move || {
            let _ = client_reporter;
            futures_block_on(client_settings_scanner::scan())
        })
    };

    let prefetch_reporter = reporter.clone();
    let prefetch_handle = {
        reporter.started("prefetch_scanner");
        tokio::task::spawn_blocking(move || {
            let _ = prefetch_reporter;
            futures_block_on(prefetch_scanner::scan())
        })
    };

    // Memory scanner needs the reporter to emit heartbeats during its walk.
    let memory_reporter = reporter.clone();
    let memory_handle = {
        reporter.started("memory_scanner");
        tokio::task::spawn_blocking(move || {
            futures_block_on(memory_scanner::scan_with_progress(memory_reporter))
        })
    };

    let mut non_memory_findings = Vec::new();
    for (scanner_id, handle) in [
        ("process_scanner", process_handle),
        ("file_scanner", file_handle),
        ("client_settings_scanner", client_handle),
        ("prefetch_scanner", prefetch_handle),
    ] {
        let mut findings = await_scanner(scanner_id, handle, &reporter).await;
        non_memory_findings.append(&mut findings);
    }

    let non_memory_findings = drop_stale_file_path_findings(non_memory_findings);
    on_non_memory_done(non_memory_findings.clone());

    let mut all_findings = non_memory_findings;
    let mut memory_findings = await_scanner("memory_scanner", memory_handle, &reporter).await;
    all_findings.append(&mut memory_findings);
    drop_stale_file_path_findings(all_findings)
}

/// Convenience wrapper that runs every scanner with progress reporting
/// disabled. Used by callers that do not have (or do not need) an
/// `AppHandle` — e.g. tests and the `save_report` command which re-runs
/// scans without a UI surface.
pub async fn run_all_scans() -> Vec<ScanFinding> {
    run_all_scans_with_progress(ScanProgress::noop()).await
}

/// The scanner functions themselves are still `async fn` (their bodies are
/// synchronous but the signatures must stay compatible with the existing
/// trait). We block on each future synchronously inside the spawn_blocking
/// closure using a tiny one-task runtime — this avoids dragging the heavy
/// tokio runtime features in just to drive a synchronous body.
fn futures_block_on<F: std::future::Future>(fut: F) -> F::Output {
    use std::pin::Pin;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWaker;
    impl Wake for NoopWaker {
        fn wake(self: std::sync::Arc<Self>) {}
    }
    let waker = Waker::from(std::sync::Arc::new(NoopWaker));
    let mut cx = Context::from_waker(&waker);
    let mut fut: Pin<Box<F>> = Box::pin(fut);
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        // The scanners never yield to the runtime, so a Ready arrives on the
        // first poll. The loop is defensive only.
    }
}

async fn await_scanner(
    scanner_id: &'static str,
    handle: JoinHandle<Vec<ScanFinding>>,
    reporter: &ScanProgress,
) -> Vec<ScanFinding> {
    match handle.await {
        Ok(findings) => {
            reporter.done(scanner_id, findings.len());
            findings
        }
        Err(e) => {
            // A scanner task panic is a tooling bug, not a cheat signal.
            // Surface it as Inconclusive so the operator knows coverage
            // was incomplete, but never let a transient JoinError flip
            // the overall verdict to Suspicious.
            let msg = format!("Scanner task panicked: {}", e);
            reporter.errored(scanner_id, msg.clone());
            vec![ScanFinding::new(
                "scanner_runtime",
                crate::models::ScanVerdict::Inconclusive,
                msg,
                None,
            )]
        }
    }
}

fn drop_stale_file_path_findings(findings: Vec<ScanFinding>) -> Vec<ScanFinding> {
    findings
        .into_iter()
        .filter(|finding| file_path_finding_is_current(finding))
        .collect()
}

fn file_path_finding_is_current(finding: &ScanFinding) -> bool {
    if finding.module != "file_scanner" {
        return true;
    }
    let Some(details) = finding.details.as_deref() else {
        return true;
    };
    let Some(path) = details_path_value(details) else {
        return true;
    };
    let Some(resolved) = resolve_redacted_local_path(&path) else {
        return true;
    };
    resolved.exists()
}

fn details_path_value(details: &str) -> Option<String> {
    let start = details.find("Path: ")? + "Path: ".len();
    let rest = &details[start..];
    let end = rest
        .find(" | ")
        .or_else(|| rest.find(", "))
        .unwrap_or(rest.len());
    let value = rest[..end].trim().trim_matches('"');
    (!value.is_empty()).then(|| value.to_string())
}

fn resolve_redacted_local_path(path: &str) -> Option<PathBuf> {
    let cleaned = path.trim();

    #[cfg(target_os = "windows")]
    {
        if let Some(profile) = std::env::var_os("USERPROFILE") {
            let profile = PathBuf::from(profile);
            let redacted = redacted_windows_user_prefix(&profile);
            if let Some(rest) = cleaned.strip_prefix(&redacted) {
                return Some(profile.join(rest.trim_start_matches(['\\', '/'])));
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Some(home) = std::env::var_os("HOME") {
            let home = PathBuf::from(home);
            for prefix in ["/Users/<user>", "/home/<user>"] {
                if let Some(rest) = cleaned.strip_prefix(prefix) {
                    return Some(home.join(rest.trim_start_matches('/')));
                }
            }
        }
    }

    Some(Path::new(cleaned).to_path_buf())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ScanVerdict;

    #[test]
    fn details_path_value_parses_pipe_and_comma_formats() {
        assert_eq!(
            details_path_value("Path: C:\\tmp\\x.json | Source: JSON").as_deref(),
            Some("C:\\tmp\\x.json")
        );
        assert_eq!(
            details_path_value("Path: C:\\tmp\\x.json, Last modified: now").as_deref(),
            Some("C:\\tmp\\x.json")
        );
    }

    #[test]
    fn stale_file_scanner_path_findings_are_dropped() {
        let missing = std::env::temp_dir().join(format!(
            "prism-missing-file-finding-{}",
            std::process::id()
        ));
        std::fs::remove_file(&missing).ok();
        let finding = ScanFinding::new(
            "file_scanner",
            ScanVerdict::Suspicious,
            "Suspicious FFlag values found in JSON file",
            Some(format!("Path: {} | Source: JSON", missing.display())),
        );

        assert!(drop_stale_file_path_findings(vec![finding]).is_empty());
    }

    #[test]
    fn existing_file_scanner_path_findings_are_kept() {
        let path = std::env::temp_dir().join(format!(
            "prism-existing-file-finding-{}",
            std::process::id()
        ));
        std::fs::write(&path, "ok").unwrap();
        let finding = ScanFinding::new(
            "file_scanner",
            ScanVerdict::Suspicious,
            "Suspicious FFlag values found in JSON file",
            Some(format!("Path: {} | Source: JSON", path.display())),
        );

        assert_eq!(drop_stale_file_path_findings(vec![finding]).len(), 1);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn non_file_scanner_path_findings_are_kept() {
        let finding = ScanFinding::new(
            "prefetch_scanner",
            ScanVerdict::Suspicious,
            "Historical execution cache",
            Some("Path: C:\\definitely\\missing.exe".to_string()),
        );

        assert_eq!(drop_stale_file_path_findings(vec![finding]).len(), 1);
    }
}
