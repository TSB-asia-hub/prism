pub mod client_settings_scanner;
pub mod file_scanner;
pub mod memory_scanner;
pub mod prefetch_scanner;
pub mod process_scanner;
pub mod progress;

use crate::models::ScanFinding;
use progress::ScanProgress;

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
            let _ = file_reporter;
            futures_block_on(file_scanner::scan())
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

    let mut all_findings = Vec::new();
    for (scanner_id, handle) in [
        ("process_scanner", process_handle),
        ("file_scanner", file_handle),
        ("client_settings_scanner", client_handle),
        ("prefetch_scanner", prefetch_handle),
        ("memory_scanner", memory_handle),
    ] {
        match handle.await {
            Ok(mut findings) => {
                reporter.done(scanner_id, findings.len());
                all_findings.append(&mut findings);
            }
            Err(e) => {
                // A scanner task panic is a tooling bug, not a cheat signal.
                // Surface it as Inconclusive so the operator knows coverage
                // was incomplete, but never let a transient JoinError flip
                // the overall verdict to Suspicious.
                let msg = format!("Scanner task panicked: {}", e);
                reporter.errored(scanner_id, msg.clone());
                all_findings.push(ScanFinding::new(
                    "scanner_runtime",
                    crate::models::ScanVerdict::Inconclusive,
                    msg,
                    None,
                ));
            }
        }
    }
    all_findings
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
