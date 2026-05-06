// On non-Windows builds the heartbeat path is unused (memory_scanner stub
// skips the walk), so silence the dead-code warnings that only apply there.
#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

//! Scan-progress reporting.
//!
//! Wraps an optional `tauri::AppHandle` so scanners can emit live progress
//! events to the frontend without forcing every call site (tests, future
//! CLI modes) to own an `AppHandle`. A `ScanProgress::noop()` instance is
//! a drop-in placeholder that silently swallows all events.
//!
//! Events are emitted under the topic `"scan-progress"`; the payload is a
//! tagged enum so the frontend can discriminate without a second topic.

use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Emitter};

/// Event payload shape. `kind` is used as the discriminator on the frontend.
#[derive(Serialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScanProgressEvent {
    Started {
        scanner: &'static str,
    },
    Done {
        scanner: &'static str,
        findings: usize,
    },
    Heartbeat {
        scanner: &'static str,
        regions_scanned: usize,
        bytes_scanned: u64,
    },
    Errored {
        scanner: &'static str,
        message: String,
    },
}

/// Shared cancellation flag. Cloning the handle is cheap (Arc-backed) — every
/// `ScanProgress` instance and the `cancel_scan` Tauri command point at the
/// same underlying `AtomicBool`, so flipping it in the command immediately
/// makes every running scanner see `is_cancelled() == true` on its next
/// poll point. Stored in Tauri state via `CancelState` (see lib.rs).
#[derive(Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn reset(&self) {
        self.0.store(false, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Handle that scanners use to emit progress. Clone is cheap (underlying
/// `AppHandle` is Arc-backed).
#[derive(Clone)]
pub struct ScanProgress {
    app: Option<AppHandle>,
    cancel: CancelToken,
}

impl ScanProgress {
    pub fn new(app: AppHandle, cancel: CancelToken) -> Self {
        Self {
            app: Some(app),
            cancel,
        }
    }

    pub fn noop() -> Self {
        Self {
            app: None,
            cancel: CancelToken::new(),
        }
    }

    /// Quick poll for whether the user has hit the Stop button. Scanners call
    /// this from their hot loops and bail out early when it returns true.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    pub fn started(&self, scanner: &'static str) {
        self.emit(ScanProgressEvent::Started { scanner });
    }

    pub fn done(&self, scanner: &'static str, findings: usize) {
        self.emit(ScanProgressEvent::Done { scanner, findings });
    }

    pub fn heartbeat(&self, scanner: &'static str, regions_scanned: usize, bytes_scanned: u64) {
        self.emit(ScanProgressEvent::Heartbeat {
            scanner,
            regions_scanned,
            bytes_scanned,
        });
    }

    pub fn errored(&self, scanner: &'static str, message: String) {
        self.emit(ScanProgressEvent::Errored { scanner, message });
    }

    fn emit(&self, event: ScanProgressEvent) {
        if let Some(app) = &self.app {
            // Emit failures are ignored — progress is best-effort and must
            // never abort a scan.
            let _ = app.emit("scan-progress", event);
        }
    }
}
