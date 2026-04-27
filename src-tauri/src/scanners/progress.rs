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

/// Handle that scanners use to emit progress. Clone is cheap (underlying
/// `AppHandle` is Arc-backed).
#[derive(Clone)]
pub struct ScanProgress {
    app: Option<AppHandle>,
}

impl ScanProgress {
    pub fn new(app: AppHandle) -> Self {
        Self { app: Some(app) }
    }

    pub fn noop() -> Self {
        Self { app: None }
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
