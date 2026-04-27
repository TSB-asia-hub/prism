use std::collections::HashSet;
use sysinfo::System;

use crate::data::known_tools::{
    KNOWN_BOOTSTRAPPER_PROCESS_NAMES, KNOWN_PROCESS_NAMES, KNOWN_TOOL_FILENAMES,
};
use crate::models::{ScanFinding, ScanVerdict};

/// Token-boundary match: returns true if `needle` appears in `haystack` as a
/// distinct token — i.e. bounded on both sides by a non-alphanumeric character
/// or by start/end of string. This prevents "bolt" from matching
/// "thunderboltd", "wave" from matching "wavelink", "delta" from "deltachat",
/// "codex" from "codex-cli", etc. Case-insensitive.
fn contains_token(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let hay = haystack.as_bytes();
    let nee = needle.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut i = 0usize;
    while i + nee.len() <= hay.len() {
        // Case-insensitive match on ASCII only (needles are lowercase).
        let mut matched = true;
        for k in 0..nee.len() {
            if hay[i + k].to_ascii_lowercase() != nee[k] {
                matched = false;
                break;
            }
        }
        if matched {
            let before_ok = i == 0 || !is_ident(hay[i - 1]);
            let after_idx = i + nee.len();
            let after_ok = after_idx >= hay.len() || !is_ident(hay[after_idx]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// True if the process is an active Roblox player (not Studio, not a crash
/// handler, not an installer, not a leftover zombie). This gate controls
/// whether a known-tool match escalates from Suspicious to Flagged — if
/// Roblox isn't actively running, a cheat tool is still Suspicious but
/// unrelated to any current gaming session.
fn is_roblox_player_process(name_lower: &str) -> bool {
    // Must be one of Roblox's actual player binaries. We explicitly exclude
    // studio/crashhandler/installer/launcher/bootstrapper — those are real
    // Roblox processes, but their presence does not imply the user is in a
    // live game session.
    const EXCLUDED: &[&str] = &[
        "robloxstudio",
        "robloxcrashhandler",
        "robloxplayerinstaller",
        "robloxplayerlauncher",
        "robloxbootstrapper",
    ];
    if EXCLUDED.iter().any(|e| name_lower.contains(e)) {
        return false;
    }
    contains_token(name_lower, "robloxplayerbeta")
        || contains_token(name_lower, "robloxplayer")
        || contains_token(name_lower, "roblox")
}

/// Scan running processes for known cheat/injection tools.
pub async fn scan() -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    let mut sys = System::new_all();
    sys.refresh_all();

    let roblox_running = sys.processes().values().any(|p| {
        let name = p.name().to_string_lossy().to_lowercase();
        is_roblox_player_process(&name)
    });

    // Each PID is reported at most once even if both name and filename rules fire.
    let mut reported: HashSet<sysinfo::Pid> = HashSet::new();

    for (pid, process) in sys.processes() {
        if reported.contains(pid) {
            continue;
        }
        let proc_name = process.name().to_string_lossy().to_lowercase();
        let exe_path = process
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let exe_filename = process
            .exe()
            .and_then(|p| p.file_name())
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();

        let mut matched_via: Option<String> = None;

        for &known_name in KNOWN_PROCESS_NAMES {
            // Token-boundary match — prevents "bolt" matching "thunderboltd",
            // "wave" matching "wavelink", "delta" matching "deltachat", etc.
            if contains_token(&proc_name, known_name) {
                matched_via = Some(format!("matched: \"{}\"", known_name));
                break;
            }
        }

        if matched_via.is_none() && !exe_filename.is_empty() {
            for &known_file in KNOWN_TOOL_FILENAMES {
                if exe_filename.eq_ignore_ascii_case(known_file) {
                    matched_via = Some(format!("filename: \"{}\"", known_file));
                    break;
                }
            }
        }

        if let Some(reason) = matched_via {
            let verdict = if roblox_running {
                ScanVerdict::Flagged
            } else {
                ScanVerdict::Suspicious
            };
            findings.push(ScanFinding::new(
                "process_scanner",
                verdict,
                format!(
                    "Known tool process detected: \"{}\" ({})",
                    process.name().to_string_lossy(),
                    reason
                ),
                Some(format!("PID: {}, Path: {}", pid, exe_path)),
            ));
            reported.insert(*pid);
            continue;
        }

        // Legitimate bootstrapper launchers — informational only, never raise
        // the verdict. Per Roblox policy these are not cheat indicators.
        for &boot_name in KNOWN_BOOTSTRAPPER_PROCESS_NAMES {
            if contains_token(&proc_name, boot_name) {
                findings.push(ScanFinding::new(
                    "process_scanner",
                    ScanVerdict::Clean,
                    format!(
                        "Bootstrapper running: \"{}\" (legitimate launcher; not a cheat indicator)",
                        process.name().to_string_lossy()
                    ),
                    Some(format!("PID: {}, Path: {}", pid, exe_path)),
                ));
                reported.insert(*pid);
                break;
            }
        }
    }

    if findings.is_empty() {
        findings.push(ScanFinding::new(
            "process_scanner",
            ScanVerdict::Clean,
            "No known cheat or injection tools detected in running processes",
            Some(format!(
                "Scanned {} running processes",
                sys.processes().len()
            )),
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_match_respects_boundaries() {
        assert!(contains_token("electron", "electron"));
        assert!(contains_token("Electron Helper", "electron"));
        assert!(contains_token("electron-renderer", "electron"));
        assert!(contains_token("LornoBypass.exe", "lornobypass"));
        assert!(contains_token("Lorno Bypass.exe", "lorno bypass"));
        // Must NOT match when the needle is embedded in a longer word.
        assert!(!contains_token("electronics", "electron"));
        assert!(!contains_token("cleanlornobypasshelper", "lornobypass"));
        assert!(!contains_token("pre Lorno Bypasser", "lorno bypass"));
        assert!(!contains_token("thunderboltd", "bolt"));
        assert!(!contains_token("wavelink", "wave"));
        assert!(!contains_token("deltachat", "delta"));
    }

    #[test]
    fn player_gate_excludes_crashhandler_and_studio() {
        assert!(is_roblox_player_process("robloxplayerbeta.exe"));
        assert!(!is_roblox_player_process("robloxcrashhandler.exe"));
        assert!(!is_roblox_player_process("robloxstudio.exe"));
        assert!(!is_roblox_player_process("robloxplayerinstaller.exe"));
    }
}
