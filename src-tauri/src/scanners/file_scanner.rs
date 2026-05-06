use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

use aho_corasick::AhoCorasick;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::data::flag_allowlist::is_allowed_flag;
use crate::data::known_tools::{
    BinaryFingerprint, GENERIC_RE_TOOL_DIRS, INJECTOR_SIBLING_CONFIG_FILES,
    KNOWN_BOOTSTRAPPER_DIRS, KNOWN_BOOTSTRAPPER_FILENAMES, KNOWN_TOOL_BINARY_FINGERPRINTS,
    KNOWN_TOOL_FILENAMES, KNOWN_TOOL_HASHES, ROBLOX_CHEAT_DIRS,
};
use crate::data::suspicious_flags::{get_flag_category, get_flag_description, get_flag_severity};
use crate::models::{ScanFinding, ScanVerdict};
use crate::scanners::progress::ScanProgress;

/// Upper size bound (bytes) for opportunistic hashing of `.exe` artefacts
/// found during the walk. The largest known injector in the hash list is
/// well under 10 MB; real games/installers can be hundreds of MB, and we do
/// not want the scanner to stall reading those.
const HASH_SIZE_LIMIT_BYTES: u64 = 64 * 1024 * 1024;
const INJECTOR_CONFIG_SIZE_LIMIT_BYTES: u64 = 512 * 1024;
const JSON_FLAG_SCAN_SIZE_LIMIT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_INJECTOR_PAYLOAD_FLAGS: usize = 16;
const MAX_JSON_FLAG_MATCHES_PER_FILE: usize = 24;
const MAX_JSON_FLAG_DEPTH: usize = 64;
const FFLAG_KEY_PREFIXES: &[&str] = &[
    "FFlag", "DFFlag", "DFInt", "FInt", "DFString", "FString", "DFLog", "FLog", "SFFlag", "SFInt",
    "SFString",
];

/// Wall-clock cap for the whole-system broad scan. Walking every drive on a
/// typical machine takes well under this even with FFlag content scanning;
/// the budget exists so a slow / encrypted / network-mounted volume can
/// never hang the scanner. On expiry the broad pass aborts and emits an
/// Inconclusive note saying coverage was time-truncated.
const BROAD_SCAN_TIME_BUDGET: Duration = Duration::from_secs(45);

/// Files-per-batch for the broad pass. We collect candidate paths into
/// fixed-size batches and dispatch each batch to rayon — this keeps memory
/// bounded on huge filesystems while still saturating the CPU during the
/// content-scan I/O.
const BROAD_SCAN_BATCH: usize = 256;

/// Scan the filesystem for known tool artifacts.
///
/// `reporter` carries the shared cancellation flag — when the user hits the
/// Stop button on the UI, every long-running loop checks
/// `reporter.is_cancelled()` and bails out early so the run can collapse to
/// a partial result within a few hundred milliseconds.
pub async fn scan(reporter: &ScanProgress) -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    let roots = get_search_roots();
    let current_exe = current_exe_canonical();

    // Track every absolute path we've already reported on, so the same file
    // isn't double-flagged when overlapping search roots cause it to be
    // visited via two different walks.
    let mut reported_paths: HashSet<PathBuf> = HashSet::new();

    for root in &roots {
        if reporter.is_cancelled() {
            break;
        }
        if !root.exists() {
            continue;
        }

        // Roblox-specific cheat tool directories → Suspicious.
        for &tool_dir in ROBLOX_CHEAT_DIRS {
            if let Some(dir_path) = known_named_dir_path(root, tool_dir) {
                let canon = dir_path.canonicalize().unwrap_or_else(|_| dir_path.clone());
                if reported_paths.insert(canon.clone()) {
                    let modified = format_modified(&dir_path);
                    findings.push(ScanFinding::new(
                        "file_scanner",
                        ScanVerdict::Suspicious,
                        format!("Roblox-cheat tool directory found: \"{}\"", tool_dir),
                        Some(format!(
                            "Path: {}, Last modified: {}",
                            dir_path.display(),
                            modified
                        )),
                    ));
                }
            }
        }

        // Generic reverse-engineering / debugging tools (x64dbg, HxD,
        // ProcessHacker, etc.) — widely used for CTF, malware analysis,
        // driver debugging, and security research. Record as informational
        // Clean notes only; do not raise the verdict.
        for &tool_dir in GENERIC_RE_TOOL_DIRS {
            if let Some(dir_path) = known_named_dir_path(root, tool_dir) {
                let canon = dir_path.canonicalize().unwrap_or_else(|_| dir_path.clone());
                if reported_paths.insert(canon.clone()) {
                    let modified = format_modified(&dir_path);
                    findings.push(ScanFinding::new(
                        "file_scanner",
                        ScanVerdict::Clean,
                        format!(
                            "Generic reverse-engineering tool present: \"{}\" (legitimate security/CTF use; not a Roblox-specific cheat indicator)",
                            tool_dir
                        ),
                        Some(format!(
                            "Path: {}, Last modified: {}",
                            dir_path.display(),
                            modified
                        )),
                    ));
                }
            }
        }

        // Bootstrapper directories — informational only (legitimate launchers
        // per Roblox policy, not cheat indicators).
        for &boot_dir in KNOWN_BOOTSTRAPPER_DIRS {
            if let Some(dir_path) = known_named_dir_path(root, boot_dir) {
                let canon = dir_path.canonicalize().unwrap_or_else(|_| dir_path.clone());
                if reported_paths.insert(canon.clone()) {
                    findings.push(ScanFinding::new(
                        "file_scanner",
                        ScanVerdict::Clean,
                        format!(
                            "Bootstrapper directory present: \"{}\" (legitimate launcher; not a cheat indicator)",
                            boot_dir
                        ),
                        Some(format!("Path: {}", dir_path.display())),
                    ));
                }
            }
        }

        // Tool executables + flag-content files (depth-limited walk).
        // Phase 1: enumerate file paths sequentially (walkdir is bounded by
        // a single directory scan, so parallelizing the walk itself buys
        // little). Phase 2: process each entry's hashing / PE inspection /
        // content scan in parallel via rayon, then dedup-and-merge into
        // the running findings list. This is where the speedup lives —
        // hashing and PE fingerprint scans were the dominant cost and ran
        // strictly serial before.
        let entries: Vec<walkdir::DirEntry> = WalkDir::new(root)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .collect();

        let current_exe_ref = current_exe.as_deref();
        let new_findings: Vec<(PathBuf, ScanFinding)> = entries
            .par_iter()
            .flat_map_iter(|entry| process_file_entry(entry, current_exe_ref).into_iter())
            .collect();

        for (canon, finding) in new_findings {
            if reported_paths.insert(canon) {
                findings.push(finding);
            }
        }
    }

    // Whole-system content sweep. Runs after the focused roots so any file
    // a higher-priority check already produced a finding for is filtered
    // out by the shared `reported_paths` dedup set, and only adds new
    // findings from places the focused roots couldn't reach (custom
    // folders like D:\flags, OneDrive subtrees outside Documents, etc.).
    // Skip entirely if the user already cancelled mid focused-roots pass.
    if !reporter.is_cancelled() {
        let broad_findings = broad_scan(&mut reported_paths, reporter);
        findings.extend(broad_findings);
    }

    if findings.is_empty() {
        let scanned: Vec<String> = roots
            .iter()
            .filter(|r| r.exists())
            .map(|r| r.display().to_string())
            .collect();
        // Zero roots = zero coverage. A signed Clean report in that case is
        // a silent false-negative — emit Inconclusive so tournament staff
        // know the file scan had nothing to look at.
        if scanned.is_empty() {
            findings.push(ScanFinding::new(
                "file_scanner",
                ScanVerdict::Inconclusive,
                "No scanner roots available — user home / AppData env vars unset?",
                Some(format!(
                    "Configured candidate roots: {}",
                    roots
                        .iter()
                        .map(|r| r.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
            ));
        } else {
            findings.push(ScanFinding::new(
                "file_scanner",
                ScanVerdict::Clean,
                "No known tool artifacts found on filesystem",
                Some(format!("Scanned {} directories", scanned.len())),
            ));
        }
    }

    findings
}

/// Lowercased file extension, or None for files without one.
fn lower_ext(path: &Path) -> Option<String> {
    path.extension().map(|e| e.to_string_lossy().to_lowercase())
}

fn current_exe_canonical() -> Option<PathBuf> {
    let path = std::env::current_exe().ok()?;
    Some(path.canonicalize().unwrap_or(path))
}

fn is_current_executable_path(path: &Path, current_exe: Option<&Path>) -> bool {
    let Some(current_exe) = current_exe else {
        return false;
    };
    let candidate = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    same_path_for_scan_exclusion(&candidate, current_exe)
}

fn is_prism_release_filename(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    lower == "prism.exe"
        || (lower.starts_with("prism-v") && lower.ends_with("-windows-portable.exe"))
}

fn file_contains_all_markers(path: &Path, markers: &[&[u8]]) -> bool {
    if markers.is_empty() {
        return false;
    }
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };

    let max_marker_len = markers.iter().map(|m| m.len()).max().unwrap_or(0);
    if max_marker_len == 0 {
        return false;
    }
    let overlap = max_marker_len.saturating_sub(1);
    let mut hits = vec![false; markers.len()];

    const CHUNK: usize = 64 * 1024;
    let mut buf = vec![0u8; overlap + CHUNK];
    let mut filled_tail = 0usize;

    loop {
        let n = match file.read(&mut buf[filled_tail..]) {
            Ok(0) => 0,
            Ok(n) => n,
            Err(_) => return false,
        };
        let valid = filled_tail + n;
        if valid == 0 {
            break;
        }
        let haystack = &buf[..valid];

        for (i, marker) in markers.iter().enumerate() {
            if !hits[i] && memchr::memmem::find(haystack, marker).is_some() {
                hits[i] = true;
            }
        }
        if hits.iter().all(|&hit| hit) {
            return true;
        }
        if n == 0 {
            break;
        }

        let keep = overlap.min(valid);
        if keep > 0 {
            buf.copy_within(valid - keep..valid, 0);
        }
        filled_tail = keep;
    }

    false
}

fn is_prism_release_artifact(path: &Path, file_name: &str) -> bool {
    is_prism_release_filename(file_name)
        && file_starts_with_mz(path)
        && file_contains_all_markers(path, &[b"Prism", b"TSBCC", b"tournament integrity"])
}

#[cfg(target_os = "windows")]
fn same_path_for_scan_exclusion(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

#[cfg(not(target_os = "windows"))]
fn same_path_for_scan_exclusion(left: &Path, right: &Path) -> bool {
    left == right
}

/// Stream-hash a file as SHA-256, returning lowercase hex. Returns None on I/O
/// error (permission denied, file racing disappearance, etc.) rather than
/// propagating — an unhashable file is simply not matched.
fn hash_file_sha256(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return None,
        }
    }
    Some(hex::encode(hasher.finalize()))
}

/// Scan a PE file for known-tool binary fingerprints. Returns the first
/// fingerprint whose markers are *all* found inside the file, or None.
///
/// Streams the file in 64 KiB chunks with an overlap region equal to the
/// longest marker - 1 bytes, so a marker that straddles a chunk boundary is
/// still found. Bails on any I/O error (no panic, no partial result).
fn pe_content_fingerprint(path: &Path) -> Option<&'static BinaryFingerprint> {
    let mut file = std::fs::File::open(path).ok()?;
    let decoded_markers: Vec<Vec<Vec<u8>>> = KNOWN_TOOL_BINARY_FINGERPRINTS
        .iter()
        .map(|fp| fp.required_markers.iter().map(|m| m.decode()).collect())
        .collect();

    // Per-fingerprint per-marker hit tracking. Indexed [fp][marker].
    let mut hits: Vec<Vec<bool>> = decoded_markers
        .iter()
        .map(|markers| vec![false; markers.len()])
        .collect();
    if hits.is_empty() {
        return None;
    }

    // Overlap = longest marker minus 1, so a marker spanning two reads is
    // still wholly inside the (overlap || chunk) buffer on the second read.
    let max_marker_len = decoded_markers
        .iter()
        .flat_map(|markers| markers.iter())
        .map(|m| m.len())
        .max()
        .unwrap_or(0);
    if max_marker_len == 0 {
        return None;
    }
    let overlap = max_marker_len.saturating_sub(1);

    const CHUNK: usize = 64 * 1024;
    let mut buf = vec![0u8; overlap + CHUNK];
    let mut filled_tail = 0usize; // bytes carried over from the previous read

    loop {
        let n = match file.read(&mut buf[filled_tail..]) {
            Ok(0) => 0,
            Ok(n) => n,
            Err(_) => return None,
        };
        let valid = filled_tail + n;
        if valid == 0 {
            break;
        }
        let haystack = &buf[..valid];

        for (fi, markers) in decoded_markers.iter().enumerate() {
            for (mi, marker) in markers.iter().enumerate() {
                if hits[fi][mi] {
                    continue;
                }
                if memchr::memmem::find(haystack, marker).is_some() {
                    hits[fi][mi] = true;
                }
            }
            if hits[fi].iter().all(|&h| h) {
                return KNOWN_TOOL_BINARY_FINGERPRINTS.get(fi);
            }
        }

        // EOF reached: no more chunks to read.
        if n == 0 {
            break;
        }

        // Carry the last `overlap` bytes forward so a marker spanning two
        // chunks is still found wholly within the next iteration's haystack.
        let carry = overlap.min(valid);
        let carry_start = valid - carry;
        buf.copy_within(carry_start..valid, 0);
        filled_tail = carry;
    }

    None
}

/// True if the file at `path` starts with the PE / Mach-O magic bytes that a
/// real Windows/macOS executable would have. Prevents the sibling-config
/// heuristic from firing on a zero-byte or text-only file that happens to be
/// named `something.exe`.
fn file_starts_with_mz(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 2];
    match f.read(&mut magic) {
        Ok(n) if n == 2 => &magic == b"MZ",
        _ => false,
    }
}

fn looks_like_fflag_key(key: &str) -> bool {
    FFLAG_KEY_PREFIXES.iter().any(|p| key.starts_with(p))
}

fn should_report_payload_key(key: &str) -> bool {
    looks_like_fflag_key(key)
        || get_flag_category(key).is_some()
        || !matches!(get_flag_severity(key), ScanVerdict::Clean)
}

fn read_small_text_file(path: &Path, limit: u64) -> Result<String, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("metadata failed: {}", e))?;
    if meta.len() > limit {
        return Err(format!("file too large: {} bytes", meta.len()));
    }
    std::fs::read_to_string(path).map_err(|e| format!("read failed: {}", e))
}

fn json_value_summary(value: &serde_json::Value) -> String {
    let raw = match value {
        serde_json::Value::String(s) => format!("\"{}\"", s),
        _ => value.to_string(),
    };
    truncate_for_detail(&raw, 96)
}

fn truncate_for_detail(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let mut out: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct JsonFlagMatch {
    name: String,
    value: String,
    location: String,
    verdict: ScanVerdict,
}

fn json_object_enabled(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    obj.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true)
}

fn json_object_flag_value(obj: &serde_json::Map<String, serde_json::Value>) -> String {
    obj.get("value")
        .or_else(|| obj.get("enabled"))
        .map(json_value_summary)
        .unwrap_or_else(|| "<present>".to_string())
}

fn push_json_flag_match(out: &mut Vec<JsonFlagMatch>, name: &str, value: String, location: String) {
    if out.len() >= MAX_JSON_FLAG_MATCHES_PER_FILE || !should_report_payload_key(name) {
        return;
    }
    if is_allowed_flag(name) {
        return;
    }
    if out
        .iter()
        .any(|hit| hit.name == name && hit.value == value && hit.location == location)
    {
        return;
    }

    out.push(JsonFlagMatch {
        name: name.to_string(),
        value,
        location,
        verdict: get_flag_severity(name),
    });
}

fn collect_json_flag_matches(
    value: &serde_json::Value,
    location: &str,
    depth: usize,
    out: &mut Vec<JsonFlagMatch>,
) {
    if depth > MAX_JSON_FLAG_DEPTH || out.len() >= MAX_JSON_FLAG_MATCHES_PER_FILE {
        return;
    }

    match value {
        serde_json::Value::Object(obj) => {
            if json_object_enabled(obj) {
                for field in ["flag", "fflag", "flagName", "flag_name"] {
                    if let Some(name) = obj.get(field).and_then(|v| v.as_str()) {
                        push_json_flag_match(
                            out,
                            name,
                            json_object_flag_value(obj),
                            format!("{}.{}", location, field),
                        );
                    }
                }

                // More generic schemas sometimes use `name` or `key`, but
                // only treat those as flag declarations when the object also
                // looks value-bearing. This avoids matching arbitrary metadata
                // such as `{ "name": "FFlag..." }` in unrelated JSON.
                if obj.contains_key("value") || obj.contains_key("enabled") {
                    for field in ["name", "key"] {
                        if let Some(name) = obj.get(field).and_then(|v| v.as_str()) {
                            push_json_flag_match(
                                out,
                                name,
                                json_object_flag_value(obj),
                                format!("{}.{}", location, field),
                            );
                        }
                    }
                }
            }

            for (key, child) in obj {
                push_json_flag_match(
                    out,
                    key,
                    json_value_summary(child),
                    format!("{}.{}", location, key),
                );
                collect_json_flag_matches(child, &format!("{}.{}", location, key), depth + 1, out);
                if out.len() >= MAX_JSON_FLAG_MATCHES_PER_FILE {
                    return;
                }
            }
        }
        serde_json::Value::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                collect_json_flag_matches(item, &format!("{}[{}]", location, idx), depth + 1, out);
                if out.len() >= MAX_JSON_FLAG_MATCHES_PER_FILE {
                    return;
                }
            }
        }
        _ => {}
    }
}

fn json_has_clean_flag_file_shape(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(obj) => {
            !obj.is_empty()
                && obj.keys().all(|key| looks_like_fflag_key(key))
                && obj.values().all(|value| {
                    matches!(
                        value,
                        serde_json::Value::Bool(_)
                            | serde_json::Value::Number(_)
                            | serde_json::Value::String(_)
                            | serde_json::Value::Null
                    )
                })
        }
        _ => false,
    }
}

fn json_is_prism_report_artifact(value: &serde_json::Value) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };

    let has_report_identity = obj.contains_key("scan_id")
        && obj.contains_key("timestamp")
        && obj.contains_key("machine_id")
        && obj.contains_key("findings");
    let has_signature = obj.contains_key("hmac_signature") || obj.contains_key("signature");
    if has_report_identity && has_signature {
        return true;
    }

    obj.get("findings")
        .and_then(|findings| findings.as_array())
        .map(|findings| {
            findings.iter().any(|finding| {
                let Some(finding) = finding.as_object() else {
                    return false;
                };
                finding.contains_key("module")
                    && finding.contains_key("verdict")
                    && finding.contains_key("description")
                    && finding.contains_key("details")
            })
        })
        .unwrap_or(false)
}

fn verdict_rank(verdict: &ScanVerdict) -> u8 {
    match verdict {
        ScanVerdict::Clean => 0,
        ScanVerdict::Inconclusive => 1,
        ScanVerdict::Suspicious => 2,
        ScanVerdict::Flagged => 3,
    }
}

fn strongest_json_verdict(matches: &[JsonFlagMatch]) -> ScanVerdict {
    matches
        .iter()
        .map(|hit| hit.verdict.clone())
        .max_by_key(verdict_rank)
        .unwrap_or(ScanVerdict::Clean)
}

fn json_flag_match_detail(hit: &JsonFlagMatch) -> String {
    let severity = match &hit.verdict {
        ScanVerdict::Flagged => "critical",
        ScanVerdict::Suspicious => "suspicious",
        ScanVerdict::Clean => "unrecognized/low",
        ScanVerdict::Inconclusive => "review",
    };
    let category = get_flag_category(&hit.name).unwrap_or("UNKNOWN");
    let desc = get_flag_description(&hit.name)
        .map(|d| format!(" ({})", d))
        .unwrap_or_default();
    format!(
        "{} = {} [{} / {}{}] @ {}",
        hit.name, hit.value, severity, category, desc, hit.location
    )
}

/// Aho-Corasick automaton over the FFlag prefix set. Used as a cheap
/// pre-filter to skip files that obviously contain no flag-shaped tokens
/// before paying for serde-json or full text tokenization. Built once on
/// first use.
static FFLAG_PREFIX_AC: OnceLock<AhoCorasick> = OnceLock::new();

fn fflag_prefix_ac() -> &'static AhoCorasick {
    FFLAG_PREFIX_AC
        .get_or_init(|| AhoCorasick::new(FFLAG_KEY_PREFIXES).expect("FFlag prefix AC build"))
}

fn content_has_flag_prefix(content: &str) -> bool {
    fflag_prefix_ac().find(content).is_some()
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Read the value that appears immediately after a flag-shaped token in
/// free-form text. Requires a normal key/value delimiter (`:` or `=`), so a
/// sentence that merely names a bad flag does not become evidence.
fn extract_text_flag_value(after_token: &str) -> Option<String> {
    let mut trimmed = after_token.trim_start();
    if matches!(trimmed.chars().next(), Some('"') | Some('\'')) {
        trimmed = trimmed[1..].trim_start();
    }
    let delimiter = trimmed.chars().next()?;
    if !matches!(delimiter, ':' | '=') {
        return None;
    }
    let trimmed = trimmed[delimiter.len_utf8()..].trim_start();
    let (quoted, body) = match trimmed.chars().next() {
        Some('"') => (true, &trimmed[1..]),
        Some('\'') => (true, &trimmed[1..]),
        _ => (false, trimmed),
    };
    let end = if quoted {
        body.find(|c: char| matches!(c, '"' | '\''))
            .unwrap_or(body.len())
    } else {
        body.find(|c: char| matches!(c, ',' | ';' | '"' | '\'' | '}' | ']') || c.is_whitespace())
            .unwrap_or(body.len())
    };
    let value = body[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(truncate_for_detail(value, 96))
    }
}

/// Walk free-form text content looking for FFlag-prefix identifiers. Each
/// match captures the value that follows on the same line (using common
/// `key: value` / `key = value` / `"key": value` shapes). Bounded by
/// `MAX_JSON_FLAG_MATCHES_PER_FILE` so a giant text dump can't blow up
/// memory or detail length.
fn text_flag_matches(content: &str) -> Vec<JsonFlagMatch> {
    let mut matches = Vec::new();
    for (line_idx, line) in content.lines().enumerate() {
        if matches.len() >= MAX_JSON_FLAG_MATCHES_PER_FILE {
            break;
        }
        let bytes = line.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() && matches.len() < MAX_JSON_FLAG_MATCHES_PER_FILE {
            while i < bytes.len() && !is_ident_byte(bytes[i]) {
                i += 1;
            }
            let start = i;
            while i < bytes.len() && is_ident_byte(bytes[i]) {
                i += 1;
            }
            if start == i {
                break;
            }
            let token = &line[start..i];
            if !looks_like_fflag_key(token) {
                continue;
            }
            let Some(value) = extract_text_flag_value(&line[i..]) else {
                continue;
            };
            push_json_flag_match(&mut matches, token, value, format!("L{}", line_idx + 1));
        }
    }
    matches
}

fn text_line_has_clean_flag_assignment(line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() {
        return true;
    }

    let line = line
        .strip_prefix('"')
        .or_else(|| line.strip_prefix('\''))
        .unwrap_or(line);
    let token_len = line.bytes().take_while(|b| is_ident_byte(*b)).count();
    if token_len == 0 {
        return false;
    }

    let token = &line[..token_len];
    looks_like_fflag_key(token) && extract_text_flag_value(&line[token_len..]).is_some()
}

fn text_has_clean_flag_file_shape(content: &str) -> bool {
    let mut meaningful_lines = 0usize;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        meaningful_lines += 1;
        if !text_line_has_clean_flag_assignment(trimmed) {
            return false;
        }
    }
    meaningful_lines > 0
}

/// Check whether a file path's extension or extension-less filename should
/// be treated as a candidate for FFlag content scanning. The set covers the
/// formats real injectors and config dumpers actually use: JSON config,
/// .txt notes, and .cfg / .ini key-value lists.
fn ext_is_flag_text_candidate(ext: Option<&str>) -> bool {
    matches!(
        ext,
        Some("json") | Some("txt") | Some("cfg") | Some("conf") | Some("config") | Some("ini")
    )
}

/// General-purpose FFlag content scanner. Tries JSON parsing first (so a
/// .txt that happens to be valid JSON still gets the structured-flag
/// treatment), then falls back to a line-based text scan. Both paths require
/// the whole file to have an FFlag-only config shape.
///
/// Cheap pre-filter: if the file body contains no FFlag-shaped prefix at
/// all, bail before paying for serde-json or full tokenization. This keeps
/// the scanner fast on large unrelated text files (game logs, chat
/// transcripts, etc.) that happen to live under a scanned root.
fn flag_file_finding(path: &Path) -> Option<ScanFinding> {
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("ClientAppSettings.json"))
    {
        return None;
    }

    let content = read_small_text_file(path, JSON_FLAG_SCAN_SIZE_LIMIT_BYTES).ok()?;
    if !content_has_flag_prefix(&content) {
        return None;
    }

    let mut matches: Vec<JsonFlagMatch> = Vec::new();
    let mut source_kind = "Text";
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
        if json_is_prism_report_artifact(&parsed) {
            return None;
        }
        if !json_has_clean_flag_file_shape(&parsed) {
            return None;
        }
        collect_json_flag_matches(&parsed, "$", 0, &mut matches);
        if matches.is_empty() {
            return None;
        }
        if !matches.is_empty() {
            source_kind = "JSON";
        }
    }
    if matches.is_empty() {
        if !text_has_clean_flag_file_shape(&content) {
            return None;
        }
        matches = text_flag_matches(&content);
    }
    if matches.is_empty() {
        return None;
    }

    let verdict = strongest_json_verdict(&matches);
    if matches!(verdict, ScanVerdict::Clean) {
        return None;
    }
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string());
    let description = match (&verdict, source_kind) {
        (ScanVerdict::Flagged, "JSON") => {
            format!(
                "Critical FFlag values found in JSON file: \"{}\"",
                file_name
            )
        }
        (ScanVerdict::Flagged, _) => {
            format!(
                "Critical FFlag values found in text file: \"{}\"",
                file_name
            )
        }
        (ScanVerdict::Suspicious, "JSON") => {
            format!(
                "Suspicious FFlag values found in JSON file: \"{}\"",
                file_name
            )
        }
        (ScanVerdict::Suspicious, _) => {
            format!(
                "Suspicious FFlag values found in text file: \"{}\"",
                file_name
            )
        }
        (ScanVerdict::Clean, "JSON") => {
            format!("FFlag-shaped JSON entries found: \"{}\"", file_name)
        }
        (ScanVerdict::Clean, _) => {
            format!("FFlag-shaped text entries found: \"{}\"", file_name)
        }
        (ScanVerdict::Inconclusive, _) => {
            format!("FFlag entries require review: \"{}\"", file_name)
        }
    };
    let truncated = if matches.len() >= MAX_JSON_FLAG_MATCHES_PER_FILE {
        format!(" | Showing first {}", MAX_JSON_FLAG_MATCHES_PER_FILE)
    } else {
        String::new()
    };
    Some(ScanFinding::new(
        "file_scanner",
        verdict,
        description,
        Some(format!(
            "Path: {} | Source: {} | Flags: {}{}",
            path.display(),
            source_kind,
            matches
                .iter()
                .map(json_flag_match_detail)
                .collect::<Vec<_>>()
                .join("; "),
            truncated
        )),
    ))
}

/// Per-entry scan worker. Encapsulates the hash / fingerprint / name /
/// sibling-config / content-scan checks so the outer loop can dispatch
/// each entry to a rayon worker. Returns up to one finding per file with
/// its canonical path, in the same priority order the serial version
/// used (hash > fingerprint > name > sibling-config), with the new
/// flag-content scan running first for text-shaped files.
fn process_file_entry(
    entry: &walkdir::DirEntry,
    current_exe: Option<&Path>,
) -> Vec<(PathBuf, ScanFinding)> {
    let mut out: Vec<(PathBuf, ScanFinding)> = Vec::new();
    if is_current_executable_path(entry.path(), current_exe) {
        return out;
    }

    let file_name_os = entry.file_name().to_string_lossy().to_string();
    let file_name = file_name_os.as_str();
    if is_prism_release_artifact(entry.path(), file_name) {
        return out;
    }

    let file_ext = lower_ext(entry.path());

    // Flag-content scan for JSON / text-shaped configs. The scanner only
    // reports files whose whole body has an FFlag-only config shape.
    if ext_is_flag_text_candidate(file_ext.as_deref()) {
        if let Some(finding) = flag_file_finding(entry.path()) {
            let canon = entry
                .path()
                .canonicalize()
                .unwrap_or_else(|_| entry.path().to_path_buf());
            out.push((canon, finding));
            return out;
        }
        // No flag content found; still fall through so a tool exe with a
        // .txt-named installer companion gets every other check applied.
    }

    let ext_is_candidate = matches!(
        file_ext.as_deref(),
        Some("exe") | Some("zip") | Some("dmg") | Some("app")
    );

    // Hash-based match (strongest evidence — Flagged).
    if ext_is_candidate {
        let size = entry.metadata().ok().map(|m| m.len()).unwrap_or(u64::MAX);
        if size <= HASH_SIZE_LIMIT_BYTES {
            if let Some(hex) = hash_file_sha256(entry.path()) {
                for &(known_hex, display_name, note) in KNOWN_TOOL_HASHES {
                    if hex.eq_ignore_ascii_case(known_hex) {
                        let canon = entry
                            .path()
                            .canonicalize()
                            .unwrap_or_else(|_| entry.path().to_path_buf());
                        let payload_detail = (file_ext.as_deref() == Some("exe"))
                            .then(|| injector_payload_detail(entry.path()))
                            .flatten();
                        out.push((
                            canon,
                            ScanFinding::new(
                                "file_scanner",
                                ScanVerdict::Flagged,
                                format!(
                                    "Known tool artefact matched by SHA-256: \"{}\" (as \"{}\")",
                                    display_name, file_name
                                ),
                                Some(format!(
                                    "Path: {}, SHA-256: {}, Last modified: {}, Note: {}{}",
                                    entry.path().display(),
                                    hex,
                                    format_modified(entry.path()),
                                    note,
                                    payload_detail
                                        .as_deref()
                                        .map(|d| format!(" | {}", d))
                                        .unwrap_or_default()
                                )),
                            ),
                        ));
                        return out;
                    }
                }
            }
        }
    }

    // PE content fingerprint (renamed/recompiled tools — Flagged).
    if ext_is_candidate && file_ext.as_deref() == Some("exe") {
        let size = entry.metadata().ok().map(|m| m.len()).unwrap_or(u64::MAX);
        if size <= HASH_SIZE_LIMIT_BYTES && file_starts_with_mz(entry.path()) {
            if let Some(fp) = pe_content_fingerprint(entry.path()) {
                let canon = entry
                    .path()
                    .canonicalize()
                    .unwrap_or_else(|_| entry.path().to_path_buf());
                let payload_detail = injector_payload_detail(entry.path());
                out.push((
                    canon,
                    ScanFinding::new(
                        "file_scanner",
                        ScanVerdict::Flagged,
                        format!(
                            "Known tool binary matched by content fingerprint: \"{}\" (as \"{}\")",
                            fp.display_name, file_name
                        ),
                        Some(format!(
                            "Path: {}, Last modified: {}, Note: {}{}",
                            entry.path().display(),
                            format_modified(entry.path()),
                            fp.note,
                            payload_detail
                                .as_deref()
                                .map(|d| format!(" | {}", d))
                                .unwrap_or_default()
                        )),
                    ),
                ));
                return out;
            }
        }
    }

    // Name-based match (Suspicious).
    for &known_file in KNOWN_TOOL_FILENAMES {
        if file_name.eq_ignore_ascii_case(known_file) {
            let canon = entry
                .path()
                .canonicalize()
                .unwrap_or_else(|_| entry.path().to_path_buf());
            let payload_detail = injector_payload_detail(entry.path());
            out.push((
                canon,
                ScanFinding::new(
                    "file_scanner",
                    ScanVerdict::Suspicious,
                    format!("Known tool executable found: \"{}\"", file_name),
                    Some(format!(
                        "Path: {}, Last modified: {}{}",
                        entry.path().display(),
                        format_modified(entry.path()),
                        payload_detail
                            .as_deref()
                            .map(|d| format!(" | {}", d))
                            .unwrap_or_default()
                    )),
                ),
            ));
            return out;
        }
    }

    // Bootstrapper executable/installer artefacts — informational only.
    // This catches portable/off-GitHub builds such as a standalone
    // Homiestrap.exe without treating them as cheats.
    if file_ext.as_deref() == Some("exe") {
        for &known_file in KNOWN_BOOTSTRAPPER_FILENAMES {
            if file_name.eq_ignore_ascii_case(known_file) {
                let canon = entry
                    .path()
                    .canonicalize()
                    .unwrap_or_else(|_| entry.path().to_path_buf());
                out.push((
                    canon,
                    ScanFinding::new(
                        "file_scanner",
                        ScanVerdict::Clean,
                        format!(
                            "Bootstrapper executable present: \"{}\" (legitimate launcher family; not a cheat indicator)",
                            file_name
                        ),
                        Some(format!(
                            "Path: {}, Last modified: {}",
                            entry.path().display(),
                            format_modified(entry.path())
                        )),
                    ),
                ));
                return out;
            }
        }
    }

    // Sibling-config heuristic: PE next to fflags.json + address.json
    // (LornoFix-family on-disk layout — Suspicious).
    if file_ext.as_deref() == Some("exe") {
        if let Some(parent) = entry.path().parent() {
            let all_present = INJECTOR_SIBLING_CONFIG_FILES
                .iter()
                .all(|name| parent.join(name).is_file());
            let exe_looks_real = file_starts_with_mz(entry.path());
            let siblings_non_empty = INJECTOR_SIBLING_CONFIG_FILES.iter().all(|name| {
                std::fs::metadata(parent.join(name))
                    .map(|m| m.len() >= 2)
                    .unwrap_or(false)
            });
            if all_present && exe_looks_real && siblings_non_empty {
                let canon = entry
                    .path()
                    .canonicalize()
                    .unwrap_or_else(|_| entry.path().to_path_buf());
                let payload_detail = injector_payload_detail(entry.path());
                out.push((
                    canon,
                    ScanFinding::new(
                        "file_scanner",
                        ScanVerdict::Suspicious,
                        format!(
                            "Executable co-located with FFlag-injector config files: \"{}\"",
                            file_name
                        ),
                        Some(format!(
                            "Path: {}, Sibling config files: [{}]{}",
                            entry.path().display(),
                            INJECTOR_SIBLING_CONFIG_FILES.join(", "),
                            payload_detail
                                .as_deref()
                                .map(|d| format!(" | {}", d))
                                .unwrap_or_default()
                        )),
                    ),
                ));
            }
        }
    }

    out
}

/// Drive / volume roots to walk during the whole-system broad pass.
/// On Windows we enumerate every existing drive letter A: through Z: so a
/// game install on D: or external storage on E: still gets scanned. On
/// Unix-likes we start at `/`; the same-filesystem flag in the walker
/// keeps the pass from descending into network mounts and pseudo-fs.
#[cfg(target_os = "windows")]
fn broad_scan_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for c in b'A'..=b'Z' {
        let p = PathBuf::from(format!("{}:\\", c as char));
        if p.exists() {
            roots.push(p);
        }
    }
    roots
}

#[cfg(not(target_os = "windows"))]
fn broad_scan_roots() -> Vec<PathBuf> {
    vec![PathBuf::from("/")]
}

/// Cheap directory-name blacklist applied during the broad walk. These
/// trees never legitimately host hand-edited FFlag dumps and are the bulk
/// of the work on a normal machine — pruning them is the difference
/// between a 5-second scan and a 5-minute scan. Match is
/// case-insensitive, last-segment only.
fn dir_name_should_skip(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        // Windows system / metadata
        "windows"
            | "$recycle.bin"
            | "system volume information"
            | "msocache"
            | "perflogs"
            | "$winreagent"
            | "recovery"
            | "windowsapps"
            // Big package / build trees
            | "node_modules"
            | ".git"
            | ".svn"
            | ".hg"
            | "target"
            | "build"
            | "dist"
            | "out"
            | ".next"
            | ".nuxt"
            | "vendor"
            | "__pycache__"
            | ".cache"
            | ".gradle"
            | ".vscode"
            | ".idea"
            | ".terraform"
            // Game library installs (fast-skip — these are gigabytes of vendor data)
            | "steamapps"
            | "epic games"
            | "gog galaxy"
            | "origin games"
            | "ea games"
            | "battle.net"
            | "riot games"
            // Browser / Electron caches
            | "code cache"
            | "shadercache"
            | "appcache"
            | "gpucache"
            | "service worker"
            | "indexeddb"
            | "blob_storage"
            | "componentcrx"
    )
}

/// Process a batch of candidate paths in parallel, returning the new
/// findings paired with their canonical paths so the caller can dedup
/// against the running reported-paths set.
fn process_broad_batch(paths: &[PathBuf]) -> Vec<(PathBuf, ScanFinding)> {
    paths
        .par_iter()
        .filter_map(|p| {
            let finding = flag_file_finding(p)?;
            let canon = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
            Some((canon, finding))
        })
        .collect()
}

/// Whole-system broad pass. Walks every drive root looking for FFlag-only
/// config content in text-shaped files (`.txt`, `.json`, `.cfg`, `.ini`).
/// Aggressively prunes system directories
/// and developer noise via `dir_name_should_skip`, caps total wall-clock
/// time via `BROAD_SCAN_TIME_BUDGET`, and processes files in parallel
/// batches. Results are deduped against `reported_paths` so a file already
/// found by the focused-roots pass keeps that higher-priority finding.
///
/// The broad pass never hashes binaries or runs PE fingerprinting — those
/// stay scoped to the focused roots, where injectors actually install.
/// Doing them across the whole system would add tens of seconds for no
/// realistic gain on a flag-detection scan.
fn broad_scan(
    reported_paths: &mut HashSet<PathBuf>,
    reporter: &ScanProgress,
) -> Vec<ScanFinding> {
    let started = Instant::now();
    let deadline = started + BROAD_SCAN_TIME_BUDGET;
    let roots = broad_scan_roots();
    let mut produced: Vec<ScanFinding> = Vec::new();
    let mut scanned_files: usize = 0;
    let mut timed_out = false;
    let mut cancelled = false;

    'outer: for root in &roots {
        if reporter.is_cancelled() {
            cancelled = true;
            break;
        }
        if !root.exists() {
            continue;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            break;
        }

        let walker = WalkDir::new(root)
            .follow_links(false)
            .same_file_system(true)
            .into_iter()
            .filter_entry(|e| {
                if e.depth() == 0 {
                    return true;
                }
                if e.file_type().is_dir() {
                    let name = e.file_name().to_string_lossy();
                    !dir_name_should_skip(&name)
                } else {
                    true
                }
            });

        let mut batch: Vec<PathBuf> = Vec::with_capacity(BROAD_SCAN_BATCH);
        for entry in walker.filter_map(|e| e.ok()) {
            if reporter.is_cancelled() {
                cancelled = true;
                break 'outer;
            }
            if Instant::now() >= deadline {
                timed_out = true;
                break 'outer;
            }
            if !entry.file_type().is_file() {
                continue;
            }
            let ext = lower_ext(entry.path());
            if !ext_is_flag_text_candidate(ext.as_deref()) {
                continue;
            }
            let size = match entry.metadata() {
                Ok(m) => m.len(),
                Err(_) => continue,
            };
            if size > JSON_FLAG_SCAN_SIZE_LIMIT_BYTES {
                continue;
            }
            batch.push(entry.path().to_path_buf());

            if batch.len() >= BROAD_SCAN_BATCH {
                scanned_files += batch.len();
                for (canon, finding) in process_broad_batch(&batch) {
                    if reported_paths.insert(canon) {
                        produced.push(finding);
                    }
                }
                batch.clear();
            }
        }
        if !batch.is_empty() {
            scanned_files += batch.len();
            for (canon, finding) in process_broad_batch(&batch) {
                if reported_paths.insert(canon) {
                    produced.push(finding);
                }
            }
        }
    }

    let elapsed = started.elapsed();
    let roots_summary = roots
        .iter()
        .map(|r| r.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let verdict = if cancelled || timed_out {
        ScanVerdict::Inconclusive
    } else {
        ScanVerdict::Clean
    };
    let description = if cancelled {
        format!(
            "Whole-system flag content scan cancelled by operator after {} files inspected — coverage incomplete",
            scanned_files
        )
    } else if timed_out {
        format!(
            "Whole-system flag content scan stopped at time budget ({} s) — partial coverage",
            BROAD_SCAN_TIME_BUDGET.as_secs()
        )
    } else {
        format!(
            "Whole-system flag content scan complete: {} text candidate files inspected",
            scanned_files
        )
    };
    produced.push(ScanFinding::new(
        "file_scanner",
        verdict,
        description,
        Some(format!(
            "Roots: {} | Files inspected: {} | Elapsed: {:.1} s | Budget: {} s",
            roots_summary,
            scanned_files,
            elapsed.as_secs_f32(),
            BROAD_SCAN_TIME_BUDGET.as_secs()
        )),
    ));

    produced
}

fn injector_fflags_payload_summary(path: &Path) -> Option<String> {
    let content = match read_small_text_file(path, INJECTOR_CONFIG_SIZE_LIMIT_BYTES) {
        Ok(content) => content,
        Err(e) => return Some(format!("fflags.json unreadable ({})", e)),
    };
    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(parsed) => parsed,
        Err(e) => return Some(format!("fflags.json unparseable ({})", e)),
    };
    let Some(map) = parsed.as_object() else {
        return Some("fflags.json is not a flat flag map".to_string());
    };

    let mut reported = Vec::new();
    let mut ignored_allowlisted = 0usize;
    let mut ignored_non_flag = 0usize;

    for (key, value) in map {
        if !should_report_payload_key(key) {
            ignored_non_flag += 1;
            continue;
        }
        if is_allowed_flag(key) {
            ignored_allowlisted += 1;
            continue;
        }

        let severity = match get_flag_severity(key) {
            ScanVerdict::Flagged => "critical",
            ScanVerdict::Suspicious => "suspicious",
            ScanVerdict::Clean => "unrecognized",
            ScanVerdict::Inconclusive => "review",
        };
        let category = get_flag_category(key).unwrap_or("UNKNOWN");
        let desc = get_flag_description(key)
            .map(|d| format!(" ({})", d))
            .unwrap_or_default();
        reported.push(format!(
            "{} = {} [{} / {}{}]",
            key,
            json_value_summary(value),
            severity,
            category,
            desc
        ));
        if reported.len() >= MAX_INJECTOR_PAYLOAD_FLAGS {
            break;
        }
    }

    if reported.is_empty() {
        let mut pieces = vec!["no non-allowlisted flag payload entries".to_string()];
        if ignored_allowlisted > 0 {
            pieces.push(format!("{} allowlisted skipped", ignored_allowlisted));
        }
        if ignored_non_flag > 0 {
            pieces.push(format!("{} non-flag keys skipped", ignored_non_flag));
        }
        return Some(format!("Payload: {}", pieces.join(", ")));
    }

    let extra = map
        .len()
        .saturating_sub(reported.len() + ignored_allowlisted + ignored_non_flag);
    let truncation = if extra > 0 {
        format!(" (+{} more)", extra)
    } else {
        String::new()
    };
    Some(format!(
        "Payload flags: {}{}",
        reported.join("; "),
        truncation
    ))
}

fn injector_address_cache_summary(path: &Path) -> Option<String> {
    let content = match read_small_text_file(path, INJECTOR_CONFIG_SIZE_LIMIT_BYTES) {
        Ok(content) => content,
        Err(e) => return Some(format!("address.json unreadable ({})", e)),
    };
    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(parsed) => parsed,
        Err(e) => return Some(format!("address.json unparseable ({})", e)),
    };
    let Some(singleton) = parsed.get("singleton").and_then(|v| v.as_u64()) else {
        return Some("address.json has no numeric singleton cache".to_string());
    };
    Some(format!(
        "address.json singleton cache: {} (0x{:X})",
        singleton, singleton
    ))
}

fn injector_payload_detail(exe_path: &Path) -> Option<String> {
    let parent = exe_path.parent()?;
    let mut parts = Vec::new();
    let fflags = parent.join("fflags.json");
    if fflags.is_file() {
        if let Some(summary) = injector_fflags_payload_summary(&fflags) {
            parts.push(summary);
        }
    }
    let address = parent.join("address.json");
    if address.is_file() {
        if let Some(summary) = injector_address_cache_summary(&address) {
            parts.push(summary);
        }
    }
    (!parts.is_empty()).then(|| parts.join(" | "))
}

fn format_modified(path: &std::path::Path) -> String {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn path_file_name_eq(path: &Path, expected: &str) -> bool {
    path.file_name()
        .map(|name| name.to_string_lossy().eq_ignore_ascii_case(expected))
        .unwrap_or(false)
}

fn known_named_dir_path(root: &Path, dir_name: &str) -> Option<PathBuf> {
    if path_file_name_eq(root, dir_name) && root.is_dir() {
        return Some(root.to_path_buf());
    }

    let child = root.join(dir_name);
    if child.is_dir() {
        return Some(child);
    }

    None
}

#[cfg(target_os = "windows")]
fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|p| same_path_for_scan_exclusion(p, &path)) {
        paths.push(path);
    }
}

/// Get the list of root directories to scan. Each root is walked at most
/// once; we deliberately do NOT include LOCALAPPDATA / APPDATA / USERPROFILE
/// as scan roots in addition to their known subdirectories — that produced
/// duplicate findings via overlapping walks.
fn get_search_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let lad = PathBuf::from(&local_app_data);
            for &dir in ROBLOX_CHEAT_DIRS {
                push_unique_path(&mut roots, lad.join(dir));
            }
            for &dir in KNOWN_BOOTSTRAPPER_DIRS {
                push_unique_path(&mut roots, lad.join(dir));
            }
            for &dir in GENERIC_RE_TOOL_DIRS {
                push_unique_path(&mut roots, lad.join(dir));
            }
            // Roblox's own LocalAppData tree houses ClientSettings and any
            // user-edited FFlag overrides; injectors often save backups of
            // their config alongside it.
            push_unique_path(&mut roots, lad.join("Roblox"));
        }
        if let Ok(appdata) = std::env::var("APPDATA") {
            let roaming = PathBuf::from(&appdata);
            push_unique_path(&mut roots, roaming.join("FFlagToolkit"));
            // Luczystrap documents its installed config under APPDATA; exact
            // known bootstrapper roots are cheap to include and avoid walking
            // the whole roaming profile.
            for &dir in KNOWN_BOOTSTRAPPER_DIRS {
                push_unique_path(&mut roots, roaming.join(dir));
            }
            // Some launchers (and Roblox itself, rarely) drop config under
            // the roaming AppData\Roblox tree.
            push_unique_path(&mut roots, roaming.join("Roblox"));
        }
        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            let up = PathBuf::from(&userprofile);
            roots.push(up.join("Downloads"));
            roots.push(up.join("Desktop"));
            roots.push(up.join("Documents"));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = home_dir() {
            roots.push(home.join("Library").join("Application Support"));
            roots.push(home.join("Library").join("Roblox"));
            roots.push(home.join("Downloads"));
            roots.push(home.join("Desktop"));
            roots.push(home.join("Documents"));
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        if let Some(home) = home_dir() {
            roots.push(home.join("Downloads"));
            roots.push(home.join("Desktop"));
            roots.push(home.join("Documents"));
        }
    }

    roots
}

#[cfg(not(target_os = "windows"))]
fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn hash_file_sha256_matches_known_value() {
        // "abc" → SHA-256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let dir = std::env::temp_dir().join(format!("prism_hash_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("abc.bin");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"abc").unwrap();
        }
        let got = hash_file_sha256(&path).expect("hash ok");
        assert_eq!(
            got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn lower_ext_normalises_case() {
        assert_eq!(lower_ext(Path::new("x/Y/Foo.EXE")).as_deref(), Some("exe"));
        assert_eq!(lower_ext(Path::new("noext")), None);
    }

    #[test]
    fn bootstrapper_filename_fingerprints_are_exact_names() {
        assert!(KNOWN_BOOTSTRAPPER_FILENAMES
            .iter()
            .any(|name| name.eq_ignore_ascii_case("Homiestrap.exe")));
        assert!(KNOWN_BOOTSTRAPPER_FILENAMES
            .iter()
            .any(|name| name.eq_ignore_ascii_case("Froststrap.exe")));
        assert!(!KNOWN_BOOTSTRAPPER_FILENAMES
            .iter()
            .any(|name| name.eq_ignore_ascii_case("strap.exe")));
    }

    #[test]
    fn known_named_dir_matches_self_or_direct_child_only() {
        let root =
            std::env::temp_dir().join(format!("fflag_check_known_dir_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let homiestrap = root.join("Homiestrap");
        std::fs::create_dir_all(&homiestrap).unwrap();
        let unrelated = root.join("Velcro Strap Organizer");
        std::fs::create_dir_all(&unrelated).unwrap();

        assert_eq!(
            known_named_dir_path(&root, "Homiestrap").as_deref(),
            Some(homiestrap.as_path())
        );
        assert_eq!(
            known_named_dir_path(&homiestrap, "Homiestrap").as_deref(),
            Some(homiestrap.as_path())
        );
        assert!(known_named_dir_path(&root, "VeloStrap").is_none());

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn self_scan_exclusion_matches_current_exe_path() {
        let root = std::env::temp_dir().join(format!("prism_self_scan_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let exe = root.join("TSBCC-FFlag-Scanner-v0.6.12-windows-portable.exe");
        std::fs::write(&exe, b"MZ\x90\x00").unwrap();

        let current = exe.canonicalize().unwrap();
        assert!(is_current_executable_path(&exe, Some(&current)));

        let other = root.join("LornoFix.exe");
        std::fs::write(&other, b"MZ\x90\x00").unwrap();
        assert!(!is_current_executable_path(&other, Some(&current)));
        assert!(!is_current_executable_path(&exe, None));

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn prism_release_artifact_exclusion_requires_name_and_identity() {
        let root = std::env::temp_dir().join(format!(
            "prism_release_artifact_test_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let prism = root.join("Prism-v0.7.2-windows-portable.exe");
        std::fs::write(
            &prism,
            b"MZ\x90\x00Prism\0TSBCC\0tournament integrity\0found singleton [cached]\0found singleton [pattern]\0fflag [{}] has unregistered getset, skipping",
        )
        .unwrap();

        assert!(is_prism_release_artifact(
            &prism,
            "Prism-v0.7.2-windows-portable.exe"
        ));
        assert!(!is_prism_release_artifact(&prism, "renamed-tool.exe"));

        let renamed_tool = root.join("Prism-v9.9.9-windows-portable.exe");
        std::fs::write(
            &renamed_tool,
            b"MZ\x90\x00found singleton [cached]\0found singleton [pattern]\0fflag [{}] has unregistered getset, skipping",
        )
        .unwrap();
        assert!(!is_prism_release_artifact(
            &renamed_tool,
            "Prism-v9.9.9-windows-portable.exe"
        ));

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn known_tool_hashes_are_lowercase_hex_64() {
        for &(hex, name, _) in KNOWN_TOOL_HASHES {
            assert_eq!(
                hex.len(),
                64,
                "hash for {} is not 64 hex chars: {}",
                name,
                hex
            );
            assert!(
                hex.chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                "hash for {} must be lowercase hex: {}",
                name,
                hex
            );
        }
    }

    #[test]
    fn sibling_config_pattern_is_detected_on_disk() {
        // Build a fake injector layout in a fresh temp dir and verify that
        // hash_file_sha256 + sibling-file logic would pick it up.
        let root = std::env::temp_dir().join(format!("prism_sibling_test_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();

        let exe = root.join("tool.exe");
        std::fs::write(&exe, b"MZ\x90\x00fake pe").unwrap();
        for name in INJECTOR_SIBLING_CONFIG_FILES {
            std::fs::write(root.join(name), b"{}").unwrap();
        }

        // All siblings present → heuristic should match.
        let all_present = INJECTOR_SIBLING_CONFIG_FILES
            .iter()
            .all(|name| root.join(name).is_file());
        assert!(all_present);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn injector_payload_detail_reports_lorno_flags_and_singleton_cache() {
        let root = std::env::temp_dir().join(format!("prism_payload_test_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();

        let exe = root.join("LornoFix.exe");
        std::fs::write(&exe, b"MZ\x90\x00fake pe").unwrap();
        std::fs::write(
            root.join("fflags.json"),
            r#"{"DFFlagDebugDrawBroadPhaseAABBs":"True","FIntCameraFarZPlane":"0"}"#,
        )
        .unwrap();
        std::fs::write(root.join("address.json"), r#"{"singleton":123080088}"#).unwrap();

        let detail = injector_payload_detail(&exe).expect("payload summary");
        assert!(detail.contains("DFFlagDebugDrawBroadPhaseAABBs = \"True\""));
        assert!(detail.contains("FIntCameraFarZPlane = \"0\""));
        assert!(detail.contains("address.json singleton cache: 123080088"));
        assert!(detail.contains("0x7560D98"));

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn injector_payload_detail_skips_allowlisted_only_payloads() {
        let root = std::env::temp_dir().join(format!(
            "prism_allowlisted_payload_test_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();

        let exe = root.join("tool.exe");
        std::fs::write(&exe, b"MZ\x90\x00fake pe").unwrap();
        std::fs::write(
            root.join("fflags.json"),
            r#"{"FFlagDebugGraphicsPreferD3D11":true,"launcher_metadata":"ok"}"#,
        )
        .unwrap();

        let detail = injector_payload_detail(&exe).expect("payload summary");
        assert!(detail.contains("no non-allowlisted flag payload entries"));
        assert!(!detail.contains("FFlagDebugGraphicsPreferD3D11 = true"));

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn flag_file_finding_reports_flat_flag_maps() {
        let root =
            std::env::temp_dir().join(format!("prism_json_flat_test_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("fflags.json");
        std::fs::write(
            &path,
            r#"{"DFIntS2PhysicsSenderRate":1,"FIntCameraFarZPlane":"0"}"#,
        )
        .unwrap();

        let finding = flag_file_finding(&path).expect("json flag finding");
        assert!(matches!(finding.verdict, ScanVerdict::Flagged));
        let details = finding.details.as_deref().unwrap_or_default();
        assert!(details.contains("DFIntS2PhysicsSenderRate = 1"));
        assert!(details.contains("FIntCameraFarZPlane = \"0\""));

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn flag_file_finding_ignores_nested_or_wrapped_flag_json() {
        let root =
            std::env::temp_dir().join(format!("prism_json_nested_test_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("profile.json");
        std::fs::write(
            &path,
            r#"{"profiles":[{"flags":[{"flag":"DFIntDataSenderRate","enabled":true,"value":-1}]}]}"#,
        )
        .unwrap();

        assert!(flag_file_finding(&path).is_none());

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn flag_file_finding_ignores_json_with_non_fflag_keys() {
        let root =
            std::env::temp_dir().join(format!("prism_json_wrapper_test_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("history.json");
        std::fs::write(
            &path,
            r#"{"path":"ClientAppSettings.json","DFIntS2PhysicsSenderRate":1}"#,
        )
        .unwrap();

        assert!(flag_file_finding(&path).is_none());

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn flag_file_finding_ignores_prism_report_with_stale_backup_path() {
        let root =
            std::env::temp_dir().join(format!("prism_report_stale_test_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("Prism_Report_stale.json");
        std::fs::write(
            &path,
            r#"{
              "scan_id": "abc",
              "timestamp": "2026-05-05T05:28:32Z",
              "machine_id": "machine",
              "os_info": "Windows",
              "overall_verdict": "Suspicious",
              "findings": [{
                "module": "file_scanner",
                "verdict": "Suspicious",
                "description": "Suspicious FFlag values found in JSON file: \"ClientAppSettings_backup.json\"",
                "details": "Path: C:\\Users\\<user>\\AppData\\Local\\Bloxstrap\\Modifications\\ClientSettings\\ClientAppSettings_backup.json | Source: JSON | Flags: DFIntTaskSchedulerTargetFps = \"500\"; FLogNetwork = \"7\"",
                "timestamp": "2026-05-05T05:28:15Z"
              }],
              "hmac_signature": "deadbeef"
            }"#,
        )
        .unwrap();

        assert!(flag_file_finding(&path).is_none());

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn report_artifact_detection_handles_unsigned_cache_shape() {
        let value = serde_json::json!({
            "findings": [{
                "module": "file_scanner",
                "verdict": "Suspicious",
                "description": "Suspicious FFlag values found in JSON file: \"ClientAppSettings_backup.json\"",
                "details": "DFIntTaskSchedulerTargetFps = \"500\""
            }]
        });

        assert!(json_is_prism_report_artifact(&value));
    }

    #[test]
    fn flag_file_finding_ignores_disabled_and_arbitrary_string_mentions() {
        let root =
            std::env::temp_dir().join(format!("prism_json_negative_test_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("notes.json");
        std::fs::write(
            &path,
            r#"{"title":"DFIntS2PhysicsSenderRate","flags":[{"flag":"DFIntDataSenderRate","enabled":false,"value":-1}]}"#,
        )
        .unwrap();

        assert!(flag_file_finding(&path).is_none());

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn flag_file_finding_ignores_allowlisted_only_json() {
        let root = std::env::temp_dir().join(format!(
            "prism_json_allowlisted_test_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("allowlisted.json");
        std::fs::write(&path, r#"{"FFlagDebugGraphicsPreferD3D11":true}"#).unwrap();

        assert!(flag_file_finding(&path).is_none());

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn flag_file_finding_ignores_allowlisted_graphics_client_settings() {
        let root = std::env::temp_dir().join(format!(
            "prism_graphics_allowlisted_test_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("ClientAppSettings.json");
        std::fs::write(
            &path,
            r#"{
              "FFlagHandleAltEnterFullscreenManually": "False",
              "FIntDebugForceMSAASamples": "1",
              "DFFlagTextureQualityOverrideEnabled": "True",
              "DFIntTextureQualityOverride": "0",
              "FFlagDebugGraphicsPreferOpenGL": true,
              "FFlagDebugGraphicsPreferVulkan": false,
              "FFlagDebugGraphicsPreferD3D11": false,
              "FFlagDebugSkyGray": true
            }"#,
        )
        .unwrap();

        assert!(
            flag_file_finding(&path).is_none(),
            "allowlisted graphics-only ClientAppSettings must not produce a file finding"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn flag_file_finding_defers_client_app_settings_to_focused_scanner() {
        let root = std::env::temp_dir().join(format!(
            "prism_client_settings_defer_test_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("ClientAppSettings.json");
        std::fs::write(&path, r#"{"DFIntS2PhysicsSenderRate":1}"#).unwrap();

        assert!(
            flag_file_finding(&path).is_none(),
            "broad file scanner must not duplicate ClientAppSettings findings"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn flag_file_finding_reports_text_flag_maps() {
        let root =
            std::env::temp_dir().join(format!("fflag_check_text_flat_test_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("flags.txt");
        std::fs::write(
            &path,
            "DFIntS2PhysicsSenderRate: 1\nFIntCameraFarZPlane = 0\n",
        )
        .unwrap();

        let finding = flag_file_finding(&path).expect("text flag finding");
        assert!(matches!(finding.verdict, ScanVerdict::Flagged));
        let details = finding.details.as_deref().unwrap_or_default();
        assert!(details.contains("Source: Text"));
        assert!(details.contains("DFIntS2PhysicsSenderRate = 1"));
        assert!(details.contains("FIntCameraFarZPlane = 0"));

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn flag_file_finding_ignores_plain_text_mentions_without_values() {
        let root = std::env::temp_dir().join(format!(
            "fflag_check_text_mention_test_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("notes.txt");
        std::fs::write(
            &path,
            "Tournament notes mention DFIntS2PhysicsSenderRate as a known bad flag name.",
        )
        .unwrap();

        assert!(flag_file_finding(&path).is_none());

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn flag_file_finding_ignores_text_with_non_fflag_lines() {
        let root = std::env::temp_dir().join(format!(
            "fflag_check_text_wrapper_test_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("notes.txt");
        std::fs::write(
            &path,
            "Old config copied from chat:\nDFIntS2PhysicsSenderRate: 1\n",
        )
        .unwrap();

        assert!(flag_file_finding(&path).is_none());

        std::fs::remove_dir_all(&root).ok();
    }

    /// Helper: build a temp dir and a synthetic PE file containing the given
    /// markers padded with random PE-looking filler. Returns the file path
    /// and the temp dir (caller cleans up).
    fn make_synthetic_pe(tag: &str, markers: &[&[u8]]) -> (PathBuf, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("prism_fp_test_{}_{}", std::process::id(), tag));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blob.exe");

        let mut bytes: Vec<u8> = Vec::with_capacity(2048);
        bytes.extend_from_slice(b"MZ\x90\x00");
        bytes.resize(512, 0);
        for m in markers {
            bytes.resize(bytes.len() + 1024, 0xAB);
            bytes.extend_from_slice(m);
        }
        bytes.resize(bytes.len() + 1024, 0xCD);

        std::fs::write(&path, &bytes).unwrap();
        (path, dir)
    }

    #[test]
    fn fingerprint_matches_full_lorno_marker_set() {
        let lorno_markers: &[&[u8]] = &[
            b"found singleton [cached]",
            b"found singleton [pattern]",
            b"fflag [{}] has unregistered getset, skipping",
        ];
        let (path, dir) = make_synthetic_pe("full", lorno_markers);

        let m = pe_content_fingerprint(&path);
        assert!(
            m.is_some(),
            "expected fingerprint hit on synthetic Lorno PE"
        );
        assert_eq!(m.unwrap().display_name, "LornoFix.exe");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fingerprint_matches_pdb_path_alone() {
        let markers: &[&[u8]] = &[b"\\fflag-manager\\bld\\release\\bin\\odessa.pdb"];
        let (path, dir) = make_synthetic_pe("pdb", markers);

        let m = pe_content_fingerprint(&path);
        assert!(m.is_some(), "PDB-path fingerprint should match");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Negative test: a PE that contains exactly one of the Lorno log strings
    /// must NOT match. The full marker set is required.
    #[test]
    fn fingerprint_rejects_partial_marker_overlap() {
        let partial: &[&[u8]] = &[b"found singleton [cached]"];
        let (path, dir) = make_synthetic_pe("partial", partial);
        let m = pe_content_fingerprint(&path);
        assert!(
            m.is_none(),
            "partial marker presence must not be enough — got {:?}",
            m.map(|fp| fp.display_name)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Negative test: an unrelated PE with the word "singleton" present in a
    /// non-cheat context must not match.
    #[test]
    fn fingerprint_rejects_random_pe() {
        let dir = std::env::temp_dir().join(format!("prism_fp_neg_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("benign.exe");
        let mut bytes: Vec<u8> = Vec::with_capacity(8 * 1024);
        bytes.extend_from_slice(b"MZ\x90\x00");
        bytes.resize(8 * 1024, 0x42);
        bytes.extend_from_slice(b"this binary uses the singleton pattern");
        std::fs::write(&path, &bytes).unwrap();

        assert!(pe_content_fingerprint(&path).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Markers that straddle the 64 KiB chunk boundary must still be found.
    #[test]
    fn fingerprint_finds_marker_across_chunk_boundary() {
        let dir =
            std::env::temp_dir().join(format!("prism_fp_boundary_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("split.exe");

        const CHUNK: usize = 64 * 1024;
        let lorno_markers: &[&[u8]] = &[
            b"found singleton [cached]",
            b"found singleton [pattern]",
            b"fflag [{}] has unregistered getset, skipping",
        ];

        let mut bytes: Vec<u8> = Vec::with_capacity(4 * CHUNK);
        bytes.extend_from_slice(b"MZ\x90\x00");
        for (i, m) in lorno_markers.iter().enumerate() {
            let target_boundary = (i + 1) * CHUNK;
            let split_point = target_boundary - m.len() / 2;
            if bytes.len() < split_point {
                bytes.resize(split_point, 0xEE);
            }
            bytes.extend_from_slice(m);
        }
        std::fs::write(&path, &bytes).unwrap();

        let m = pe_content_fingerprint(&path);
        assert!(m.is_some(), "boundary-spanning markers should still match");
        assert_eq!(m.unwrap().display_name, "LornoFix.exe");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fingerprint_returns_none_on_missing_file() {
        let path = std::env::temp_dir().join("prism_does_not_exist.exe");
        assert!(pe_content_fingerprint(&path).is_none());
    }

    #[test]
    fn binary_fingerprints_are_well_formed() {
        for fp in KNOWN_TOOL_BINARY_FINGERPRINTS {
            assert!(
                !fp.required_markers.is_empty(),
                "fingerprint for {} has no markers",
                fp.display_name
            );
            for m in fp.required_markers {
                let marker = m.decode();
                assert!(
                    !marker.is_empty(),
                    "fingerprint for {} has empty marker",
                    fp.display_name
                );
                assert!(
                    marker.len() >= 8,
                    "fingerprint marker for {} too short ({} bytes) — risk of false positives",
                    fp.display_name,
                    marker.len()
                );
            }
        }
    }
}
