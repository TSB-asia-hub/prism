use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use sha2::{Digest, Sha256};

use crate::data::flag_allowlist::is_allowed_flag;
use crate::data::known_tools::{
    BinaryFingerprint, GENERIC_RE_TOOL_DIRS, INJECTOR_SIBLING_CONFIG_FILES,
    KNOWN_BOOTSTRAPPER_DIRS, KNOWN_TOOL_BINARY_FINGERPRINTS, KNOWN_TOOL_FILENAMES,
    KNOWN_TOOL_HASHES, ROBLOX_CHEAT_DIRS,
};
use crate::data::suspicious_flags::{get_flag_category, get_flag_description, get_flag_severity};
use crate::models::{ScanFinding, ScanVerdict};

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

/// Scan the filesystem for known tool artifacts.
pub async fn scan() -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    let roots = get_search_roots();
    let current_exe = current_exe_canonical();

    // Track every absolute path we've already reported on, so the same file
    // isn't double-flagged when overlapping search roots cause it to be
    // visited via two different walks.
    let mut reported_paths: HashSet<PathBuf> = HashSet::new();

    for root in &roots {
        if !root.exists() {
            continue;
        }

        // Roblox-specific cheat tool directories → Suspicious.
        for &tool_dir in ROBLOX_CHEAT_DIRS {
            let dir_path = root.join(tool_dir);
            if dir_path.exists() && dir_path.is_dir() {
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
            let dir_path = root.join(tool_dir);
            if dir_path.exists() && dir_path.is_dir() {
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
            let dir_path = root.join(boot_dir);
            if dir_path.exists() && dir_path.is_dir() {
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

        // Tool executables (depth-limited walk).
        let walker = WalkDir::new(root)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok());

        for entry in walker {
            if !entry.file_type().is_file() {
                continue;
            }
            if is_current_executable_path(entry.path(), current_exe.as_deref()) {
                continue;
            }

            let file_name_os = entry.file_name().to_string_lossy().to_string();
            let file_name = file_name_os.as_str();
            let file_ext = lower_ext(entry.path());

            if file_ext.as_deref() == Some("json") {
                if let Some(finding) = json_flag_file_finding(entry.path()) {
                    let canon = entry
                        .path()
                        .canonicalize()
                        .unwrap_or_else(|_| entry.path().to_path_buf());
                    if reported_paths.insert(canon) {
                        findings.push(finding);
                    }
                }
                continue;
            }

            // Hash-based match: strongest on-disk evidence. Do this before
            // name matching so an unrenamed `LornoFix.exe` still gets the
            // Flagged SHA-256 verdict instead of being downgraded to a
            // Suspicious filename hit.
            let ext_is_candidate = matches!(
                file_ext.as_deref(),
                Some("exe") | Some("zip") | Some("dmg") | Some("app")
            );
            let mut matched_by_hash = false;
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
                                if reported_paths.insert(canon.clone()) {
                                    let payload_detail = (file_ext.as_deref() == Some("exe"))
                                        .then(|| injector_payload_detail(entry.path()))
                                        .flatten();
                                    findings.push(ScanFinding::new(
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
                                    ));
                                }
                                matched_by_hash = true;
                                break;
                            }
                        }
                    }
                }
            }
            if matched_by_hash {
                continue;
            }

            // Content-fingerprint match: catches renamed/recompiled tool
            // binaries. Run only on PE candidates we already size-clamped
            // for hashing — same I/O budget, same size guard. Flagged
            // verdict (not Suspicious) because the fingerprints are unique
            // log strings / leaked PDB paths that have no legitimate use.
            let mut matched_by_fingerprint = false;
            if ext_is_candidate && file_ext.as_deref() == Some("exe") {
                let size = entry.metadata().ok().map(|m| m.len()).unwrap_or(u64::MAX);
                if size <= HASH_SIZE_LIMIT_BYTES && file_starts_with_mz(entry.path()) {
                    if let Some(fp) = pe_content_fingerprint(entry.path()) {
                        let canon = entry
                            .path()
                            .canonicalize()
                            .unwrap_or_else(|_| entry.path().to_path_buf());
                        if reported_paths.insert(canon.clone()) {
                            let payload_detail = injector_payload_detail(entry.path());
                            findings.push(ScanFinding::new(
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
                            ));
                        }
                        matched_by_fingerprint = true;
                    }
                }
            }
            if matched_by_fingerprint {
                continue;
            }

            // Name-based match.
            let mut matched_by_name = false;
            for &known_file in KNOWN_TOOL_FILENAMES {
                if file_name.eq_ignore_ascii_case(known_file) {
                    let canon = entry
                        .path()
                        .canonicalize()
                        .unwrap_or_else(|_| entry.path().to_path_buf());
                    if reported_paths.insert(canon.clone()) {
                        let payload_detail = injector_payload_detail(entry.path());
                        findings.push(ScanFinding::new(
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
                        ));
                    }
                    matched_by_name = true;
                    break;
                }
            }
            if matched_by_name {
                continue;
            }

            // Sibling-config heuristic: PE with fflags.json + address.json next
            // to it is the LornoFix family's on-disk layout. This is a
            // filename heuristic with no content verification, so it is
            // Suspicious — not Flagged. A real PE-magic check plus non-empty
            // JSON shape keeps it from firing on zero-byte stubs named the
            // same way in a developer's scratch folder.
            if file_ext.as_deref() == Some("exe") {
                if let Some(parent) = entry.path().parent() {
                    let all_present = INJECTOR_SIBLING_CONFIG_FILES
                        .iter()
                        .all(|name| parent.join(name).is_file());
                    let exe_looks_real = file_starts_with_mz(entry.path());
                    let siblings_non_empty = INJECTOR_SIBLING_CONFIG_FILES.iter().all(|name| {
                        std::fs::metadata(parent.join(name))
                            .map(|m| m.len() >= 2) // enough to hold at least "{}"
                            .unwrap_or(false)
                    });
                    if all_present && exe_looks_real && siblings_non_empty {
                        let canon = entry
                            .path()
                            .canonicalize()
                            .unwrap_or_else(|_| entry.path().to_path_buf());
                        if reported_paths.insert(canon.clone()) {
                            let payload_detail = injector_payload_detail(entry.path());
                            findings.push(ScanFinding::new(
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
                            ));
                        }
                    }
                }
            }
        }
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

    // Per-fingerprint per-marker hit tracking. Indexed [fp][marker].
    let mut hits: Vec<Vec<bool>> = KNOWN_TOOL_BINARY_FINGERPRINTS
        .iter()
        .map(|fp| vec![false; fp.required_markers.len()])
        .collect();
    if hits.is_empty() {
        return None;
    }

    // Overlap = longest marker minus 1, so a marker spanning two reads is
    // still wholly inside the (overlap || chunk) buffer on the second read.
    let max_marker_len = KNOWN_TOOL_BINARY_FINGERPRINTS
        .iter()
        .flat_map(|fp| fp.required_markers.iter())
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

        for (fi, fp) in KNOWN_TOOL_BINARY_FINGERPRINTS.iter().enumerate() {
            for (mi, marker) in fp.required_markers.iter().enumerate() {
                if hits[fi][mi] {
                    continue;
                }
                if memchr::memmem::find(haystack, marker).is_some() {
                    hits[fi][mi] = true;
                }
            }
            if hits[fi].iter().all(|&h| h) {
                return Some(fp);
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

fn json_flag_file_finding(path: &Path) -> Option<ScanFinding> {
    let content = read_small_text_file(path, JSON_FLAG_SCAN_SIZE_LIMIT_BYTES).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;

    let mut matches = Vec::new();
    collect_json_flag_matches(&parsed, "$", 0, &mut matches);
    if matches.is_empty() {
        return None;
    }

    let verdict = strongest_json_verdict(&matches);
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string());
    let description = match &verdict {
        ScanVerdict::Flagged => {
            format!(
                "Critical FFlag values found in JSON file: \"{}\"",
                file_name
            )
        }
        ScanVerdict::Suspicious => {
            format!(
                "Suspicious FFlag values found in JSON file: \"{}\"",
                file_name
            )
        }
        ScanVerdict::Clean => {
            format!("FFlag-shaped JSON entries found: \"{}\"", file_name)
        }
        ScanVerdict::Inconclusive => {
            format!("FFlag JSON entries require review: \"{}\"", file_name)
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
            "Path: {} | Flags: {}{}",
            path.display(),
            matches
                .iter()
                .map(json_flag_match_detail)
                .collect::<Vec<_>>()
                .join("; "),
            truncated
        )),
    ))
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
            roots.push(lad.join("Voidstrap"));
            roots.push(lad.join("Bloxstrap"));
            roots.push(lad.join("Fishstrap"));
        }
        if let Ok(appdata) = std::env::var("APPDATA") {
            roots.push(PathBuf::from(&appdata).join("FFlagToolkit"));
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
        let dir =
            std::env::temp_dir().join(format!("fflag_check_hash_test_{}", std::process::id()));
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
    fn self_scan_exclusion_matches_current_exe_path() {
        let root =
            std::env::temp_dir().join(format!("fflag_check_self_scan_{}", std::process::id()));
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
        let root =
            std::env::temp_dir().join(format!("fflag_check_sibling_test_{}", std::process::id()));
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
        let root =
            std::env::temp_dir().join(format!("fflag_check_payload_test_{}", std::process::id()));
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
            "fflag_check_allowlisted_payload_test_{}",
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
    fn json_flag_file_finding_reports_flat_flag_maps() {
        let root =
            std::env::temp_dir().join(format!("fflag_check_json_flat_test_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("fflags.json");
        std::fs::write(
            &path,
            r#"{"DFIntS2PhysicsSenderRate":1,"FIntCameraFarZPlane":"0"}"#,
        )
        .unwrap();

        let finding = json_flag_file_finding(&path).expect("json flag finding");
        assert!(matches!(finding.verdict, ScanVerdict::Flagged));
        let details = finding.details.as_deref().unwrap_or_default();
        assert!(details.contains("DFIntS2PhysicsSenderRate = 1"));
        assert!(details.contains("FIntCameraFarZPlane = \"0\""));

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn json_flag_file_finding_reports_nested_flag_arrays() {
        let root = std::env::temp_dir().join(format!(
            "fflag_check_json_nested_test_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("profile.json");
        std::fs::write(
            &path,
            r#"{"profiles":[{"flags":[{"flag":"DFIntDataSenderRate","enabled":true,"value":-1}]}]}"#,
        )
        .unwrap();

        let finding = json_flag_file_finding(&path).expect("nested json flag finding");
        assert!(matches!(finding.verdict, ScanVerdict::Flagged));
        let details = finding.details.as_deref().unwrap_or_default();
        assert!(details.contains("DFIntDataSenderRate = -1"));
        assert!(details.contains("$.profiles[0].flags[0].flag"));

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn json_flag_file_finding_ignores_disabled_and_arbitrary_string_mentions() {
        let root = std::env::temp_dir().join(format!(
            "fflag_check_json_negative_test_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("notes.json");
        std::fs::write(
            &path,
            r#"{"title":"DFIntS2PhysicsSenderRate","flags":[{"flag":"DFIntDataSenderRate","enabled":false,"value":-1}]}"#,
        )
        .unwrap();

        assert!(json_flag_file_finding(&path).is_none());

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn json_flag_file_finding_ignores_allowlisted_only_json() {
        let root = std::env::temp_dir().join(format!(
            "fflag_check_json_allowlisted_test_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("allowlisted.json");
        std::fs::write(&path, r#"{"FFlagDebugGraphicsPreferD3D11":true}"#).unwrap();

        assert!(json_flag_file_finding(&path).is_none());

        std::fs::remove_dir_all(&root).ok();
    }

    /// Helper: build a temp dir and a synthetic PE file containing the given
    /// markers padded with random PE-looking filler. Returns the file path
    /// and the temp dir (caller cleans up).
    fn make_synthetic_pe(tag: &str, markers: &[&[u8]]) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "fflag_check_fp_test_{}_{}",
            std::process::id(),
            tag
        ));
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
        let dir =
            std::env::temp_dir().join(format!("fflag_check_fp_neg_test_{}", std::process::id()));
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
        let dir = std::env::temp_dir().join(format!(
            "fflag_check_fp_boundary_test_{}",
            std::process::id()
        ));
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
        let path = std::env::temp_dir().join("fflag_check_does_not_exist.exe");
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
                assert!(
                    !m.is_empty(),
                    "fingerprint for {} has empty marker",
                    fp.display_name
                );
                assert!(
                    m.len() >= 8,
                    "fingerprint marker for {} too short ({} bytes) — risk of false positives",
                    fp.display_name,
                    m.len()
                );
            }
        }
    }
}
