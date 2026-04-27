#![cfg_attr(
    not(all(target_os = "windows", target_pointer_width = "64")),
    allow(dead_code)
)]

use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

#[cfg(all(target_os = "windows", target_pointer_width = "64"))]
use std::time::Instant;

const SCHEMA_VERSION: u32 = 1;
const DEFAULT_PROCESS_HINT: &str = "robloxplayerbeta";
const DEFAULT_CONTEXT_BYTES: usize = 0;
/// `0` means "record every match". Clean-baseline mapping is explicitly
/// allowed to get noisy; the scan should not stop just because Roblox has
/// thousands of ordinary flag names resident.
const DEFAULT_MAX_MATCHES: usize = 0;
const DEFAULT_MAX_SCAN_BYTES: u64 = u64::MAX;
const DEFAULT_TIMEOUT_SECONDS: u64 = 300;
const MAX_REGIONS_WALKED: usize = 200_000;
const MAX_CHUNK_BYTES: usize = 4 * 1024 * 1024;
const MIN_READ_CHUNK_BYTES: usize = 4 * 1024;
const MAX_IDENT_BODY_LEN: usize = 128;
const MIN_IDENT_BODY_LEN: usize = 3;
const FLAG_PREFIXES: &[&str] = &[
    "DFFlag", "FFlag", "DFInt", "FInt", "DFString", "FString", "DFLog", "FLog", "SFFlag", "SFInt",
    "SFString",
];
const TOOL_MARKERS: &[&str] = &[
    "fflags.json",
    "address.json",
    "fflagtoolkit",
    "fflag_injector",
    "fflag-manager",
    "lorno bypass",
    "lornofix",
    "lornobypass",
    "odessa",
    "robloxoffsetdumper",
    "offset_dumper",
    "writeprocessmemory",
];
const SUSPICIOUS_FLAGS_SOURCE: &str = include_str!("../data/suspicious_flags.rs");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedValue {
    Bool(bool),
    Int(i32),
}

const RUNTIME_RULES: &[(&str, ExpectedValue)] = &[
    ("DFIntS2PhysicsSenderRate", ExpectedValue::Int(1)),
    ("DFIntS2PhysicsSenderRate", ExpectedValue::Int(-30)),
    ("DFIntS2PhysicSenderRate", ExpectedValue::Int(1)),
    ("DFIntPhysicsSenderMaxBandwidthBps", ExpectedValue::Int(1)),
    (
        "DFIntPhysicsSenderMaxBandwidthBpsScaling",
        ExpectedValue::Int(0),
    ),
    ("DFIntDataSenderRate", ExpectedValue::Int(-1)),
    ("DFIntTouchSenderMaxBandwidthBps", ExpectedValue::Int(-1)),
    (
        "DFIntMinClientSimulationRadius",
        ExpectedValue::Int(2_147_000_000),
    ),
    (
        "DFIntMaxClientSimulationRadius",
        ExpectedValue::Int(2_147_000_000),
    ),
    (
        "DFFlagDebugPhysicsSenderDoesNotShrinkSimRadius",
        ExpectedValue::Bool(true),
    ),
    ("FFlagDebugUseCustomSimRadius", ExpectedValue::Bool(true)),
    ("NextGenReplicatorEnabledWrite4", ExpectedValue::Bool(true)),
    ("NextGenReplicatorEnabledRead", ExpectedValue::Bool(true)),
    (
        "DFIntReplicatorAnimationTrackLimitPerAnimator",
        ExpectedValue::Int(-1),
    ),
    (
        "DFIntGameNetPVHeaderTranslationZeroCutoffExponent",
        ExpectedValue::Int(10),
    ),
    (
        "DFIntGameNetPVHeaderLinearVelocityZeroCutoffExponent",
        ExpectedValue::Int(10),
    ),
    (
        "DFIntGameNetPVHeaderRotationalVelocityZeroCutoffExponent",
        ExpectedValue::Int(10),
    ),
    (
        "DFIntAssemblyExtentsExpansionStudHundredth",
        ExpectedValue::Int(-50),
    ),
    (
        "DFIntSimBlockLargeLocalToolWeldManipulationsThreshold",
        ExpectedValue::Int(-1),
    ),
    ("DFIntDebugSimPrimalStiffness", ExpectedValue::Int(0)),
    (
        "DFIntSimAdaptiveHumanoidPDControllerSubstepMultiplier",
        ExpectedValue::Int(-999_999),
    ),
    (
        "DFIntSolidFloorPercentForceApplication",
        ExpectedValue::Int(-1_000),
    ),
    (
        "DFIntNonSolidFloorPercentForceApplication",
        ExpectedValue::Int(-5_000),
    ),
    ("DFIntHipHeightClamp", ExpectedValue::Int(-48)),
    (
        "FIntParallelDynamicPartsFastClusterBatchSize",
        ExpectedValue::Int(-1),
    ),
    ("DFIntRaycastMaxDistance", ExpectedValue::Int(3)),
    (
        "DFIntMaxMissedWorldStepsRemembered",
        ExpectedValue::Int(1_000),
    ),
    ("DFIntMaxActiveAnimationTracks", ExpectedValue::Int(0)),
    ("DFFlagDebugDrawBroadPhaseAABBs", ExpectedValue::Bool(true)),
    ("DFFlagDebugDrawBvhNodes", ExpectedValue::Bool(true)),
    ("FIntCameraFarZPlane", ExpectedValue::Int(0)),
    ("FIntCameraFarZPlane", ExpectedValue::Int(1)),
    ("DFIntDebugRestrictGCDistance", ExpectedValue::Int(1)),
    ("DFIntAnimationLodFacsDistanceMin", ExpectedValue::Int(0)),
    ("DFIntAnimationLodFacsDistanceMax", ExpectedValue::Int(0)),
    ("FIntRenderShadowIntensity", ExpectedValue::Int(0)),
    ("FFlagDisablePostFx", ExpectedValue::Bool(true)),
    ("FFlagDebugDontRenderScreenGui", ExpectedValue::Bool(true)),
    ("FFlagDebugDontRenderUI", ExpectedValue::Bool(true)),
];

#[derive(Debug, Clone)]
struct Args {
    pid: Option<u32>,
    process_hint: String,
    out: Option<PathBuf>,
    context_bytes: usize,
    max_matches: usize,
    max_scan_bytes: u64,
    timeout: Duration,
    scan_images: bool,
    interactive: bool,
}

#[derive(Serialize)]
struct EvidenceExport {
    schema_version: u32,
    created_at: String,
    tool: ToolInfo,
    target: TargetInfo,
    settings: ExportSettings,
    summary: ExportSummary,
    modules: Vec<ModuleInfo>,
    regions: Vec<RegionInfo>,
    matches: Vec<EvidenceMatch>,
    errors: Vec<String>,
}

#[derive(Serialize)]
struct ToolInfo {
    name: &'static str,
    package_version: &'static str,
}

#[derive(Serialize)]
struct TargetInfo {
    pid: u32,
    name: String,
    exe_path: Option<String>,
}

#[derive(Serialize)]
struct ExportSettings {
    process_hint: String,
    context_bytes: usize,
    max_matches: usize,
    max_scan_bytes: u64,
    timeout_seconds: u64,
    scan_images: bool,
}

#[derive(Serialize, Default)]
struct ExportSummary {
    regions_walked: usize,
    regions_scanned: usize,
    regions_skipped: usize,
    bytes_intended: u64,
    bytes_scanned: u64,
    read_failures: usize,
    read_failed_bytes: u64,
    matches_recorded: usize,
    matches_seen: usize,
    matches_dropped_by_cap: usize,
    fflag_identifiers_seen: usize,
    tool_markers_seen: usize,
    parsed_value_matches_seen: usize,
    high_priority_matches_recorded: usize,
    unique_names: usize,
    truncated_by_match_cap: bool,
    truncated_by_byte_cap: bool,
    timed_out: bool,
}

#[derive(Serialize)]
struct ModuleInfo {
    base: String,
    size: u64,
    path: Option<String>,
}

#[derive(Serialize)]
struct RegionInfo {
    base: String,
    size: u64,
    state: String,
    protect: String,
    kind: String,
    readable: bool,
    scanned: bool,
    matches_seen: usize,
    parsed_value_matches_seen: usize,
    note: Option<String>,
}

#[derive(Serialize, Clone)]
struct EvidenceMatch {
    kind: &'static str,
    name: String,
    address: String,
    region_base: String,
    encoding: &'static str,
    priority: u8,
    reason: String,
    parsed_value: Option<String>,
    context_sha256: String,
    context_hex: String,
    context_ascii: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RawMatch {
    kind: &'static str,
    name: String,
    offset: usize,
    len: usize,
    encoding: &'static str,
}

fn main() {
    if let Err(err) = run() {
        if err.starts_with("usage:") {
            println!("{err}");
            return;
        }
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

#[cfg(not(all(target_os = "windows", target_pointer_width = "64")))]
fn run() -> Result<(), String> {
    Err("memory_evidence_exporter only reads process memory on 64-bit Windows".to_string())
}

#[cfg(all(target_os = "windows", target_pointer_width = "64"))]
fn run() -> Result<(), String> {
    let raw_args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut args = parse_args(raw_args.clone())?;
    args.interactive = raw_args.is_empty();

    if args.interactive {
        println!("Roblox memory evidence exporter");
        println!("Looking for RobloxPlayerBeta and exporting evidence to your Desktop...");
        flush_stdout();
    }

    let export = match windows_impl::collect_export(&args) {
        Ok(export) => export,
        Err(err) => {
            if args.out.is_none() {
                let filename = default_error_output_filename();
                let body = serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "created_at": Utc::now().to_rfc3339(),
                    "tool": {
                        "name": "memory_evidence_exporter",
                        "package_version": env!("CARGO_PKG_VERSION")
                    },
                    "error": err,
                    "hint": "Run as Administrator with RobloxPlayerBeta running, then rerun this exporter."
                });
                let json = serde_json::to_string_pretty(&body).map_err(|e| e.to_string())?;
                let saved = write_default_outputs(&filename, json.as_bytes())?;
                println!();
                println!("Could not complete the export: {err}");
                println_saved_paths("Error report saved to:", &saved);
                if args.interactive {
                    pause_before_exit();
                    return Ok(());
                }
            }
            return Err(err);
        }
    };
    let filename = default_output_filename(
        export
            .target
            .name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect::<String>()
            .as_str(),
        export.target.pid,
    );
    let json = serde_json::to_string_pretty(&export).map_err(|e| e.to_string())?;
    let saved = if let Some(out) = args.out.clone() {
        std::fs::write(&out, json.as_bytes())
            .map_err(|e| format!("failed to write {}: {e}", out.display()))?;
        vec![out]
    } else {
        write_default_outputs(&filename, json.as_bytes())?
    };
    println!();
    println!("Export complete.");
    println_saved_paths("Saved to:", &saved);
    if args.interactive {
        pause_before_exit();
    }
    Ok(())
}

fn parse_args<I>(iter: I) -> Result<Args, String>
where
    I: IntoIterator,
    I::Item: Into<String>,
{
    let mut args = Args {
        pid: None,
        process_hint: DEFAULT_PROCESS_HINT.to_string(),
        out: None,
        context_bytes: DEFAULT_CONTEXT_BYTES,
        max_matches: DEFAULT_MAX_MATCHES,
        max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
        timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
        scan_images: false,
        interactive: false,
    };

    let mut it = iter.into_iter().map(Into::into);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--pid" => {
                let value = it.next().ok_or("--pid requires a value")?;
                args.pid = Some(
                    value
                        .parse()
                        .map_err(|_| "--pid must be a positive integer")?,
                );
            }
            "--process" => {
                args.process_hint = it.next().ok_or("--process requires a value")?;
            }
            "--out" => {
                args.out = Some(PathBuf::from(it.next().ok_or("--out requires a value")?));
            }
            "--context-bytes" => {
                let value: usize = it
                    .next()
                    .ok_or("--context-bytes requires a value")?
                    .parse()
                    .map_err(|_| "--context-bytes must be a positive integer")?;
                args.context_bytes = value.min(1024);
            }
            "--max-matches" => {
                args.max_matches = it
                    .next()
                    .ok_or("--max-matches requires a value")?
                    .parse()
                    .map_err(|_| "--max-matches must be a positive integer")?;
            }
            "--max-scan-mib" => {
                let mib: u64 = it
                    .next()
                    .ok_or("--max-scan-mib requires a value")?
                    .parse()
                    .map_err(|_| "--max-scan-mib must be a positive integer")?;
                args.max_scan_bytes = mib.saturating_mul(1024 * 1024);
            }
            "--timeout-seconds" => {
                let seconds: u64 = it
                    .next()
                    .ok_or("--timeout-seconds requires a value")?
                    .parse()
                    .map_err(|_| "--timeout-seconds must be a positive integer")?;
                args.timeout = Duration::from_secs(seconds.max(1));
            }
            "--scan-images" => args.scan_images = true,
            "--help" | "-h" => return Err(help_text()),
            unknown => return Err(format!("unknown argument: {unknown}\n\n{}", help_text())),
        }
    }

    Ok(args)
}

fn help_text() -> String {
    [
        "usage: memory_evidence_exporter.exe [options]",
        "",
        "options:",
        "  --pid <pid>                 read a specific process id",
        "  --process <name>            process-name hint, default robloxplayerbeta",
        "  --out <path>                output JSON path",
        "  --context-bytes <n>         bytes before/after each match, capped at 1024; default 0",
        "  --max-matches <n>           output match cap; 0 records every match",
        "  --max-scan-mib <n>          stop scanning after this many MiB",
        "  --timeout-seconds <n>       wall-clock scan cap",
        "  --scan-images               include MEM_IMAGE regions in string scan",
    ]
    .join("\n")
}

fn default_output_filename(process_name: &str, pid: u32) -> String {
    format!(
        "roblox-memory-evidence-{}-{}-{}.json",
        if process_name.is_empty() {
            "process"
        } else {
            process_name
        },
        pid,
        Utc::now().format("%Y%m%d-%H%M%S")
    )
}

fn default_error_output_filename() -> String {
    format!(
        "roblox-memory-evidence-error-{}.json",
        Utc::now().format("%Y%m%d-%H%M%S")
    )
}

fn write_default_outputs(filename: &str, bytes: &[u8]) -> Result<Vec<PathBuf>, String> {
    let mut failures = Vec::new();

    for dir in default_output_dirs() {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            failures.push(format!("{}: {e}", dir.display()));
            continue;
        }
        let path = dir.join(filename);
        match std::fs::write(&path, bytes) {
            Ok(()) => return Ok(vec![path]),
            Err(e) => failures.push(format!("{}: {e}", path.display())),
        }
    }

    Err(format!(
        "failed to write output to any Desktop/fallback location: {}",
        failures.join(" | ")
    ))
}

fn default_output_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    #[cfg(windows)]
    {
        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            dirs.push(PathBuf::from(userprofile).join("Desktop"));
        }
        for var in ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"] {
            if let Ok(path) = std::env::var(var) {
                dirs.push(PathBuf::from(path).join("Desktop"));
            }
        }
        if let Ok(public) = std::env::var("PUBLIC") {
            dirs.push(PathBuf::from(public).join("Desktop"));
        }
        if let (Ok(drive), Ok(path)) = (std::env::var("HOMEDRIVE"), std::env::var("HOMEPATH")) {
            dirs.push(PathBuf::from(format!("{drive}{path}")).join("Desktop"));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(home).join("Desktop"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            dirs.push(parent.to_path_buf());
        }
    }
    dirs.push(std::env::temp_dir());

    let mut seen = std::collections::HashSet::new();
    dirs.into_iter()
        .filter(|dir| seen.insert(dir.to_string_lossy().to_lowercase()))
        .collect()
}

fn println_saved_paths(header: &str, paths: &[PathBuf]) {
    println!("{header}");
    for path in paths {
        println!("{}", path.display());
    }
}

fn flush_stdout() {
    let _ = std::io::stdout().flush();
}

fn pause_before_exit() {
    println!();
    println!("Press Enter to close this window.");
    flush_stdout();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

fn scan_buffer_for_matches(buffer: &[u8]) -> Vec<RawMatch> {
    let mut out = Vec::new();
    out.extend(scan_ascii_prefixes(buffer));
    out.extend(scan_wide_prefixes(buffer));
    out.extend(scan_ascii_tracked_names(buffer));
    out.extend(scan_ascii_markers(buffer));
    out.extend(scan_wide_markers(buffer));
    out.sort_by_key(|m| m.offset);
    out
}

fn scan_ascii_prefixes(buffer: &[u8]) -> Vec<RawMatch> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < buffer.len() {
        if !matches!(buffer[i], b'D' | b'F' | b'S') {
            i += 1;
            continue;
        }
        if i > 0 && is_ident_byte(buffer[i - 1]) {
            i += 1;
            continue;
        }
        let Some(prefix) = FLAG_PREFIXES
            .iter()
            .find(|prefix| buffer[i..].starts_with(prefix.as_bytes()))
        else {
            i += 1;
            continue;
        };
        let body_start = i + prefix.len();
        if body_start >= buffer.len() || !buffer[body_start].is_ascii_uppercase() {
            i += 1;
            continue;
        }
        let mut end = body_start;
        while end < buffer.len()
            && end - body_start < MAX_IDENT_BODY_LEN
            && is_ident_byte(buffer[end])
        {
            end += 1;
        }
        if end - body_start < MIN_IDENT_BODY_LEN || !right_boundary_ok(buffer, end) {
            i += 1;
            continue;
        }
        if let Ok(name) = std::str::from_utf8(&buffer[i..end]) {
            out.push(RawMatch {
                kind: "fflag_identifier",
                name: name.to_string(),
                offset: i,
                len: end - i,
                encoding: "ascii",
            });
        }
        i = end;
    }
    out
}

fn scan_wide_prefixes(buffer: &[u8]) -> Vec<RawMatch> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 1 < buffer.len() {
        if buffer[i + 1] != 0 || !matches!(buffer[i], b'D' | b'F' | b'S') {
            i += 1;
            continue;
        }
        if !wide_left_boundary_ok(buffer, i) {
            i += 1;
            continue;
        }
        let Some(prefix) = FLAG_PREFIXES
            .iter()
            .find(|prefix| wide_starts_with(buffer, i, prefix))
        else {
            i += 1;
            continue;
        };
        let body_start = i + prefix.len() * 2;
        if body_start + 1 >= buffer.len()
            || buffer[body_start + 1] != 0
            || !buffer[body_start].is_ascii_uppercase()
        {
            i += 1;
            continue;
        }
        let mut end = body_start;
        let mut chars = Vec::new();
        while end + 1 < buffer.len()
            && buffer[end + 1] == 0
            && chars.len() < MAX_IDENT_BODY_LEN
            && is_ident_byte(buffer[end])
        {
            chars.push(buffer[end]);
            end += 2;
        }
        if chars.len() < MIN_IDENT_BODY_LEN || !wide_right_boundary_ok(buffer, end) {
            i += 1;
            continue;
        }
        let name_bytes: Vec<u8> = buffer[i..end].chunks_exact(2).map(|c| c[0]).collect();
        if let Ok(name) = String::from_utf8(name_bytes) {
            out.push(RawMatch {
                kind: "fflag_identifier",
                name,
                offset: i,
                len: end - i,
                encoding: "utf16le",
            });
        }
        i = end;
    }
    out
}

fn scan_ascii_tracked_names(buffer: &[u8]) -> Vec<RawMatch> {
    let mut out = Vec::new();
    for &(name, _) in RUNTIME_RULES {
        if FLAG_PREFIXES.iter().any(|prefix| name.starts_with(prefix)) {
            continue;
        }
        let needle = name.as_bytes();
        let mut start = 0usize;
        while start + needle.len() <= buffer.len() {
            let Some(rel) = find_bytes(&buffer[start..], needle) else {
                break;
            };
            let offset = start + rel;
            if marker_boundary_ok(buffer, offset, needle.len()) {
                out.push(RawMatch {
                    kind: "tracked_identifier",
                    name: name.to_string(),
                    offset,
                    len: needle.len(),
                    encoding: "ascii",
                });
            }
            start = offset + needle.len();
        }
    }
    out
}

fn scan_ascii_markers(buffer: &[u8]) -> Vec<RawMatch> {
    let lower = buffer
        .iter()
        .map(|b| b.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let mut out = Vec::new();
    for marker in TOOL_MARKERS {
        let needle = marker.as_bytes();
        let mut start = 0usize;
        while start + needle.len() <= lower.len() {
            let Some(rel) = find_bytes(&lower[start..], needle) else {
                break;
            };
            let offset = start + rel;
            if marker_boundary_ok(buffer, offset, needle.len()) {
                out.push(RawMatch {
                    kind: "tool_marker",
                    name: marker.to_string(),
                    offset,
                    len: needle.len(),
                    encoding: "ascii",
                });
            }
            start = offset + needle.len();
        }
    }
    out
}

fn scan_wide_markers(buffer: &[u8]) -> Vec<RawMatch> {
    let mut out = Vec::new();
    for marker in TOOL_MARKERS {
        let len = marker.len() * 2;
        if len > buffer.len() {
            continue;
        }
        for offset in 0..=buffer.len() - len {
            if wide_ascii_case_insensitive_at(buffer, offset, marker)
                && wide_marker_boundary_ok(buffer, offset, len)
            {
                out.push(RawMatch {
                    kind: "tool_marker",
                    name: marker.to_string(),
                    offset,
                    len,
                    encoding: "utf16le",
                });
            }
        }
    }
    out
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn right_boundary_ok(buffer: &[u8], end: usize) -> bool {
    end >= buffer.len() || !is_ident_byte(buffer[end])
}

fn wide_starts_with(buffer: &[u8], offset: usize, s: &str) -> bool {
    let needed = s.len() * 2;
    if offset + needed > buffer.len() {
        return false;
    }
    s.as_bytes()
        .iter()
        .enumerate()
        .all(|(idx, b)| buffer[offset + idx * 2] == *b && buffer[offset + idx * 2 + 1] == 0)
}

fn wide_ascii_case_insensitive_at(buffer: &[u8], offset: usize, s: &str) -> bool {
    let needed = s.len() * 2;
    if offset + needed > buffer.len() {
        return false;
    }
    s.as_bytes().iter().enumerate().all(|(idx, b)| {
        buffer[offset + idx * 2].to_ascii_lowercase() == b.to_ascii_lowercase()
            && buffer[offset + idx * 2 + 1] == 0
    })
}

fn wide_left_boundary_ok(buffer: &[u8], offset: usize) -> bool {
    offset < 2 || buffer[offset - 1] != 0 || !is_ident_byte(buffer[offset - 2])
}

fn wide_right_boundary_ok(buffer: &[u8], end: usize) -> bool {
    end + 1 >= buffer.len() || buffer[end + 1] != 0 || !is_ident_byte(buffer[end])
}

fn marker_boundary_ok(buffer: &[u8], offset: usize, len: usize) -> bool {
    (offset == 0 || !is_ident_byte(buffer[offset - 1]))
        && (offset + len >= buffer.len() || !is_ident_byte(buffer[offset + len]))
}

fn wide_marker_boundary_ok(buffer: &[u8], offset: usize, len: usize) -> bool {
    wide_left_boundary_ok(buffer, offset) && wide_right_boundary_ok(buffer, offset + len)
}

fn evidence_from_match(
    raw: &RawMatch,
    buffer: &[u8],
    region_base: usize,
    context_bytes: usize,
) -> EvidenceMatch {
    let start = raw.offset.saturating_sub(context_bytes);
    let end = raw
        .offset
        .saturating_add(raw.len)
        .saturating_add(context_bytes)
        .min(buffer.len());
    let context = &buffer[start..end];
    let parsed_value = parse_value_after_match(raw, buffer);
    let (priority, reason) = evidence_priority(raw, parsed_value.as_deref());
    let mut hasher = Sha256::new();
    hasher.update(context);
    EvidenceMatch {
        kind: raw.kind,
        name: raw.name.clone(),
        address: hex_addr(region_base.saturating_add(raw.offset)),
        region_base: hex_addr(region_base),
        encoding: raw.encoding,
        priority,
        reason,
        parsed_value,
        context_sha256: hex::encode(hasher.finalize()),
        context_hex: hex::encode(context),
        context_ascii: printable_ascii(context),
    }
}

fn record_evidence_match(
    raw: &RawMatch,
    buffer: &[u8],
    region_base: usize,
    args: &Args,
    matches: &mut Vec<EvidenceMatch>,
    seen_names: &mut HashSet<String>,
    summary: &mut ExportSummary,
) {
    summary.matches_seen = summary.matches_seen.saturating_add(1);
    match raw.kind {
        "tool_marker" => summary.tool_markers_seen = summary.tool_markers_seen.saturating_add(1),
        "fflag_identifier" | "tracked_identifier" => {
            summary.fflag_identifiers_seen = summary.fflag_identifiers_seen.saturating_add(1)
        }
        _ => {}
    }
    seen_names.insert(raw.name.clone());

    let evidence = evidence_from_match(raw, buffer, region_base, args.context_bytes);
    if evidence.parsed_value.is_some() {
        summary.parsed_value_matches_seen = summary.parsed_value_matches_seen.saturating_add(1);
    }

    if args.max_matches == 0 || matches.len() < args.max_matches {
        matches.push(evidence);
        return;
    }

    summary.truncated_by_match_cap = true;
    summary.matches_dropped_by_cap = summary.matches_dropped_by_cap.saturating_add(1);
    if let Some((weakest_index, weakest)) = matches
        .iter()
        .enumerate()
        .min_by_key(|(_, existing)| existing.priority)
    {
        if evidence.priority > weakest.priority {
            matches[weakest_index] = evidence;
        }
    }
}

fn finalize_match_order(matches: &mut [EvidenceMatch]) {
    matches.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.address.cmp(&b.address))
    });
}

fn evidence_priority(raw: &RawMatch, parsed_value: Option<&str>) -> (u8, String) {
    if raw.kind == "tool_marker" {
        return if high_value_tool_marker(&raw.name) {
            (100, "exact high-value tool/config marker".to_string())
        } else {
            (25, "diagnostic API/tool marker".to_string())
        };
    }

    if let Some(value) = parsed_value {
        if runtime_rule_value_matches(&raw.name, value) {
            return (95, "exact curated name+value match".to_string());
        }
        if is_curated_name(&raw.name) || is_runtime_rule_name(&raw.name) {
            return (75, "curated flag name with nearby value".to_string());
        }
        return (45, "flag-like name with nearby value".to_string());
    }

    if is_runtime_rule_name(&raw.name) {
        return (60, "curated runtime flag name".to_string());
    }
    if is_curated_name(&raw.name) {
        return (50, "curated suspicious flag name".to_string());
    }
    (10, "generic flag-like identifier".to_string())
}

fn high_value_tool_marker(name: &str) -> bool {
    !matches!(name, "writeprocessmemory")
}

fn is_runtime_rule_name(name: &str) -> bool {
    RUNTIME_RULES
        .iter()
        .any(|(rule_name, _)| *rule_name == name)
}

fn is_curated_name(name: &str) -> bool {
    SUSPICIOUS_FLAGS_SOURCE.contains(&format!("\"{name}\""))
}

fn runtime_rule_value_matches(name: &str, value: &str) -> bool {
    RUNTIME_RULES
        .iter()
        .filter(|(rule_name, _)| *rule_name == name)
        .any(|(_, expected)| expected_value_matches(*expected, value))
}

fn expected_value_matches(expected: ExpectedValue, value: &str) -> bool {
    match expected {
        ExpectedValue::Bool(expected) => match normalize_value(value).as_str() {
            "true" => expected,
            "false" => !expected,
            "1" => expected,
            "0" => !expected,
            _ => false,
        },
        ExpectedValue::Int(expected) => normalize_value(value)
            .parse::<i32>()
            .map(|observed| observed == expected)
            .unwrap_or(false),
    }
}

fn normalize_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .replace('_', "")
        .to_ascii_lowercase()
}

fn parse_value_after_match(raw: &RawMatch, buffer: &[u8]) -> Option<String> {
    if raw.encoding != "ascii" {
        return None;
    }
    let mut i = raw.offset.saturating_add(raw.len);
    let scan_end = i.saturating_add(96).min(buffer.len());

    while i < scan_end && matches!(buffer[i], b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'\'') {
        i += 1;
    }
    while i < scan_end
        && matches!(
            buffer[i],
            b' ' | b'\t' | b'\r' | b'\n' | b':' | b'=' | b'"' | b'\''
        )
    {
        i += 1;
    }
    if i >= scan_end {
        return None;
    }

    if buffer[i] == b'"' || buffer[i] == b'\'' {
        let quote = buffer[i];
        i += 1;
        let start = i;
        while i < scan_end && buffer[i] != quote && buffer[i] != b',' && buffer[i] != b'}' {
            i += 1;
        }
        return value_from_bytes(&buffer[start..i]);
    }

    let start = i;
    while i < scan_end {
        let b = buffer[i];
        if matches!(b, b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n') {
            break;
        }
        i += 1;
    }
    value_from_bytes(&buffer[start..i])
}

fn value_from_bytes(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() > 128 {
        return None;
    }
    let s = std::str::from_utf8(bytes).ok()?.trim();
    if s.is_empty() {
        return None;
    }
    let value = s.trim_matches('"').trim_matches('\'').to_string();
    if value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        Some(value)
    } else {
        None
    }
}

fn printable_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| match *b {
            b'\r' | b'\n' | b'\t' => ' ',
            0x20..=0x7e => *b as char,
            _ => '.',
        })
        .collect()
}

fn hex_addr(addr: usize) -> String {
    format!("0x{addr:016X}")
}

fn redact_user_path(path: String) -> String {
    #[cfg(windows)]
    {
        if let Ok(profile) = std::env::var("USERPROFILE") {
            return path.replace(&profile, "%USERPROFILE%");
        }
    }
    path
}

#[cfg(all(target_os = "windows", target_pointer_width = "64"))]
mod windows_impl {
    use super::*;
    use std::ffi::c_void;
    use std::mem;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HMODULE, MAX_PATH};
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
        PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    };
    use windows_sys::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL,
        MODULEINFO,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    struct ScopedHandle(HANDLE);
    impl Drop for ScopedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    struct ReadStats {
        bytes_scanned: u64,
        read_failures: usize,
        read_failed_bytes: u64,
    }

    pub(super) fn collect_export(args: &Args) -> Result<EvidenceExport, String> {
        let started = Instant::now();
        let proc = find_target_process(args)?;
        if args.interactive {
            println!("Found target: {} (PID {})", proc.name, proc.pid);
            println!("Opening process memory for read-only scan...");
            flush_stdout();
        }
        let raw_handle =
            unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, proc.pid) };
        if raw_handle.is_null() {
            return Err(format!(
                "could not open PID {} for read/query access; run as Administrator",
                proc.pid
            ));
        }
        let handle = ScopedHandle(raw_handle);

        let modules = enumerate_modules(handle.0);
        if args.interactive {
            println!("Loaded module inventory: {} modules", modules.len());
            println!(
                "Scanning readable committed memory. This can take up to {} seconds.",
                args.timeout.as_secs()
            );
            flush_stdout();
        }
        let mut export = EvidenceExport {
            schema_version: SCHEMA_VERSION,
            created_at: Utc::now().to_rfc3339(),
            tool: ToolInfo {
                name: "memory_evidence_exporter",
                package_version: env!("CARGO_PKG_VERSION"),
            },
            target: proc,
            settings: ExportSettings {
                process_hint: args.process_hint.clone(),
                context_bytes: args.context_bytes,
                max_matches: args.max_matches,
                max_scan_bytes: args.max_scan_bytes,
                timeout_seconds: args.timeout.as_secs(),
                scan_images: args.scan_images,
            },
            summary: ExportSummary::default(),
            modules,
            regions: Vec::new(),
            matches: Vec::new(),
            errors: Vec::new(),
        };

        let mut address = 0usize;
        let mut info: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
        let mut seen_names = HashSet::new();
        let mut scratch = Vec::with_capacity(MAX_CHUNK_BYTES);
        let mut last_progress = Instant::now();

        loop {
            if export.summary.regions_walked >= MAX_REGIONS_WALKED {
                export
                    .errors
                    .push("region walk stopped at safety cap".to_string());
                break;
            }
            if started.elapsed() >= args.timeout {
                export.summary.timed_out = true;
                break;
            }
            if export.summary.bytes_intended >= args.max_scan_bytes {
                export.summary.truncated_by_byte_cap = true;
                break;
            }

            let result = unsafe {
                VirtualQueryEx(
                    handle.0,
                    address as *const c_void,
                    &mut info,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if result == 0 {
                break;
            }

            export.summary.regions_walked += 1;
            let region_base = info.BaseAddress as usize;
            let region_size = info.RegionSize;
            let committed = info.State == MEM_COMMIT;
            let readable = committed && is_readable(info.Protect);
            let is_image = info.Type == MEM_IMAGE;
            let should_scan = readable && (!is_image || args.scan_images);
            let mut note = None;
            let matches_seen_before_region = export.summary.matches_seen;
            let value_matches_before_region = export.summary.parsed_value_matches_seen;

            if should_scan && region_size > 0 {
                let remaining = args
                    .max_scan_bytes
                    .saturating_sub(export.summary.bytes_intended);
                let scan_size = (region_size as u64).min(remaining) as usize;
                export.summary.bytes_intended = export
                    .summary
                    .bytes_intended
                    .saturating_add(scan_size as u64);
                let before = export.summary.bytes_scanned;
                let stats = scan_region(
                    handle.0,
                    region_base,
                    scan_size,
                    &mut scratch,
                    args,
                    &mut export.matches,
                    &mut seen_names,
                    &mut export.summary,
                    started,
                    &mut last_progress,
                );
                export.summary.bytes_scanned = export
                    .summary
                    .bytes_scanned
                    .saturating_add(stats.bytes_scanned);
                export.summary.read_failures += stats.read_failures;
                export.summary.read_failed_bytes = export
                    .summary
                    .read_failed_bytes
                    .saturating_add(stats.read_failed_bytes);
                if export.summary.bytes_scanned > before {
                    export.summary.regions_scanned += 1;
                }
                if started.elapsed() >= args.timeout {
                    export.summary.timed_out = true;
                    note = Some("timeout reached while scanning this region".to_string());
                }
                if args.interactive && last_progress.elapsed() >= Duration::from_millis(750) {
                    print_progress(&export.summary);
                    last_progress = Instant::now();
                }
            } else {
                export.summary.regions_skipped += 1;
                if readable && is_image && !args.scan_images {
                    note = Some(
                        "MEM_IMAGE skipped by default to avoid vanilla literal noise".to_string(),
                    );
                }
            }

            export.regions.push(RegionInfo {
                base: hex_addr(region_base),
                size: region_size as u64,
                state: state_label(info.State).to_string(),
                protect: protect_label(info.Protect).to_string(),
                kind: type_label(info.Type).to_string(),
                readable,
                scanned: should_scan,
                matches_seen: export
                    .summary
                    .matches_seen
                    .saturating_sub(matches_seen_before_region),
                parsed_value_matches_seen: export
                    .summary
                    .parsed_value_matches_seen
                    .saturating_sub(value_matches_before_region),
                note,
            });

            if export.summary.timed_out {
                break;
            }
            if region_size == 0 {
                break;
            }
            let next = address.wrapping_add(region_size);
            if next <= address {
                break;
            }
            address = next;
        }

        export.summary.matches_recorded = export.matches.len();
        export.summary.unique_names = seen_names.len();
        export.summary.high_priority_matches_recorded =
            export.matches.iter().filter(|m| m.priority >= 75).count();
        finalize_match_order(&mut export.matches);
        if args.interactive {
            print_progress(&export.summary);
        }
        Ok(export)
    }

    fn find_target_process(args: &Args) -> Result<TargetInfo, String> {
        if let Some(pid) = args.pid {
            return Ok(TargetInfo {
                pid,
                name: format!("pid-{pid}"),
                exe_path: None,
            });
        }

        let mut system = sysinfo::System::new_all();
        system.refresh_all();
        let hint = args.process_hint.to_lowercase();
        let mut candidates = system
            .processes()
            .iter()
            .filter_map(|(pid, process)| {
                let name = process.name().to_string_lossy().to_string();
                let lower = name.to_lowercase();
                if !lower.contains(&hint)
                    || lower.contains("studio")
                    || lower.contains("crashhandler")
                {
                    return None;
                }
                let pid = pid.to_string().parse::<u32>().ok()?;
                let exe_path = process
                    .exe()
                    .map(|p| redact_user_path(p.to_string_lossy().to_string()));
                Some(TargetInfo {
                    pid,
                    name,
                    exe_path,
                })
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|p| p.pid);
        candidates
            .into_iter()
            .next()
            .ok_or_else(|| format!("no process matching {:?} was found", args.process_hint))
    }

    fn enumerate_modules(handle: HANDLE) -> Vec<ModuleInfo> {
        let mut modules: Vec<HMODULE> = vec![std::ptr::null_mut(); 1024];
        let mut needed = 0u32;
        let ok = unsafe {
            EnumProcessModulesEx(
                handle,
                modules.as_mut_ptr(),
                (mem::size_of::<HMODULE>() * modules.len()) as u32,
                &mut needed,
                LIST_MODULES_ALL,
            )
        };
        if ok == 0 {
            return Vec::new();
        }
        let count = needed as usize / mem::size_of::<HMODULE>();
        if count > modules.len() {
            modules.resize(count.min(65_536), std::ptr::null_mut());
            needed = 0;
            let ok = unsafe {
                EnumProcessModulesEx(
                    handle,
                    modules.as_mut_ptr(),
                    (mem::size_of::<HMODULE>() * modules.len()) as u32,
                    &mut needed,
                    LIST_MODULES_ALL,
                )
            };
            if ok == 0 {
                return Vec::new();
            }
        }

        let count = (needed as usize / mem::size_of::<HMODULE>()).min(modules.len());
        modules
            .into_iter()
            .take(count)
            .filter(|hmod| !hmod.is_null())
            .filter_map(|hmod| {
                let mut info: MODULEINFO = unsafe { mem::zeroed() };
                let ok = unsafe {
                    GetModuleInformation(
                        handle,
                        hmod,
                        &mut info,
                        mem::size_of::<MODULEINFO>() as u32,
                    )
                };
                if ok == 0 || info.lpBaseOfDll.is_null() {
                    return None;
                }
                Some(ModuleInfo {
                    base: hex_addr(info.lpBaseOfDll as usize),
                    size: info.SizeOfImage as u64,
                    path: module_path(handle, hmod).map(redact_user_path),
                })
            })
            .collect()
    }

    fn module_path(handle: HANDLE, hmod: HMODULE) -> Option<String> {
        let mut buf = vec![0u16; MAX_PATH as usize];
        let mut len =
            unsafe { GetModuleFileNameExW(handle, hmod, buf.as_mut_ptr(), buf.len() as u32) };
        while len != 0 && len as usize == buf.len() {
            let new_len = buf.len().saturating_mul(2).min(65_536);
            if new_len <= buf.len() {
                break;
            }
            buf.resize(new_len, 0);
            len = unsafe { GetModuleFileNameExW(handle, hmod, buf.as_mut_ptr(), buf.len() as u32) };
        }
        (len != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }

    fn scan_region(
        handle: HANDLE,
        base: usize,
        size: usize,
        scratch: &mut Vec<u8>,
        args: &Args,
        matches: &mut Vec<EvidenceMatch>,
        seen_names: &mut HashSet<String>,
        summary: &mut ExportSummary,
        started: Instant,
        last_progress: &mut Instant,
    ) -> ReadStats {
        let mut stats = ReadStats {
            bytes_scanned: 0,
            read_failures: 0,
            read_failed_bytes: 0,
        };
        let mut offset = 0usize;
        while offset < size && started.elapsed() < args.timeout {
            let chunk = (size - offset).min(MAX_CHUNK_BYTES);
            scan_span_adaptive(
                handle,
                base.saturating_add(offset),
                chunk,
                scratch,
                args,
                matches,
                seen_names,
                summary,
                &mut stats,
                started,
            );
            if args.interactive && last_progress.elapsed() >= Duration::from_millis(750) {
                print_scan_line(
                    stats.bytes_scanned,
                    matches.len(),
                    base.saturating_add(offset),
                    started.elapsed(),
                );
                *last_progress = Instant::now();
            }
            offset = offset.saturating_add(chunk);
        }
        stats
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_span_adaptive(
        handle: HANDLE,
        addr: usize,
        size: usize,
        scratch: &mut Vec<u8>,
        args: &Args,
        matches: &mut Vec<EvidenceMatch>,
        seen_names: &mut HashSet<String>,
        summary: &mut ExportSummary,
        stats: &mut ReadStats,
        started: Instant,
    ) {
        if size == 0 || started.elapsed() >= args.timeout {
            return;
        }

        scratch.resize(size, 0);
        let mut bytes_read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                handle,
                addr as *const c_void,
                scratch.as_mut_ptr() as *mut c_void,
                size,
                &mut bytes_read,
            )
        };
        if ok != 0 && bytes_read > 0 && bytes_read <= size {
            stats.bytes_scanned = stats.bytes_scanned.saturating_add(bytes_read as u64);
            let buffer = &scratch[..bytes_read];
            for raw in scan_buffer_for_matches(buffer) {
                record_evidence_match(&raw, buffer, addr, args, matches, seen_names, summary);
            }
            if bytes_read < size {
                stats.read_failures += 1;
                stats.read_failed_bytes = stats
                    .read_failed_bytes
                    .saturating_add((size - bytes_read) as u64);
            }
            return;
        }

        if size <= MIN_READ_CHUNK_BYTES {
            stats.read_failures += 1;
            stats.read_failed_bytes = stats.read_failed_bytes.saturating_add(size as u64);
            return;
        }

        let split = (size / 2)
            .max(MIN_READ_CHUNK_BYTES)
            .min(size - MIN_READ_CHUNK_BYTES);
        scan_span_adaptive(
            handle, addr, split, scratch, args, matches, seen_names, summary, stats, started,
        );
        scan_span_adaptive(
            handle,
            addr.saturating_add(split),
            size - split,
            scratch,
            args,
            matches,
            seen_names,
            summary,
            stats,
            started,
        );
    }

    fn is_readable(protect: u32) -> bool {
        if protect & PAGE_GUARD != 0 || protect & PAGE_NOACCESS != 0 {
            return false;
        }
        matches!(
            protect & 0xFF,
            PAGE_READONLY
                | PAGE_READWRITE
                | PAGE_WRITECOPY
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY
        )
    }

    fn state_label(state: u32) -> &'static str {
        match state {
            MEM_COMMIT => "MEM_COMMIT",
            _ => "OTHER",
        }
    }

    fn type_label(kind: u32) -> &'static str {
        match kind {
            MEM_IMAGE => "MEM_IMAGE",
            MEM_MAPPED => "MEM_MAPPED",
            MEM_PRIVATE => "MEM_PRIVATE",
            _ => "OTHER",
        }
    }

    fn protect_label(protect: u32) -> String {
        let base = match protect & 0xFF {
            PAGE_NOACCESS => "PAGE_NOACCESS",
            PAGE_READONLY => "PAGE_READONLY",
            PAGE_READWRITE => "PAGE_READWRITE",
            PAGE_WRITECOPY => "PAGE_WRITECOPY",
            PAGE_EXECUTE_READ => "PAGE_EXECUTE_READ",
            PAGE_EXECUTE_READWRITE => "PAGE_EXECUTE_READWRITE",
            PAGE_EXECUTE_WRITECOPY => "PAGE_EXECUTE_WRITECOPY",
            _ => "OTHER",
        };
        if protect & PAGE_GUARD != 0 {
            format!("{base}|PAGE_GUARD")
        } else {
            base.to_string()
        }
    }

    fn print_progress(summary: &ExportSummary) {
        println!(
            "Progress: walked {} regions, scanned {} MiB, matches seen {}, recorded {}, value matches {}",
            summary.regions_walked,
            summary.bytes_scanned / (1024 * 1024),
            summary.matches_seen,
            summary.matches_recorded,
            summary.parsed_value_matches_seen
        );
        flush_stdout();
    }

    fn print_scan_line(
        bytes_scanned_in_region: u64,
        matches: usize,
        address: usize,
        elapsed: Duration,
    ) {
        println!(
            "Scanning... {} MiB in current region, recorded matches {}, address {}, elapsed {}s",
            bytes_scanned_in_region / (1024 * 1024),
            matches,
            hex_addr(address),
            elapsed.as_secs()
        );
        flush_stdout();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(buf: &[u8]) -> Vec<String> {
        scan_buffer_for_matches(buf)
            .into_iter()
            .map(|m| format!("{}:{}", m.encoding, m.name))
            .collect()
    }

    #[test]
    fn extracts_ascii_fflag_identifier() {
        let found = names(br#"{"DFIntS2PhysicsSenderRate":-30}"#);
        assert!(found.contains(&"ascii:DFIntS2PhysicsSenderRate".to_string()));
    }

    #[test]
    fn extracts_utf16le_fflag_identifier() {
        let wide = "DFIntHipHeightClamp"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<_>>();
        let found = names(&wide);
        assert!(found.contains(&"utf16le:DFIntHipHeightClamp".to_string()));
    }

    #[test]
    fn extracts_unaligned_utf16le_fflag_identifier() {
        let mut wide = vec![0xCC];
        wide.extend(
            "DFIntHipHeightClamp"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes()),
        );
        let found = names(&wide);
        assert!(found.contains(&"utf16le:DFIntHipHeightClamp".to_string()));
    }

    #[test]
    fn rejects_superficially_similar_non_fflag_text() {
        let found = names(b"pre_DFIntS2PhysicsSenderRate FakeFFlagabc FFlagaa");
        assert!(
            found.is_empty(),
            "embedded prefixes, lowercase bodies, and too-short bodies are diagnostic noise"
        );
    }

    #[test]
    fn marker_requires_boundaries() {
        let found = names(b"myfflags.json.backup fflags.json address.json Lorno Bypass");
        assert!(!found.contains(&"ascii:myfflags.json".to_string()));
        assert!(found.contains(&"ascii:fflags.json".to_string()));
        assert!(found.contains(&"ascii:address.json".to_string()));
        assert!(found.contains(&"ascii:lorno bypass".to_string()));
    }

    #[test]
    fn context_is_bounded_around_match() {
        let buf = b"aaaa DFIntS2PhysicsSenderRate bbbb";
        let raw = scan_ascii_prefixes(buf).remove(0);
        let ev = evidence_from_match(&raw, buf, 0x1000, 2);
        assert!(ev.context_ascii.len() <= raw.len + 4);
        assert_eq!(ev.address, "0x0000000000001005");
    }

    #[test]
    fn value_parser_marks_exact_curated_name_value_pair() {
        let buf = br#"{"DFIntS2PhysicsSenderRate":-30}"#;
        let raw = scan_ascii_prefixes(buf).remove(0);
        let ev = evidence_from_match(&raw, buf, 0x2000, 16);
        assert_eq!(ev.parsed_value.as_deref(), Some("-30"));
        assert_eq!(ev.priority, 95);
    }

    #[test]
    fn debug_draw_enable_true_default_is_not_exact_runtime_rule() {
        assert!(!runtime_rule_value_matches("DFFlagDebugDrawEnable", "True"));
    }

    #[test]
    fn zero_match_cap_records_every_match() {
        let args = Args {
            pid: None,
            process_hint: DEFAULT_PROCESS_HINT.to_string(),
            out: None,
            context_bytes: DEFAULT_CONTEXT_BYTES,
            max_matches: 0,
            max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
            scan_images: false,
            interactive: false,
        };
        let buf = br#"{"DFIntS2PhysicsSenderRate":-30,"FIntCameraFarZPlane":100000}"#;
        let mut summary = ExportSummary::default();
        let mut matches = Vec::new();
        let mut seen = HashSet::new();
        for raw in scan_buffer_for_matches(buf) {
            record_evidence_match(
                &raw,
                buf,
                0x3000,
                &args,
                &mut matches,
                &mut seen,
                &mut summary,
            );
        }
        assert_eq!(summary.matches_seen, matches.len());
        assert_eq!(summary.matches_dropped_by_cap, 0);
        assert!(!summary.truncated_by_match_cap);
    }
}
