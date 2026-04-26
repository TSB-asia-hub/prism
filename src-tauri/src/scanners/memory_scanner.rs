// On non-Windows builds, memory scanning is stubbed and most helpers are only
// exercised by the Windows path or the unit tests. Silence dead_code there.
#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use crate::data::flag_allowlist::is_allowed_flag;
use crate::data::suspicious_flags::{
    get_flag_category, get_flag_description, get_flag_severity, CRITICAL_FLAGS, HIGH_FLAGS,
    MEDIUM_FLAGS,
};
use crate::models::{ScanFinding, ScanVerdict};
use crate::scanners::progress::ScanProgress;
use std::collections::{HashMap, HashSet};

/// Known FFlag prefixes. Any identifier matching `<prefix><IdentBody>` where
/// the body is a camel-cased identifier is a candidate flag name. Unknown
/// candidates stay informational unless they also have parsed value evidence
/// near injector/offset-tool provenance.
const FLAG_PREFIXES: &[&str] = &[
    "DFFlag", "FFlag", "DFInt", "FInt", "DFString", "FString", "DFLog", "FLog", "SFFlag", "SFInt",
    "SFString",
];

/// Maximum identifier body length after a prefix. Real Roblox flag names top
/// out around ~90 chars; anything longer is almost certainly not a flag.
const MAX_IDENT_BODY_LEN: usize = 128;
/// Minimum identifier body length. Single-character bodies are noise.
const MIN_IDENT_BODY_LEN: usize = 3;

/// Hard cap on regions walked per scan, to prevent runaway loops when the OS
/// enumeration API misbehaves. Roblox typically has far fewer regions.
const MAX_REGIONS_WALKED: usize = 200_000;

/// Wall-clock safety cap for the entire memory scan. Without this, a stuck
/// `ReadProcessMemory` on a pathological region (rare, but observed in
/// field reports) can hang the UI indefinitely with no recovery path. On
/// expiry the scan returns an Inconclusive "aborted" finding so the user
/// learns coverage was incomplete rather than seeing an infinite spinner.
const MAX_SCAN_DURATION: std::time::Duration = std::time::Duration::from_secs(90);

/// Max per-chunk read (16 MiB). Regions larger than this are chunked with a
/// replay overlap large enough to preserve injector context and string values
/// across chunk boundaries.
const MAX_CHUNK_BYTES: usize = 16 * 1024 * 1024;

/// Absolute per-region cap. Regions larger than this (>1 GiB) are only
/// partially scanned (the first ABS_REGION_CAP bytes), with coverage
/// accounting noting the truncation, to keep total scan time bounded.
const ABS_REGION_CAP: usize = 1024 * 1024 * 1024;

/// Fallback read granularity when a large ReadProcessMemory call fails.
/// Windows x64 uses 4 KiB pages; falling back this far prevents one raced page
/// from hiding an otherwise readable 16 MiB chunk.
const MIN_READ_CHUNK_BYTES: usize = 4 * 1024;

/// Do not scare users for normal Windows/Roblox memory churn. Even with an
/// administrator handle, pages can be decommitted or reprotected between
/// VirtualQueryEx and ReadProcessMemory. Surface a coverage warning only when
/// the unread/skipped span is large in absolute terms, large relative to the
/// intended scan, or effectively the whole memory scan.
const COVERAGE_WARNING_MIN_MISSING_BYTES: u64 = 512 * 1024 * 1024;
const COVERAGE_WARNING_LARGE_MISSING_BYTES: u64 = 1024 * 1024 * 1024;
const COVERAGE_WARNING_MIN_MISSING_PERCENT: u64 = 25;
const COVERAGE_WARNING_NEAR_TOTAL_MISSING_PERCENT: u64 = 90;

/// Maximum distance between a flag/value pair and injector/offset-tool
/// provenance strings for the value to be treated as runtime injection
/// evidence. Kept deliberately small relative to the 16 MiB scan chunk so a
/// random marker elsewhere in the same heap region does not taint vanilla
/// Roblox's remote flag-config blob.
const INJECTOR_CONTEXT_WINDOW_BYTES: usize = 64 * 1024;
const MAX_VALUE_SAMPLES_PER_FLAG: usize = 8;
const MAX_MARKER_MATCHES_PER_CHUNK: usize = 4096;
const MAX_PREFIX_HITS_PER_CHUNK: usize = 4096;
const FNV1A64_OFFSET: u64 = 0xcbf29ce484222325;
const FNV1A64_PRIME: u64 = 0x100000001b3;
const RUNTIME_TABLE_OFFSET_FROM_SINGLETON: usize = 0x8;
const RUNTIME_TABLE_SIZE: usize = 0x38;
const RUNTIME_TABLE_MAX_MASK: u64 = 0x00ff_ffff;
const MAX_RUNTIME_TABLE_HEADERS_PER_SCAN: usize = 65_536;
const RUNTIME_NODE_SIZE: usize = 0x38;
const RUNTIME_NODE_STRING_OFFSET: usize = 0x10;
const RUNTIME_NODE_LEN_OFFSET: usize = 0x20;
const RUNTIME_NODE_CAP_OFFSET: usize = 0x28;
const RUNTIME_NODE_ENTRY_OFFSET: usize = 0x30;
const RUNTIME_INLINE_STRING_CAP: u64 = 0x0f;
const MAX_RUNTIME_STRING_HITS_PER_CHUNK: usize = 1024;
const MAX_RUNTIME_NODE_ENTRIES_PER_SCAN: usize = 8192;
const RUNTIME_SINGLETON_ACCESSOR_PATTERN: &[Option<u8>] = &[
    Some(0x48),
    Some(0x83),
    Some(0xEC),
    Some(0x38),
    Some(0x48),
    Some(0x8B),
    Some(0x0D),
    None,
    None,
    None,
    None,
    Some(0x4C),
    Some(0x8D),
    Some(0x05),
    None,
    None,
    None,
    None,
];

/// Strings carried by common FFlag injectors / offset tools. These are not
/// verdicts on their own; they only let nearby parsed flag values graduate
/// from "Roblox heap contains a flag name" to "Roblox heap contains a
/// serialized injector/config artefact".
const INJECTOR_TOOL_MARKERS: &[&str] = &[
    "fflags.json",
    "address.json",
    "fflagtoolkit",
    "fflag_injector",
    "fflag-manager",
    "lornofix",
    "lornobypass",
    "odessa",
    "robloxoffsetdumper",
    "offset_dumper",
    "writeprocessmemory",
];

#[derive(Clone, Copy)]
struct MarkerMatch {
    name: &'static str,
    start: usize,
}

/// Aggregated state for an observed flag name, across all regions in one scan.
#[derive(Default)]
struct FlagHit {
    count: usize,
    first_address: usize,
    /// True if at least one occurrence was found as UTF-16LE (wide string).
    seen_wide: bool,
    /// True if at least one occurrence was found as plain ASCII/UTF-8.
    seen_ascii: bool,
    /// Best-effort literal value captured from bytes adjacent to the first
    /// match — typically `"FlagName":123` or `"FlagName":"str"`. None if no
    /// JSON-like context could be parsed. We keep several distinct values
    /// because vanilla Roblox flag payloads and injected override blobs can
    /// both be resident at once; the first value seen is not necessarily the
    /// one with evidentiary value.
    value_samples: Vec<FlagValueSample>,
}

#[derive(Clone)]
struct FlagValueSample {
    value: String,
    address: usize,
    wide: bool,
    context_summary: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeFlagValue {
    Bool(bool),
    Int(i32),
}

#[derive(Clone, Copy, Debug)]
struct RuntimeOverrideRule {
    name: &'static str,
    value: RuntimeFlagValue,
}

/// Values seen in public desync/ESP configs or in the deobfuscated
/// LornoFix payload. Runtime registry inspection only elevates exact
/// name+value pairs from this list; a bare registered flag name remains
/// baseline Roblox state.
const RUNTIME_OVERRIDE_RULES: &[RuntimeOverrideRule] = &[
    RuntimeOverrideRule {
        name: "DFIntS2PhysicsSenderRate",
        value: RuntimeFlagValue::Int(1),
    },
    RuntimeOverrideRule {
        name: "DFIntS2PhysicsSenderRate",
        value: RuntimeFlagValue::Int(-30),
    },
    RuntimeOverrideRule {
        name: "DFIntS2PhysicSenderRate",
        value: RuntimeFlagValue::Int(1),
    },
    RuntimeOverrideRule {
        name: "DFIntPhysicsSenderMaxBandwidthBps",
        value: RuntimeFlagValue::Int(1),
    },
    RuntimeOverrideRule {
        name: "DFIntPhysicsSenderMaxBandwidthBpsScaling",
        value: RuntimeFlagValue::Int(0),
    },
    RuntimeOverrideRule {
        name: "DFIntDataSenderRate",
        value: RuntimeFlagValue::Int(-1),
    },
    RuntimeOverrideRule {
        name: "DFIntTouchSenderMaxBandwidthBps",
        value: RuntimeFlagValue::Int(-1),
    },
    RuntimeOverrideRule {
        name: "DFIntMinClientSimulationRadius",
        value: RuntimeFlagValue::Int(2_147_000_000),
    },
    RuntimeOverrideRule {
        name: "DFIntMaxClientSimulationRadius",
        value: RuntimeFlagValue::Int(2_147_000_000),
    },
    RuntimeOverrideRule {
        name: "DFFlagDebugPhysicsSenderDoesNotShrinkSimRadius",
        value: RuntimeFlagValue::Bool(true),
    },
    RuntimeOverrideRule {
        name: "FFlagDebugUseCustomSimRadius",
        value: RuntimeFlagValue::Bool(true),
    },
    RuntimeOverrideRule {
        name: "NextGenReplicatorEnabledWrite4",
        value: RuntimeFlagValue::Bool(false),
    },
    RuntimeOverrideRule {
        name: "NextGenReplicatorEnabledRead",
        value: RuntimeFlagValue::Bool(false),
    },
    RuntimeOverrideRule {
        name: "LargeReplicatorEnabled9",
        value: RuntimeFlagValue::Bool(false),
    },
    RuntimeOverrideRule {
        name: "LargeReplicatorSerializeWrite4",
        value: RuntimeFlagValue::Bool(false),
    },
    RuntimeOverrideRule {
        name: "LargeReplicatorSerializeRead3",
        value: RuntimeFlagValue::Bool(false),
    },
    RuntimeOverrideRule {
        name: "LargeReplicatorWrite5",
        value: RuntimeFlagValue::Bool(false),
    },
    RuntimeOverrideRule {
        name: "LargeReplicatorRead5",
        value: RuntimeFlagValue::Bool(false),
    },
    RuntimeOverrideRule {
        name: "DFIntReplicatorAnimationTrackLimitPerAnimator",
        value: RuntimeFlagValue::Int(-1),
    },
    RuntimeOverrideRule {
        name: "DFIntGameNetPVHeaderTranslationZeroCutoffExponent",
        value: RuntimeFlagValue::Int(10),
    },
    RuntimeOverrideRule {
        name: "DFIntGameNetPVHeaderLinearVelocityZeroCutoffExponent",
        value: RuntimeFlagValue::Int(10),
    },
    RuntimeOverrideRule {
        name: "DFIntGameNetPVHeaderRotationalVelocityZeroCutoffExponent",
        value: RuntimeFlagValue::Int(10),
    },
    RuntimeOverrideRule {
        name: "DFIntAssemblyExtentsExpansionStudHundredth",
        value: RuntimeFlagValue::Int(-50),
    },
    RuntimeOverrideRule {
        name: "DFIntSimBlockLargeLocalToolWeldManipulationsThreshold",
        value: RuntimeFlagValue::Int(-1),
    },
    RuntimeOverrideRule {
        name: "DFIntDebugSimPrimalStiffness",
        value: RuntimeFlagValue::Int(0),
    },
    RuntimeOverrideRule {
        name: "DFIntSimAdaptiveHumanoidPDControllerSubstepMultiplier",
        value: RuntimeFlagValue::Int(-999_999),
    },
    RuntimeOverrideRule {
        name: "DFIntSolidFloorPercentForceApplication",
        value: RuntimeFlagValue::Int(-1_000),
    },
    RuntimeOverrideRule {
        name: "DFIntNonSolidFloorPercentForceApplication",
        value: RuntimeFlagValue::Int(-5_000),
    },
    RuntimeOverrideRule {
        name: "DFIntHipHeightClamp",
        value: RuntimeFlagValue::Int(-48),
    },
    RuntimeOverrideRule {
        name: "FIntParallelDynamicPartsFastClusterBatchSize",
        value: RuntimeFlagValue::Int(-1),
    },
    RuntimeOverrideRule {
        name: "DFIntRaycastMaxDistance",
        value: RuntimeFlagValue::Int(3),
    },
    RuntimeOverrideRule {
        name: "DFIntMaxMissedWorldStepsRemembered",
        value: RuntimeFlagValue::Int(1_000),
    },
    RuntimeOverrideRule {
        name: "DFIntMaxActiveAnimationTracks",
        value: RuntimeFlagValue::Int(0),
    },
    RuntimeOverrideRule {
        name: "DFFlagDebugDrawBroadPhaseAABBs",
        value: RuntimeFlagValue::Bool(true),
    },
    RuntimeOverrideRule {
        name: "DFFlagDebugDrawBvhNodes",
        value: RuntimeFlagValue::Bool(true),
    },
    RuntimeOverrideRule {
        name: "DFFlagDebugDrawEnable",
        value: RuntimeFlagValue::Bool(true),
    },
    RuntimeOverrideRule {
        name: "FIntCameraFarZPlane",
        value: RuntimeFlagValue::Int(0),
    },
    RuntimeOverrideRule {
        name: "FIntCameraFarZPlane",
        value: RuntimeFlagValue::Int(1),
    },
    RuntimeOverrideRule {
        name: "DFIntDebugRestrictGCDistance",
        value: RuntimeFlagValue::Int(1),
    },
    RuntimeOverrideRule {
        name: "DFIntAnimationLodFacsDistanceMin",
        value: RuntimeFlagValue::Int(0),
    },
    RuntimeOverrideRule {
        name: "DFIntAnimationLodFacsDistanceMax",
        value: RuntimeFlagValue::Int(0),
    },
    RuntimeOverrideRule {
        name: "FIntRenderShadowIntensity",
        value: RuntimeFlagValue::Int(0),
    },
    RuntimeOverrideRule {
        name: "FFlagDisablePostFx",
        value: RuntimeFlagValue::Bool(true),
    },
    RuntimeOverrideRule {
        name: "FFlagDebugDontRenderScreenGui",
        value: RuntimeFlagValue::Bool(true),
    },
    RuntimeOverrideRule {
        name: "FFlagDebugDontRenderUI",
        value: RuntimeFlagValue::Bool(true),
    },
];

/// Aggregated state for high-risk strings that offset-based FFlag injectors
/// commonly carry alongside their serialized config/address cache. These are
/// only used in combinations (for example `fflags.json` + `address.json`) so
/// a single incidental string does not raise the verdict.
#[derive(Default)]
struct ToolMarkerHit {
    count: usize,
    first_address: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RuntimeTableHeaderCandidate {
    address: usize,
    mask: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RuntimeStringHit {
    name: &'static str,
    offset: usize,
    address: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RuntimeNodeEntryCandidate {
    name: &'static str,
    node_address: usize,
    string_address: usize,
    entry: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RuntimeLongStringNodeCandidate {
    node_address: usize,
    string_address: usize,
    entry: usize,
    len: usize,
}

/// Per-scan hit map. Keys are interned flag names (static strings for known
/// flags, owned strings for unknown discoveries).
#[derive(Default)]
struct FlagHitTable {
    hits: HashMap<String, FlagHit>,
    tool_markers: HashMap<&'static str, ToolMarkerHit>,
    runtime_table_headers: Vec<RuntimeTableHeaderCandidate>,
    runtime_table_header_seen: HashSet<usize>,
    runtime_table_header_matches: usize,
    runtime_node_entries: Vec<RuntimeNodeEntryCandidate>,
    runtime_node_entry_seen: HashSet<(&'static str, usize)>,
    runtime_node_entry_matches: usize,
    runtime_string_hits: Vec<RuntimeStringHit>,
    runtime_string_hit_seen: HashSet<usize>,
    runtime_long_string_nodes: Vec<RuntimeLongStringNodeCandidate>,
    runtime_long_string_node_seen: HashSet<(usize, usize)>,
    runtime_long_string_node_matches: usize,
}

impl FlagHitTable {
    fn record_with_value(
        &mut self,
        flag: &str,
        address: usize,
        wide: bool,
        value: Option<String>,
        context_summary: Option<String>,
    ) {
        let entry = self.hits.entry(flag.to_string()).or_default();
        if entry.count == 0 {
            entry.first_address = address;
        }
        entry.count += 1;
        if wide {
            entry.seen_wide = true;
        } else {
            entry.seen_ascii = true;
        }
        if let Some(value) = value {
            let injector_context = context_summary.is_some();
            let already_seen = entry.value_samples.iter().any(|s| {
                s.value == value && s.wide == wide && s.context_summary == context_summary
            });
            if !already_seen {
                let sample = FlagValueSample {
                    value,
                    address,
                    wide,
                    context_summary,
                };
                push_value_sample(&mut entry.value_samples, sample, injector_context);
            }
        }
    }

    fn record_tool_marker(&mut self, marker: &'static str, address: usize) {
        let entry = self.tool_markers.entry(marker).or_default();
        if entry.count == 0 || address < entry.first_address {
            entry.first_address = address;
        }
        entry.count += 1;
    }

    fn record_runtime_table_header(&mut self, candidate: RuntimeTableHeaderCandidate) {
        self.runtime_table_header_matches = self.runtime_table_header_matches.saturating_add(1);
        self.keep_runtime_table_header(candidate);
    }

    fn keep_runtime_table_header(&mut self, candidate: RuntimeTableHeaderCandidate) {
        if self.runtime_table_header_seen.contains(&candidate.address) {
            return;
        }
        if self.runtime_table_headers.len() < MAX_RUNTIME_TABLE_HEADERS_PER_SCAN {
            self.runtime_table_header_seen.insert(candidate.address);
            self.runtime_table_headers.push(candidate);
            return;
        }

        if let Some((weakest_index, weakest)) = self
            .runtime_table_headers
            .iter()
            .enumerate()
            .min_by_key(|(_, existing)| existing.mask)
        {
            if candidate.mask <= weakest.mask {
                return;
            }
            self.runtime_table_header_seen.remove(&weakest.address);
            self.runtime_table_header_seen.insert(candidate.address);
            self.runtime_table_headers[weakest_index] = candidate;
        }
    }

    fn record_runtime_node_entry(&mut self, candidate: RuntimeNodeEntryCandidate) {
        self.runtime_node_entry_matches = self.runtime_node_entry_matches.saturating_add(1);
        self.keep_runtime_node_entry(candidate);
    }

    fn keep_runtime_node_entry(&mut self, candidate: RuntimeNodeEntryCandidate) {
        let key = (candidate.name, candidate.entry);
        if self.runtime_node_entry_seen.contains(&key) {
            return;
        }
        if self.runtime_node_entries.len() >= MAX_RUNTIME_NODE_ENTRIES_PER_SCAN {
            return;
        }
        self.runtime_node_entry_seen.insert(key);
        self.runtime_node_entries.push(candidate);
    }

    fn record_runtime_string_hit(&mut self, hit: RuntimeStringHit) {
        if self.runtime_string_hit_seen.contains(&hit.address) {
            return;
        }
        if self.runtime_string_hits.len() >= MAX_RUNTIME_NODE_ENTRIES_PER_SCAN {
            return;
        }
        self.runtime_string_hit_seen.insert(hit.address);
        self.runtime_string_hits.push(hit);
    }

    fn record_runtime_long_string_node(&mut self, candidate: RuntimeLongStringNodeCandidate) {
        self.runtime_long_string_node_matches =
            self.runtime_long_string_node_matches.saturating_add(1);
        let key = (candidate.string_address, candidate.entry);
        if self.runtime_long_string_node_seen.contains(&key) {
            return;
        }
        if self.runtime_long_string_nodes.len() >= MAX_RUNTIME_NODE_ENTRIES_PER_SCAN {
            return;
        }
        self.runtime_long_string_node_seen.insert(key);
        self.runtime_long_string_nodes.push(candidate);
    }

    fn total_flags(&self) -> usize {
        self.hits.len()
    }

    /// Fold another table into this one. Used by the parallel scanner to
    /// combine per-worker tables at the end of the region walk. Preserves
    /// the lowest observed `first_address` across workers so the final
    /// finding points at the earliest sighting, not a random one.
    fn merge(&mut self, other: FlagHitTable) {
        for (name, h) in other.hits {
            match self.hits.entry(name) {
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    let existing = e.get_mut();
                    if existing.count == 0 || h.first_address < existing.first_address {
                        existing.first_address = h.first_address;
                    }
                    existing.count = existing.count.saturating_add(h.count);
                    existing.seen_wide |= h.seen_wide;
                    existing.seen_ascii |= h.seen_ascii;
                    for sample in h.value_samples {
                        let has_context = sample.context_summary.is_some();
                        let already_seen = existing.value_samples.iter().any(|s| {
                            s.value == sample.value
                                && s.wide == sample.wide
                                && s.context_summary == sample.context_summary
                        });
                        if !already_seen {
                            push_value_sample(&mut existing.value_samples, sample, has_context);
                        }
                    }
                }
                std::collections::hash_map::Entry::Vacant(v) => {
                    v.insert(h);
                }
            }
        }
        for (marker, h) in other.tool_markers {
            match self.tool_markers.entry(marker) {
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    let existing = e.get_mut();
                    if existing.count == 0 || h.first_address < existing.first_address {
                        existing.first_address = h.first_address;
                    }
                    existing.count = existing.count.saturating_add(h.count);
                }
                std::collections::hash_map::Entry::Vacant(v) => {
                    v.insert(h);
                }
            }
        }
        self.runtime_table_header_matches = self
            .runtime_table_header_matches
            .saturating_add(other.runtime_table_header_matches);
        for candidate in other.runtime_table_headers {
            self.keep_runtime_table_header(candidate);
        }
        self.runtime_node_entry_matches = self
            .runtime_node_entry_matches
            .saturating_add(other.runtime_node_entry_matches);
        for candidate in other.runtime_node_entries {
            self.keep_runtime_node_entry(candidate);
        }
        for hit in other.runtime_string_hits {
            self.record_runtime_string_hit(hit);
        }
        self.runtime_long_string_node_matches = self
            .runtime_long_string_node_matches
            .saturating_add(other.runtime_long_string_node_matches);
        for candidate in other.runtime_long_string_nodes {
            let key = (candidate.string_address, candidate.entry);
            if self.runtime_long_string_node_seen.contains(&key) {
                continue;
            }
            if self.runtime_long_string_nodes.len() >= MAX_RUNTIME_NODE_ENTRIES_PER_SCAN {
                continue;
            }
            self.runtime_long_string_node_seen.insert(key);
            self.runtime_long_string_nodes.push(candidate);
        }
    }
}

fn push_value_sample(
    samples: &mut Vec<FlagValueSample>,
    sample: FlagValueSample,
    has_context: bool,
) {
    if samples.len() < MAX_VALUE_SAMPLES_PER_FLAG {
        samples.push(sample);
        return;
    }

    // Context-backed samples are the only ones that can affect the verdict,
    // so never let a pile of vanilla remote-config values crowd out the first
    // useful injector-context value for the same flag.
    if has_context {
        if let Some(slot) = samples.iter().position(|s| s.context_summary.is_none()) {
            samples[slot] = sample;
        }
    }
}

fn percent(part: u64, total: u64) -> u64 {
    if total == 0 {
        0
    } else {
        part.min(total).saturating_mul(100) / total
    }
}

fn coverage_gap_is_material(missing_bytes: u64, intended_bytes: u64) -> bool {
    if missing_bytes == 0 || intended_bytes == 0 {
        return false;
    }
    let missing_percent = percent(missing_bytes, intended_bytes);
    missing_bytes >= COVERAGE_WARNING_LARGE_MISSING_BYTES
        || missing_percent >= COVERAGE_WARNING_NEAR_TOTAL_MISSING_PERCENT
        || (missing_bytes >= COVERAGE_WARNING_MIN_MISSING_BYTES
            && missing_percent >= COVERAGE_WARNING_MIN_MISSING_PERCENT)
}

#[derive(Clone, Copy, Debug, Default)]
struct MemoryCoverage {
    intended_bytes: u64,
    bytes_scanned: u64,
    regions_scanned: usize,
    truncated_regions: usize,
    truncated_bytes: u64,
    read_failures: usize,
    read_failed_bytes: u64,
}

impl MemoryCoverage {
    fn gap_bytes(self) -> u64 {
        self.truncated_bytes
            .saturating_add(self.read_failed_bytes)
            .min(self.intended_bytes)
    }

    fn gap_percent(self) -> u64 {
        percent(self.gap_bytes(), self.intended_bytes)
    }

    fn no_successful_reads(self) -> bool {
        self.intended_bytes > 0 && self.bytes_scanned == 0
    }

    fn material_gap(self) -> bool {
        coverage_gap_is_material(self.gap_bytes(), self.intended_bytes)
    }

    fn details(self) -> String {
        format!(
            "intended_bytes: {}, bytes_scanned: {}, regions_scanned: {}, coverage_gap_bytes: {}, coverage_gap_percent: {}%, truncated_regions: {}, truncated_bytes: {}, read_failures: {}, read_failed_bytes: {}",
            self.intended_bytes,
            self.bytes_scanned,
            self.regions_scanned,
            self.gap_bytes(),
            self.gap_percent(),
            self.truncated_regions,
            self.truncated_bytes,
            self.read_failures,
            self.read_failed_bytes
        )
    }
}

/// Scan Roblox process memory for runtime FFlag injections.
#[allow(dead_code)]
pub async fn scan() -> Vec<ScanFinding> {
    scan_with_progress(ScanProgress::noop()).await
}

/// Same as [`scan`] but accepts a progress reporter so the frontend can show
/// live region/byte counters while the Windows memory walk is in flight.
pub async fn scan_with_progress(reporter: ScanProgress) -> Vec<ScanFinding> {
    #[cfg(all(target_os = "windows", target_pointer_width = "64"))]
    {
        scan_windows(reporter).await
    }

    #[cfg(all(target_os = "windows", not(target_pointer_width = "64")))]
    {
        let _ = reporter;
        vec![ScanFinding::new(
            "memory_scanner",
            ScanVerdict::Inconclusive,
            "Memory scan requires a 64-bit Windows build",
            Some(
                "32-bit Windows builds cannot safely inspect a 64-bit Roblox address space."
                    .to_string(),
            ),
        )]
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = reporter; // unused on non-Windows
        vec![ScanFinding::new(
            "memory_scanner",
            ScanVerdict::Inconclusive,
            "Memory scan not supported on this platform",
            Some("Memory scanning is Windows-only in this build — the scan result reflects only process/file/client-settings coverage.".to_string()),
        )]
    }
}

/// Result of locating a Roblox process: the PID and whether the executable
/// path passed basic validation against expected Roblox install roots.
#[cfg(all(target_os = "windows", target_pointer_width = "64"))]
struct RobloxProcess {
    pid: u32,
    exe_path: Option<String>,
    path_looks_trusted: bool,
}

/// Find the Roblox process PID, validating the executable path against
/// expected install roots. Falls back to name-only matching when the path
/// cannot be read.
#[cfg(all(target_os = "windows", target_pointer_width = "64"))]
fn find_roblox_process() -> Option<RobloxProcess> {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System};
    let mut sys = System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_all();

    let name_hint = "robloxplayerbeta";

    let mut best: Option<RobloxProcess> = None;

    for (pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().to_lowercase();
        if !name.contains(name_hint) {
            continue;
        }
        let exe_path = process.exe().map(|p| p.to_string_lossy().to_string());
        let path_looks_trusted = exe_path
            .as_deref()
            .map(is_trusted_roblox_exe_path)
            .unwrap_or(false);

        let candidate = RobloxProcess {
            pid: pid.as_u32(),
            exe_path,
            path_looks_trusted,
        };

        // Prefer a trusted-path match; otherwise keep the FIRST name match
        // and don't let later untrusted matches overwrite it.
        match &best {
            Some(b) if b.path_looks_trusted => {} // already optimal — keep it
            Some(_) if !candidate.path_looks_trusted => {} // keep the first untrusted
            _ => best = Some(candidate),
        }
        if let Some(b) = &best {
            if b.path_looks_trusted {
                break;
            }
        }
    }

    best
}

/// Check whether an executable path looks like a real Roblox install.
#[cfg(all(target_os = "windows", target_pointer_width = "64"))]
fn is_trusted_roblox_exe_path(exe_path: &str) -> bool {
    let lower = exe_path.to_lowercase();
    let roots: Vec<String> = trusted_windows_roblox_roots();
    roots.iter().any(|r| lower.starts_with(&r.to_lowercase()))
}

/// Require that the match be bounded by non-identifier bytes (or start/end of
/// buffer). This rejects matches that are a prefix/suffix inside a longer
/// identifier — e.g. searching for `FFlagFoo` must not match `FFlagFooBar`.
fn is_boundary_ok(buffer: &[u8], start: usize, len: usize) -> bool {
    let before = if start == 0 {
        None
    } else {
        Some(buffer[start - 1])
    };
    let after_idx = start + len;
    let after = if after_idx < buffer.len() {
        Some(buffer[after_idx])
    } else {
        None
    };
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    if before.map(is_ident).unwrap_or(false) {
        return false;
    }
    if after.map(is_ident).unwrap_or(false) {
        return false;
    }
    true
}

/// Extended boundary check requiring at least one surrounding byte to look like
/// a JSON/C-string/shell delimiter. Used for generic prefix discovery so that
/// identifiers embedded in random binary noise are not picked up.
fn is_contextual_match(buffer: &[u8], start: usize, len: usize) -> bool {
    if !is_boundary_ok(buffer, start, len) {
        return false;
    }
    let before = if start == 0 {
        None
    } else {
        Some(buffer[start - 1])
    };
    let after_idx = start + len;
    let after = if after_idx < buffer.len() {
        Some(buffer[after_idx])
    } else {
        None
    };
    // NUL was previously accepted here as a delimiter, but NUL-padded C
    // strings (and the runtime's interned flag-name registry strings) end
    // with NUL. Accepting it meant every Roblox-internal reference to a
    // suspicious flag name trivially passed the "looks like config context"
    // check. Require an actual JSON / config-file delimiter on at least one
    // side, and reject matches bounded by NUL on both sides.
    let is_delim = |b: u8| matches!(b, b'"' | b':' | b'=' | b'{' | b',' | b' ' | b'\t');
    let before_ok = before.map(is_delim).unwrap_or(true);
    let after_ok = after.map(is_delim).unwrap_or(true);
    before_ok && after_ok
}

/// Identifier-body character (first byte must still be an uppercase letter,
/// see the scanner logic).
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_value_boundary_byte(b: u8) -> bool {
    b == 0 || b.is_ascii_whitespace() || matches!(b, b',' | b'}' | b']' | b';')
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = FNV1A64_OFFSET;
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV1A64_PRIME);
    }
    hash
}

fn resolve_rip_relative_address(
    instruction_address: usize,
    instruction_len: usize,
    disp: i32,
) -> usize {
    let rip_after_instruction = instruction_address.saturating_add(instruction_len);
    if disp >= 0 {
        rip_after_instruction.saturating_add(disp as usize)
    } else {
        rip_after_instruction.saturating_sub((-disp) as usize)
    }
}

fn push_unique_runtime_slot(out: &mut Vec<usize>, slot: usize) {
    if !out.contains(&slot) {
        out.push(slot);
    }
}

fn is_rip_relative_qword_load(buffer: &[u8], i: usize) -> bool {
    i + 7 <= buffer.len()
        && matches!(buffer[i], 0x48 | 0x4C)
        && buffer[i + 1] == 0x8B
        && (buffer[i + 2] & 0xC7) == 0x05
}

fn find_runtime_singleton_slots(buffer: &[u8], base_address: usize) -> Vec<usize> {
    let mut out = Vec::new();
    let pattern = RUNTIME_SINGLETON_ACCESSOR_PATTERN;

    if buffer.len() >= pattern.len() {
        for i in 0..=buffer.len() - pattern.len() {
            if !pattern
                .iter()
                .enumerate()
                .all(|(j, expected)| expected.map(|b| buffer[i + j] == b).unwrap_or(true))
            {
                continue;
            }
            let disp_start = i + 7;
            let disp = i32::from_le_bytes([
                buffer[disp_start],
                buffer[disp_start + 1],
                buffer[disp_start + 2],
                buffer[disp_start + 3],
            ]);
            let slot = resolve_rip_relative_address(base_address.saturating_add(i), 11, disp);
            push_unique_runtime_slot(&mut out, slot);
        }
    }

    // Lorno's own pattern path does not need the full accessor shape above: it
    // finds the RIP-relative singleton load, reads that slot, and validates the
    // table. Roblox updates can change the surrounding prologue/trailing LEA
    // while leaving this load intact, so use the same core primitive and let the
    // remote table validator reject unrelated global loads.
    if buffer.len() >= 7 {
        for i in 0..=buffer.len() - 7 {
            if !is_rip_relative_qword_load(buffer, i) {
                continue;
            }
            let disp =
                i32::from_le_bytes([buffer[i + 3], buffer[i + 4], buffer[i + 5], buffer[i + 6]]);
            let slot = resolve_rip_relative_address(base_address.saturating_add(i), 7, disp);
            push_unique_runtime_slot(&mut out, slot);
        }
    }

    out
}

fn runtime_table_header_mask(table: &[u8]) -> Option<u64> {
    if table.len() < RUNTIME_TABLE_SIZE {
        return None;
    }

    let sentinel = u64::from_le_bytes(table[0x00..0x08].try_into().unwrap());
    let buckets = u64::from_le_bytes(table[0x10..0x18].try_into().unwrap());
    let mask = u64::from_le_bytes(table[0x28..0x30].try_into().unwrap());

    (sentinel != 0
        && buckets != 0
        && sentinel != buckets
        && (sentinel & 0x7) == 0
        && (buckets & 0x7) == 0
        && mask != 0
        && (mask + 1).is_power_of_two()
        && mask <= RUNTIME_TABLE_MAX_MASK)
        .then_some(mask)
}

fn runtime_table_header_bytes_look_plausible(table: &[u8]) -> bool {
    runtime_table_header_mask(table).is_some()
}

fn find_runtime_table_headers(
    buffer: &[u8],
    base_address: usize,
) -> Vec<RuntimeTableHeaderCandidate> {
    let mut out = Vec::new();
    if buffer.len() < RUNTIME_TABLE_SIZE {
        return out;
    }

    let aligned_start = (8usize.wrapping_sub(base_address & 0x7)) & 0x7;
    let mut i = aligned_start;
    while i + RUNTIME_TABLE_SIZE <= buffer.len() {
        if let Some(mask) = runtime_table_header_mask(&buffer[i..i + RUNTIME_TABLE_SIZE]) {
            let address = base_address.saturating_add(i);
            if !out.iter().any(|candidate| candidate.address == address) {
                out.push(RuntimeTableHeaderCandidate { address, mask });
            }
        }
        i = i.saturating_add(8);
    }

    out
}

fn runtime_value_label(value: RuntimeFlagValue) -> String {
    match value {
        RuntimeFlagValue::Bool(v) => v.to_string(),
        RuntimeFlagValue::Int(v) => v.to_string(),
    }
}

fn runtime_rule_matches_observed(rule: RuntimeOverrideRule, raw_value: [u8; 4]) -> bool {
    let observed_int = i32::from_le_bytes(raw_value);
    match rule.value {
        RuntimeFlagValue::Int(expected) => observed_int == expected,
        RuntimeFlagValue::Bool(expected) => match observed_int {
            0 => !expected,
            1 => expected,
            _ => false,
        },
    }
}

/// Longest value literal we'll surface in a finding. Strings longer than
/// this are truncated with a trailing "…" — the point is evidence for the
/// operator, not a full dump of an adjacent memory region.
const MAX_VALUE_CAPTURE_BYTES: usize = 64;

/// Attempt to extract a JSON/assignment-style value that immediately follows
/// a flag NAME match in ASCII bytes. Expected shapes (after skipping the
/// optional closing quote and the `:` / `=` separator):
///   "FlagName":1234
///   "FlagName":"literal"
///   "FlagName":true | false
///   FlagName=1234
///   "FlagName":null
/// Returns `None` if no such context is present (e.g. the name is a bare
/// C string in Roblox's flag registry with no adjacent JSON value).
fn extract_adjacent_value_ascii(buffer: &[u8], match_end: usize) -> Option<String> {
    // Skip over an optional closing quote `"` after the name — we accept
    // both `"Foo":1` and `Foo:1` shapes because some memory layouts store
    // interned keys without quotes.
    let mut i = match_end;
    if i < buffer.len() && buffer[i] == b'"' {
        i += 1;
    }
    // Skip whitespace up to the value separator.
    while i < buffer.len() && buffer[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= buffer.len() || !matches!(buffer[i], b':' | b'=') {
        return None;
    }
    i += 1;
    while i < buffer.len() && buffer[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= buffer.len() {
        return None;
    }

    let start = i;
    match buffer[i] {
        // Quoted string: read up to the next unescaped quote.
        b'"' => {
            i += 1;
            let str_start = i;
            let mut escaped = false;
            while i < buffer.len() && buffer[i] != 0 {
                if !escaped && buffer[i] == b'"' {
                    break;
                }
                escaped = !escaped && buffer[i] == b'\\';
                i += 1;
            }
            if i >= buffer.len() || buffer[i] != b'"' {
                return None;
            }
            let after_quote = i + 1;
            if after_quote < buffer.len() && !is_value_boundary_byte(buffer[after_quote]) {
                return None;
            }
            let captured_end = (str_start + MAX_VALUE_CAPTURE_BYTES).min(i);
            let body = &buffer[str_start..captured_end];
            let s = std::str::from_utf8(body).ok()?;
            let truncated = i - str_start > MAX_VALUE_CAPTURE_BYTES;
            Some(if truncated {
                format!("\"{}…\"", s)
            } else {
                format!("\"{}\"", s)
            })
        }
        // Number: int / float / leading sign.
        b'-' | b'0'..=b'9' => {
            if buffer[i] == b'-' {
                i += 1;
            }
            let int_start = i;
            while i < buffer.len()
                && i - start < MAX_VALUE_CAPTURE_BYTES
                && buffer[i].is_ascii_digit()
            {
                i += 1;
            }
            let mut saw_digit = i > int_start;
            if i < buffer.len() && i - start < MAX_VALUE_CAPTURE_BYTES && buffer[i] == b'.' {
                i += 1;
                let frac_start = i;
                while i < buffer.len()
                    && i - start < MAX_VALUE_CAPTURE_BYTES
                    && buffer[i].is_ascii_digit()
                {
                    i += 1;
                }
                saw_digit |= i > frac_start;
            }
            if !saw_digit {
                return None;
            }
            if i < buffer.len()
                && i - start < MAX_VALUE_CAPTURE_BYTES
                && matches!(buffer[i], b'e' | b'E')
            {
                let exp_marker = i;
                i += 1;
                if i < buffer.len() && matches!(buffer[i], b'+' | b'-') {
                    i += 1;
                }
                let exp_start = i;
                while i < buffer.len()
                    && i - start < MAX_VALUE_CAPTURE_BYTES
                    && buffer[i].is_ascii_digit()
                {
                    i += 1;
                }
                if i == exp_start {
                    i = exp_marker;
                }
            }
            if i < buffer.len() && !is_value_boundary_byte(buffer[i]) {
                return None;
            }
            std::str::from_utf8(&buffer[start..i])
                .ok()
                .map(str::to_owned)
        }
        // true / false / null — peek up to 5 bytes and check.
        b't' | b'f' | b'n' => {
            let end = (start + 5).min(buffer.len());
            let slice = &buffer[start..end];
            if slice.starts_with(b"true")
                && buffer
                    .get(start + 4)
                    .map(|b| is_value_boundary_byte(*b))
                    .unwrap_or(true)
            {
                Some("true".to_string())
            } else if slice.starts_with(b"false")
                && buffer
                    .get(start + 5)
                    .map(|b| is_value_boundary_byte(*b))
                    .unwrap_or(true)
            {
                Some("false".to_string())
            } else if slice.starts_with(b"null")
                && buffer
                    .get(start + 4)
                    .map(|b| is_value_boundary_byte(*b))
                    .unwrap_or(true)
            {
                Some("null".to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Wide (UTF-16LE) variant of `extract_adjacent_value_ascii`. We handle the
/// common case where the override looks like `F\x00l\x00a\x00g\x00"\x00:\x00`
/// followed by either another wide string or a wide-encoded digit run.
fn extract_adjacent_value_wide(buffer: &[u8], match_end: usize) -> Option<String> {
    // Decode up to MAX_VALUE_CAPTURE_BYTES wide chars into a scratch string
    // and then parse it with the ASCII extractor. This avoids duplicating
    // all of the JSON shape logic.
    let mut i = match_end;
    let mut ascii: Vec<u8> = Vec::with_capacity(MAX_VALUE_CAPTURE_BYTES + 8);
    while i + 1 < buffer.len() && ascii.len() < MAX_VALUE_CAPTURE_BYTES + 8 {
        let lo = buffer[i];
        let hi = buffer[i + 1];
        // Only copy bytes that look like genuine wide-encoded ASCII — a
        // non-zero high byte means the code unit is non-ASCII, which
        // terminates our capture window.
        if hi != 0 {
            break;
        }
        ascii.push(lo);
        i += 2;
    }
    extract_adjacent_value_ascii(&ascii, 0)
}

/// Cached set of every known suspicious flag name, for O(1) lookups from
/// the hot ASCII-scan loop. Before this cache each candidate triggered three
/// linear scans over the CRITICAL/HIGH/MEDIUM arrays (~300 string compares
/// per hit).
fn known_flag_set() -> &'static HashSet<&'static str> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<HashSet<&'static str>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut s: HashSet<&'static str> = HashSet::with_capacity(known_suspicious_names().len());
        s.extend(known_suspicious_names().iter().copied());
        s
    })
}

fn runtime_tracked_name_set() -> &'static HashSet<&'static str> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<HashSet<&'static str>> = OnceLock::new();
    CACHE.get_or_init(|| {
        RUNTIME_OVERRIDE_RULES
            .iter()
            .map(|rule| rule.name)
            .collect()
    })
}

fn runtime_tracked_name_lengths() -> &'static HashSet<usize> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<HashSet<usize>> = OnceLock::new();
    CACHE.get_or_init(|| {
        RUNTIME_OVERRIDE_RULES
            .iter()
            .map(|rule| rule.name.len())
            .collect()
    })
}

fn known_suspicious_names() -> &'static Vec<&'static str> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Vec<&'static str>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut names: Vec<&'static str> =
            Vec::with_capacity(CRITICAL_FLAGS.len() + HIGH_FLAGS.len() + MEDIUM_FLAGS.len());
        names.extend(CRITICAL_FLAGS.iter().copied());
        names.extend(HIGH_FLAGS.iter().copied());
        names.extend(MEDIUM_FLAGS.iter().copied());
        names
    })
}

/// Cached Aho-Corasick automaton over every known suspicious flag name in
/// ASCII. This catches suspicious DB entries that do not have the standard
/// FFlag/DFInt prefix (for example `NextGenReplicatorEnabledWrite4`) and lets
/// known names be collected even when they are NUL-bounded C strings. Verdicts
/// still require stronger value/provenance evidence later.
fn known_ascii_automaton() -> &'static (aho_corasick::AhoCorasick, Vec<&'static str>) {
    use std::sync::OnceLock;
    static CACHE: OnceLock<(aho_corasick::AhoCorasick, Vec<&'static str>)> = OnceLock::new();
    CACHE.get_or_init(|| {
        let names = known_suspicious_names().clone();
        let ac = aho_corasick::AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .build(&names)
            .expect("aho-corasick automaton build should not fail over static flag set");
        (ac, names)
    })
}

fn tool_marker_ascii_automaton() -> &'static (aho_corasick::AhoCorasick, Vec<&'static str>) {
    use std::sync::OnceLock;
    static CACHE: OnceLock<(aho_corasick::AhoCorasick, Vec<&'static str>)> = OnceLock::new();
    CACHE.get_or_init(|| {
        let names: Vec<&'static str> = INJECTOR_TOOL_MARKERS.to_vec();
        let ac = aho_corasick::AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .build(&names)
            .expect("aho-corasick automaton build should not fail over static marker set");
        (ac, names)
    })
}

fn tool_marker_wide_automaton() -> &'static (aho_corasick::AhoCorasick, Vec<&'static str>) {
    use std::sync::OnceLock;
    static CACHE: OnceLock<(aho_corasick::AhoCorasick, Vec<&'static str>)> = OnceLock::new();
    CACHE.get_or_init(|| {
        let names: Vec<&'static str> = INJECTOR_TOOL_MARKERS.to_vec();
        let patterns: Vec<Vec<u8>> = names.iter().map(|n| to_utf16le(n)).collect();
        let ac = aho_corasick::AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .build(&patterns)
            .expect("aho-corasick automaton build should not fail over static marker set");
        (ac, names)
    })
}

fn marker_is_config(name: &str) -> bool {
    name.eq_ignore_ascii_case("fflags.json")
}

fn marker_is_address_cache(name: &str) -> bool {
    name.eq_ignore_ascii_case("address.json")
}

fn marker_is_strong_tool(name: &str) -> bool {
    matches!(
        name,
        "fflagtoolkit"
            | "fflag_injector"
            | "fflag-manager"
            | "lornofix"
            | "lornobypass"
            | "robloxoffsetdumper"
            | "offset_dumper"
    )
}

fn marker_is_memory_writer(name: &str) -> bool {
    name.eq_ignore_ascii_case("writeprocessmemory")
}

fn is_marker_delim(b: u8) -> bool {
    b == 0
        || b.is_ascii_whitespace()
        || matches!(
            b,
            b'"' | b'\''
                | b'\\'
                | b'/'
                | b':'
                | b';'
                | b','
                | b'{'
                | b'}'
                | b'['
                | b']'
                | b'('
                | b')'
                | b'='
        )
}

fn is_marker_boundary_ok(buffer: &[u8], start: usize, len: usize) -> bool {
    let before_ok = start == 0 || is_marker_delim(buffer[start - 1]);
    let after_idx = start + len;
    let after_ok = after_idx >= buffer.len() || is_marker_delim(buffer[after_idx]);
    before_ok && after_ok
}

fn is_wide_marker_boundary_ok(buffer: &[u8], start: usize, len: usize) -> bool {
    let before_ok = if start >= 2 {
        let lo = buffer[start - 2];
        let hi = buffer[start - 1];
        hi == 0 && is_marker_delim(lo)
    } else {
        true
    };
    let after = start + len;
    let after_ok = if after + 1 < buffer.len() {
        let lo = buffer[after];
        let hi = buffer[after + 1];
        hi == 0 && is_marker_delim(lo)
    } else {
        true
    };
    before_ok && after_ok
}

fn injector_context_summary_near(markers: &[MarkerMatch], offset: usize) -> Option<String> {
    let mut has_config = false;
    let mut has_address_cache = false;
    let mut has_strong_tool = false;
    let mut has_writer = false;
    let mut nearby = Vec::new();

    for marker in markers
        .iter()
        .filter(|m| m.start.abs_diff(offset) <= INJECTOR_CONTEXT_WINDOW_BYTES)
    {
        has_config |= marker_is_config(marker.name);
        has_address_cache |= marker_is_address_cache(marker.name);
        has_strong_tool |= marker_is_strong_tool(marker.name);
        has_writer |= marker_is_memory_writer(marker.name);
        if nearby.len() < 8 && !nearby.contains(&marker.name) {
            nearby.push(marker.name);
        }
    }

    let supported = (has_config && has_address_cache)
        || (has_config && has_writer)
        || (has_strong_tool && (has_config || has_address_cache || has_writer));
    if supported {
        Some(nearby.join(", "))
    } else {
        None
    }
}

fn scan_tool_markers(
    buffer: &[u8],
    base_address: usize,
    table: &mut FlagHitTable,
) -> Vec<MarkerMatch> {
    let mut matches = Vec::new();

    let (ascii_ac, ascii_names) = tool_marker_ascii_automaton();
    for m in ascii_ac.find_iter(buffer) {
        let name = ascii_names[m.pattern().as_usize()];
        if !is_marker_boundary_ok(buffer, m.start(), m.end() - m.start()) {
            continue;
        }
        table.record_tool_marker(name, base_address.saturating_add(m.start()));
        if matches.len() < MAX_MARKER_MATCHES_PER_CHUNK {
            matches.push(MarkerMatch {
                name,
                start: m.start(),
            });
        }
    }

    let (wide_ac, wide_names) = tool_marker_wide_automaton();
    for m in wide_ac.find_iter(buffer) {
        let name = wide_names[m.pattern().as_usize()];
        if !is_wide_marker_boundary_ok(buffer, m.start(), m.end() - m.start()) {
            continue;
        }
        table.record_tool_marker(name, base_address.saturating_add(m.start()));
        if matches.len() < MAX_MARKER_MATCHES_PER_CHUNK {
            matches.push(MarkerMatch {
                name,
                start: m.start(),
            });
        }
    }

    matches
}

/// Generic prefix scan. Every FFlag prefix starts with `D`, `F`, or `S`, so
/// we use `memchr3` to skip directly to candidate positions instead of
/// touching every byte. On random binary data this cuts the inner loop from
/// ~N iterations to ~N/256 — a single 16 MiB chunk of non-identifier bytes
/// becomes a handful of `pcmpeqb`/`pmovmskb` ops instead of 16 million
/// per-byte prefix-compare passes.
///
/// At each candidate position we still do: left-boundary, prefix match,
/// uppercase-body-start, body-length + contextual boundary checks —
/// identical semantics to the pre-memchr version.
/// Returns tuples of (offset_in_buffer, full_name, is_known_or_allowed).
fn scan_prefix_hits(buffer: &[u8]) -> Vec<(usize, String, bool)> {
    let mut out: Vec<(usize, String, bool)> = Vec::new();
    if buffer.is_empty() {
        return out;
    }
    let known = known_flag_set();

    let mut cursor = 0usize;
    while cursor < buffer.len() {
        let rel = match memchr::memchr3(b'D', b'F', b'S', &buffer[cursor..]) {
            Some(o) => o,
            None => break,
        };
        let i = cursor + rel;
        // Tentatively advance one byte; if we find a full identifier below we
        // jump past it to skip its interior.
        cursor = i + 1;

        // Left boundary: previous byte must not be an ident byte.
        if i > 0 && is_ident_byte(buffer[i - 1]) {
            continue;
        }

        let mut matched_prefix: Option<&'static str> = None;
        for &prefix in FLAG_PREFIXES {
            let pb = prefix.as_bytes();
            if i + pb.len() > buffer.len() {
                continue;
            }
            // Cheap first-byte check already passed (memchr3), but prefixes
            // share first letters so still need the full compare.
            if &buffer[i..i + pb.len()] == pb {
                matched_prefix = Some(prefix);
                break;
            }
        }
        let prefix = match matched_prefix {
            Some(p) => p,
            None => continue,
        };

        // Body must start with an uppercase ASCII letter (real flags are
        // camel-cased), followed by at least MIN_IDENT_BODY_LEN ident bytes.
        let body_start = i + prefix.len();
        if body_start >= buffer.len() {
            continue;
        }
        if !buffer[body_start].is_ascii_uppercase() {
            continue;
        }

        let mut j = body_start;
        while j < buffer.len() && j - body_start < MAX_IDENT_BODY_LEN && is_ident_byte(buffer[j]) {
            j += 1;
        }
        let body_len = j - body_start;
        if body_len < MIN_IDENT_BODY_LEN {
            continue;
        }

        let total_len = prefix.len() + body_len;
        if !is_contextual_match(buffer, i, total_len) {
            continue;
        }

        let name = match std::str::from_utf8(&buffer[i..j]) {
            Ok(s) => s.to_string(),
            Err(_) => continue,
        };

        let is_known = known.contains(name.as_str()) || is_allowed_flag(&name);
        out.push((i, name, is_known));
        if out.len() >= MAX_PREFIX_HITS_PER_CHUNK {
            break;
        }
        // Jump past the identifier so its interior isn't re-examined.
        cursor = j;
    }

    out
}

/// Cached Aho-Corasick automaton over the UTF-16LE encodings of every known
/// suspicious flag. Replaces the previous per-pattern linear scan which did
/// `N * patterns` byte compares (~278 passes over each chunk). A single AC
/// pass is O(N + matches) — for a 16 MiB chunk that's ~50 ms instead of
/// ~20 s on typical hardware.
///
/// The returned tuple keeps the parallel slice of `&'static` flag names
/// aligned with pattern indices so `Match::pattern()` → name is O(1).
fn known_wide_automaton() -> &'static (aho_corasick::AhoCorasick, Vec<&'static str>) {
    use std::sync::OnceLock;
    static CACHE: OnceLock<(aho_corasick::AhoCorasick, Vec<&'static str>)> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut names: Vec<&'static str> =
            Vec::with_capacity(CRITICAL_FLAGS.len() + HIGH_FLAGS.len() + MEDIUM_FLAGS.len());
        names.extend(CRITICAL_FLAGS.iter().copied());
        names.extend(HIGH_FLAGS.iter().copied());
        names.extend(MEDIUM_FLAGS.iter().copied());
        let patterns: Vec<Vec<u8>> = names.iter().map(|n| to_utf16le(n)).collect();
        let ac = aho_corasick::AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .build(&patterns)
            .expect("aho-corasick automaton build should not fail over static flag set");
        (ac, names)
    })
}

/// Scan a buffer for UTF-16LE occurrences of any known suspicious flag name
/// using the cached Aho-Corasick automaton. Targeted (against known lists)
/// rather than generic because UTF-16 noise generates unacceptable
/// false-positive rates otherwise.
fn scan_ascii_known(
    buffer: &[u8],
    base_address: usize,
    markers: &[MarkerMatch],
    table: &mut FlagHitTable,
) -> Vec<RuntimeStringHit> {
    let runtime_tracked = runtime_tracked_name_set();
    let mut runtime_hits = Vec::new();
    let (ac, names) = known_ascii_automaton();
    for m in ac.find_iter(buffer) {
        let start = m.start();
        let len = m.end() - start;
        if !is_boundary_ok(buffer, start, len) {
            continue;
        }
        let name = names[m.pattern().as_usize()];
        let address = base_address.saturating_add(start);
        let value = extract_adjacent_value_ascii(buffer, start + len);
        let context_summary = value
            .as_ref()
            .and_then(|_| injector_context_summary_near(markers, start));
        table.record_with_value(name, address, false, value, context_summary);
        if runtime_tracked.contains(name) && runtime_hits.len() < MAX_RUNTIME_STRING_HITS_PER_CHUNK
        {
            let hit = RuntimeStringHit {
                name,
                offset: start,
                address,
            };
            table.record_runtime_string_hit(hit);
            runtime_hits.push(hit);
        }
    }
    runtime_hits
}

/// Scan a buffer for UTF-16LE occurrences of any known suspicious flag name
/// using the cached Aho-Corasick automaton. Targeted (against known lists)
/// rather than generic because UTF-16 noise generates unacceptable
/// false-positive rates otherwise.
fn scan_wide_known(
    buffer: &[u8],
    base_address: usize,
    markers: &[MarkerMatch],
    table: &mut FlagHitTable,
) {
    let (ac, names) = known_wide_automaton();
    for m in ac.find_iter(buffer) {
        let start = m.start();
        let len = m.end() - start;
        if !is_wide_boundary_ok(buffer, start, len) {
            continue;
        }
        let name = names[m.pattern().as_usize()];
        let address = base_address.saturating_add(start);
        let value = extract_adjacent_value_wide(buffer, start + len);
        let context_summary = value
            .as_ref()
            .and_then(|_| injector_context_summary_near(markers, start));
        table.record_with_value(name, address, true, value, context_summary);
    }
}

fn read_u64_le_at(buffer: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let bytes = buffer.get(offset..end)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn read_usize_le_at(buffer: &[u8], offset: usize) -> Option<usize> {
    usize::try_from(read_u64_le_at(buffer, offset)?).ok()
}

fn record_runtime_node_if_valid(
    buffer: &[u8],
    base_address: usize,
    node_offset: usize,
    name: &'static str,
    expected_string_address: usize,
    table: &mut FlagHitTable,
) {
    let node_end = match node_offset.checked_add(RUNTIME_NODE_SIZE) {
        Some(end) if end <= buffer.len() => end,
        _ => return,
    };
    let node = &buffer[node_offset..node_end];
    let len = match read_u64_le_at(node, RUNTIME_NODE_LEN_OFFSET) {
        Some(len) => len as usize,
        None => return,
    };
    if len != name.len() || len > MAX_IDENT_BODY_LEN + 16 {
        return;
    }

    let cap = match read_u64_le_at(node, RUNTIME_NODE_CAP_OFFSET) {
        Some(cap) => cap,
        None => return,
    };
    let entry = match read_usize_le_at(node, RUNTIME_NODE_ENTRY_OFFSET) {
        Some(entry) if entry != 0 && (entry & 0x7) == 0 => entry,
        _ => return,
    };

    let string_address = if cap <= RUNTIME_INLINE_STRING_CAP {
        if len > RUNTIME_INLINE_STRING_CAP as usize {
            return;
        }
        let inline_end = RUNTIME_NODE_STRING_OFFSET + len;
        if node.get(RUNTIME_NODE_STRING_OFFSET..inline_end) != Some(name.as_bytes()) {
            return;
        }
        base_address.saturating_add(node_offset + RUNTIME_NODE_STRING_OFFSET)
    } else {
        let ptr = match read_usize_le_at(node, RUNTIME_NODE_STRING_OFFSET) {
            Some(ptr) => ptr,
            None => return,
        };
        if ptr != expected_string_address
            || cap < len as u64
            || cap > (MAX_IDENT_BODY_LEN + 32) as u64
        {
            return;
        }
        ptr
    };

    table.record_runtime_node_entry(RuntimeNodeEntryCandidate {
        name,
        node_address: base_address.saturating_add(node_offset),
        string_address,
        entry,
    });
}

fn scan_runtime_node_entries(
    buffer: &[u8],
    base_address: usize,
    runtime_hits: &[RuntimeStringHit],
    table: &mut FlagHitTable,
) {
    if runtime_hits.is_empty() {
        return;
    }

    for hit in runtime_hits
        .iter()
        .filter(|hit| hit.name.len() <= RUNTIME_INLINE_STRING_CAP as usize)
    {
        if hit.offset >= RUNTIME_NODE_STRING_OFFSET {
            record_runtime_node_if_valid(
                buffer,
                base_address,
                hit.offset - RUNTIME_NODE_STRING_OFFSET,
                hit.name,
                hit.address,
                table,
            );
        }
    }

    let string_names: HashMap<usize, &'static str> = runtime_hits
        .iter()
        .filter(|hit| hit.name.len() > RUNTIME_INLINE_STRING_CAP as usize)
        .map(|hit| (hit.address, hit.name))
        .collect();
    if string_names.is_empty() || buffer.len() < RUNTIME_NODE_STRING_OFFSET + 8 {
        return;
    }

    let aligned_start = (8usize.wrapping_sub(base_address & 0x7)) & 0x7;
    let mut offset = aligned_start;
    while offset + 8 <= buffer.len() {
        if let Some(ptr) = read_usize_le_at(buffer, offset) {
            if let Some(&name) = string_names.get(&ptr) {
                if offset >= RUNTIME_NODE_STRING_OFFSET {
                    record_runtime_node_if_valid(
                        buffer,
                        base_address,
                        offset - RUNTIME_NODE_STRING_OFFSET,
                        name,
                        ptr,
                        table,
                    );
                }
            }
        }
        offset = offset.saturating_add(8);
    }
}

fn scan_runtime_long_string_node_candidates(
    buffer: &[u8],
    base_address: usize,
    table: &mut FlagHitTable,
) {
    if buffer.len() < RUNTIME_NODE_SIZE {
        return;
    }
    let tracked_lengths = runtime_tracked_name_lengths();
    let aligned_start = (8usize.wrapping_sub(base_address & 0x7)) & 0x7;
    let mut node_offset = aligned_start;
    while node_offset + RUNTIME_NODE_SIZE <= buffer.len() {
        let len = match read_u64_le_at(buffer, node_offset + RUNTIME_NODE_LEN_OFFSET) {
            Some(len) => len as usize,
            None => break,
        };
        if tracked_lengths.contains(&len) {
            let cap = read_u64_le_at(buffer, node_offset + RUNTIME_NODE_CAP_OFFSET);
            let string_address = read_usize_le_at(buffer, node_offset + RUNTIME_NODE_STRING_OFFSET);
            let entry = read_usize_le_at(buffer, node_offset + RUNTIME_NODE_ENTRY_OFFSET);
            if let (Some(cap), Some(string_address), Some(entry)) = (cap, string_address, entry) {
                if cap > RUNTIME_INLINE_STRING_CAP
                    && cap >= len as u64
                    && cap <= (MAX_IDENT_BODY_LEN + 32) as u64
                    && string_address != 0
                    && (string_address & 0x7) == 0
                    && entry != 0
                    && (entry & 0x7) == 0
                {
                    table.record_runtime_long_string_node(RuntimeLongStringNodeCandidate {
                        node_address: base_address.saturating_add(node_offset),
                        string_address,
                        entry,
                        len,
                    });
                }
            }
        }
        node_offset = node_offset.saturating_add(8);
    }
}

fn resolved_runtime_node_entries(table: &FlagHitTable) -> Vec<RuntimeNodeEntryCandidate> {
    let mut out = table.runtime_node_entries.clone();
    let mut seen: HashSet<(&'static str, usize)> = out
        .iter()
        .map(|candidate| (candidate.name, candidate.entry))
        .collect();
    let strings_by_address: HashMap<usize, RuntimeStringHit> = table
        .runtime_string_hits
        .iter()
        .map(|hit| (hit.address, *hit))
        .collect();

    for candidate in &table.runtime_long_string_nodes {
        let Some(hit) = strings_by_address.get(&candidate.string_address) else {
            continue;
        };
        if hit.name.len() != candidate.len {
            continue;
        }
        let key = (hit.name, candidate.entry);
        if seen.insert(key) {
            out.push(RuntimeNodeEntryCandidate {
                name: hit.name,
                node_address: candidate.node_address,
                string_address: candidate.string_address,
                entry: candidate.entry,
            });
        }
    }

    out
}

fn to_utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// UTF-16LE boundary check: the wide char before/after must not be another
/// identifier code unit. For ASCII identifier chars in UTF-16LE, this means
/// the byte pair `(x, 0x00)` where `x` is ident-like.
fn is_wide_boundary_ok(buffer: &[u8], start: usize, len: usize) -> bool {
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    // Before: two bytes prior
    if start >= 2 {
        let lo = buffer[start - 2];
        let hi = buffer[start - 1];
        if hi == 0 && is_ident(lo) {
            return false;
        }
    }
    // After
    let after = start + len;
    if after + 1 < buffer.len() {
        let lo = buffer[after];
        let hi = buffer[after + 1];
        if hi == 0 && is_ident(lo) {
            return false;
        }
    }
    true
}

/// Core per-buffer scan. Combines generic prefix discovery (ASCII) + targeted
/// UTF-16LE search against known lists. Updates the shared hit table.
fn scan_buffer(buffer: &[u8], base_address: usize, table: &mut FlagHitTable) {
    for header in find_runtime_table_headers(buffer, base_address) {
        table.record_runtime_table_header(header);
    }
    scan_runtime_long_string_node_candidates(buffer, base_address, table);

    let markers = scan_tool_markers(buffer, base_address, table);
    // ASCII targeted scan — catches known suspicious names with and without
    // Roblox's standard FFlag prefixes. Collection is broad, verdicting is not.
    let runtime_hits = scan_ascii_known(buffer, base_address, &markers, table);
    scan_runtime_node_entries(buffer, base_address, &runtime_hits, table);

    // ASCII generic prefix scan — captures known AND unknown flags.
    for (offset, name, _is_known) in scan_prefix_hits(buffer) {
        if known_flag_set().contains(name.as_str()) {
            continue;
        }
        let address = base_address.saturating_add(offset);
        let match_end = offset + name.len();
        let value = extract_adjacent_value_ascii(buffer, match_end);
        let context_summary = value
            .as_ref()
            .and_then(|_| injector_context_summary_near(&markers, offset));
        table.record_with_value(&name, address, false, value, context_summary);
    }
    // UTF-16LE targeted scan for known names.
    scan_wide_known(buffer, base_address, &markers, table);
}

fn marker_summary(table: &FlagHitTable) -> String {
    if table.tool_markers.is_empty() {
        return "none".to_string();
    }
    let mut markers: Vec<(&&'static str, &ToolMarkerHit)> = table.tool_markers.iter().collect();
    markers.sort_by(|a, b| a.0.cmp(b.0));
    markers
        .into_iter()
        .take(8)
        .map(|(name, hit)| format!("{} x{} @0x{:X}", name, hit.count, hit.first_address))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Build scan findings from the aggregated hit table.
///
/// Bare flag names and plain `"FlagName": value` blobs stay informational:
/// vanilla Roblox keeps its remote flag configuration and internal registry in
/// heap, and those byte shapes look exactly like serialized overrides. The
/// memory scanner only raises a cheat verdict when a known suspicious flag has
/// an adjacent parsed value AND that value is near injector / offset-tool
/// provenance such as `fflags.json` + `address.json`, `LornoFix`, or
/// `WriteProcessMemory`. That catches the common runtime-injection artefact
/// without turning Roblox's own heap into false positives.
fn findings_from_table(table: &FlagHitTable) -> Vec<ScanFinding> {
    const SAMPLE_LIMIT: usize = 25;
    let mut out = Vec::new();
    if table.hits.is_empty() {
        return out;
    }

    let mut entries: Vec<(&String, &FlagHit)> = table.hits.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));

    let mut unique: usize = 0;
    let mut total_occurrences: u64 = 0;
    let mut seen_ascii = false;
    let mut seen_wide = false;
    let mut samples: Vec<String> = Vec::new();

    for &(name, hit) in &entries {
        // Allowlisted names don't enter the count at all — Roblox's own
        // September 2025 allowlist permits them in every configuration
        // path, so their presence in heap is explicitly sanctioned.
        if is_allowed_flag(name) {
            continue;
        }

        let mut verdict = get_flag_severity(name);
        let context_sample = hit
            .value_samples
            .iter()
            .find(|s| s.context_summary.is_some());
        if matches!(verdict, ScanVerdict::Clean)
            && get_flag_category(name).is_none()
            && context_sample.is_some()
        {
            verdict = ScanVerdict::Suspicious;
        }
        if matches!(verdict, ScanVerdict::Flagged | ScanVerdict::Suspicious) {
            if let Some(sample) = context_sample {
                let category = get_flag_category(name).unwrap_or("UNKNOWN");
                let desc = get_flag_description(name)
                    .map(|d| format!(" | {}", d))
                    .unwrap_or_default();
                let encoding = if sample.wide { "utf16" } else { "ascii" };
                let label = match verdict {
                    ScanVerdict::Flagged => "Critical runtime FFlag injection evidence",
                    ScanVerdict::Suspicious => "Suspicious runtime FFlag injection evidence",
                    ScanVerdict::Clean | ScanVerdict::Inconclusive => "Runtime FFlag evidence",
                };
                out.push(ScanFinding::new(
                    "memory_scanner",
                    verdict,
                    format!("{}: \"{}\" = {}", label, name, sample.value),
                    Some(format!(
                        "Address: 0x{:X} | Encoding: {} | Occurrences: {} | Category: {}{} | Context: value was within {} bytes of injector/offset-tool provenance | Observed markers: {}",
                        sample.address,
                        encoding,
                        hit.count,
                        category,
                        desc,
                        INJECTOR_CONTEXT_WINDOW_BYTES,
                        sample.context_summary.as_deref().unwrap_or("unknown")
                    )),
                ));
            }
        }

        unique += 1;
        total_occurrences = total_occurrences.saturating_add(hit.count as u64);
        seen_ascii |= hit.seen_ascii;
        seen_wide |= hit.seen_wide;
        if samples.len() < SAMPLE_LIMIT {
            samples.push(name.clone());
        }
    }

    if unique == 0 {
        return out;
    }

    let encoding = match (seen_ascii, seen_wide) {
        (true, true) => "ascii+utf16",
        (true, false) => "ascii",
        (false, true) => "utf16",
        (false, false) => "unknown",
    };
    let sample_line = if samples.is_empty() {
        String::new()
    } else {
        let truncation = if unique > SAMPLE_LIMIT {
            format!(" (+{} more)", unique - SAMPLE_LIMIT)
        } else {
            String::new()
        };
        format!(" | Samples: {}{}", samples.join(", "), truncation)
    };

    out.push(ScanFinding::new(
        "memory_scanner",
        ScanVerdict::Clean,
        format!(
            "{} non-allowlisted FFlag-shaped identifiers observed in Roblox heap. Bare names / plain values are baseline Roblox heap data; only nearby injector-context values affect the verdict.",
            unique
        ),
        Some(format!(
            "Unique names: {} | Total occurrences: {} | Encoding: {} | Injector/offset markers observed: {}{}",
            unique,
            total_occurrences,
            encoding,
            marker_summary(table),
            sample_line
        )),
    ));

    out
}

// ============================
// Windows implementation
// ============================
#[cfg(all(target_os = "windows", target_pointer_width = "64"))]
mod windows_impl {
    use super::*;
    use rayon::prelude::*;
    use std::ffi::c_void;
    use std::mem;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HMODULE, MAX_PATH};
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE,
        PAGE_WRITECOPY,
    };
    use windows_sys::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL,
        MODULEINFO,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    /// RAII wrapper for a Windows process HANDLE — ensures CloseHandle on all exit paths.
    pub(super) struct ScopedHandle(pub HANDLE);
    impl Drop for ScopedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    /// Longest candidate byte-length we need to preserve across chunk boundaries.
    /// Maximum plausible wide-string length dominates: (prefix + MAX_IDENT_BODY_LEN) * 2.
    fn chunk_overlap_bytes() -> usize {
        // Longest prefix is "DFString" / "SFString" at 8 chars.
        let max_name = 8 + MAX_IDENT_BODY_LEN;
        INJECTOR_CONTEXT_WINDOW_BYTES + (max_name * 2) + MAX_VALUE_CAPTURE_BYTES + 8
    }

    struct ReadCounters<'a> {
        bytes_scanned: &'a AtomicU64,
        regions_scanned: &'a AtomicUsize,
        read_failures: &'a AtomicUsize,
        read_failed_bytes: &'a AtomicU64,
        timed_out: &'a AtomicBool,
    }

    fn mark_region_scanned(counted_region: &mut bool, counters: &ReadCounters<'_>) {
        if !*counted_region {
            counters.regions_scanned.fetch_add(1, Ordering::Relaxed);
            *counted_region = true;
        }
    }

    fn try_read_and_scan(
        local: &mut FlagHitTable,
        scratch: &mut Vec<u8>,
        handle: HANDLE,
        addr: usize,
        size: usize,
        counters: &ReadCounters<'_>,
        counted_region: &mut bool,
    ) -> Option<usize> {
        scratch.resize(size, 0);
        let mut bytes_read: usize = 0;
        let read_ok = unsafe {
            ReadProcessMemory(
                handle,
                addr as *const c_void,
                scratch.as_mut_ptr() as *mut c_void,
                size,
                &mut bytes_read,
            )
        };
        if read_ok == 0 || bytes_read == 0 || bytes_read > size {
            return None;
        }

        counters
            .bytes_scanned
            .fetch_add(bytes_read as u64, Ordering::Relaxed);
        scan_buffer(&scratch[..bytes_read], addr, local);
        mark_region_scanned(counted_region, counters);

        // ReadProcessMemory should normally fail rather than report a short
        // successful read, but account for the tail defensively instead of
        // pretending it was covered.
        if bytes_read < size {
            counters.read_failures.fetch_add(1, Ordering::Relaxed);
            counters
                .read_failed_bytes
                .fetch_add((size - bytes_read) as u64, Ordering::Relaxed);
        }

        Some(bytes_read)
    }

    fn scan_span_adaptive(
        local: &mut FlagHitTable,
        scratch: &mut Vec<u8>,
        handle: HANDLE,
        addr: usize,
        size: usize,
        overlap: usize,
        counters: &ReadCounters<'_>,
        counted_region: &mut bool,
    ) -> u64 {
        if size == 0 || counters.timed_out.load(Ordering::Relaxed) {
            return 0;
        }
        if let Some(bytes_read) =
            try_read_and_scan(local, scratch, handle, addr, size, counters, counted_region)
        {
            return bytes_read as u64;
        }
        if size <= MIN_READ_CHUNK_BYTES {
            counters.read_failures.fetch_add(1, Ordering::Relaxed);
            counters
                .read_failed_bytes
                .fetch_add(size as u64, Ordering::Relaxed);
            return 0;
        }

        let split = if size > MIN_READ_CHUNK_BYTES * 2 {
            (size / 2)
                .max(MIN_READ_CHUNK_BYTES)
                .min(size - MIN_READ_CHUNK_BYTES)
        } else {
            size / 2
        };
        if split == 0 || split >= size {
            counters.read_failures.fetch_add(1, Ordering::Relaxed);
            counters
                .read_failed_bytes
                .fetch_add(size as u64, Ordering::Relaxed);
            return 0;
        }

        let split_overlap = if overlap > 0 && size > overlap.saturating_mul(4) {
            overlap.min(split / 2).min((size - split) / 2)
        } else {
            0
        };
        let right_start = split.saturating_sub(split_overlap);

        let left = scan_span_adaptive(
            local,
            scratch,
            handle,
            addr,
            split,
            overlap,
            counters,
            counted_region,
        );
        let right = if right_start < size && !counters.timed_out.load(Ordering::Relaxed) {
            scan_span_adaptive(
                local,
                scratch,
                handle,
                addr.saturating_add(right_start),
                size - right_start,
                overlap,
                counters,
                counted_region,
            )
        } else {
            0
        };

        left.saturating_add(right)
    }

    /// Read every chunk of a single committed region into `scratch` and feed
    /// it to `scan_buffer`, updating the worker-local `FlagHitTable` and the
    /// shared atomic counters. Failed large reads are subdivided so one raced
    /// page does not make the scanner skip an entire 16 MiB span.
    fn scan_region_into(
        local: &mut FlagHitTable,
        scratch: &mut Vec<u8>,
        handle: HANDLE,
        addr: usize,
        size: usize,
        overlap: usize,
        bytes_scanned: &AtomicU64,
        regions_scanned: &AtomicUsize,
        read_failures: &AtomicUsize,
        read_failed_bytes: &AtomicU64,
        timed_out: &AtomicBool,
    ) {
        if scratch.capacity() < MAX_CHUNK_BYTES {
            scratch.reserve(MAX_CHUNK_BYTES - scratch.capacity());
        }
        let counters = ReadCounters {
            bytes_scanned,
            regions_scanned,
            read_failures,
            read_failed_bytes,
            timed_out,
        };
        let mut counted_region = false;
        let mut offset = 0usize;
        while offset < size {
            if timed_out.load(Ordering::Relaxed) {
                return;
            }
            let this_chunk = (size - offset).min(MAX_CHUNK_BYTES);
            let _ = scan_span_adaptive(
                local,
                scratch,
                handle,
                addr.saturating_add(offset),
                this_chunk,
                overlap,
                &counters,
                &mut counted_region,
            );
            let advance = if this_chunk > overlap {
                this_chunk - overlap
            } else {
                this_chunk
            };
            offset = offset.saturating_add(advance);
        }
    }

    #[derive(Clone, Copy)]
    struct RuntimeRegistryCandidate {
        singleton: usize,
        slot: Option<usize>,
        table: usize,
        source: &'static str,
    }

    #[derive(Clone)]
    struct RuntimeModuleInfo {
        base: usize,
        size: usize,
        path: Option<String>,
    }

    const RUNTIME_VALUE_PTR_OFFSET: usize = 0xC0;
    const RUNTIME_MAX_CHAIN_STEPS: usize = 128;
    const RUNTIME_PATTERN_SCAN_CHUNK: usize = 1024 * 1024;
    const RUNTIME_PATTERN_SCAN_CAP: usize = 256 * 1024 * 1024;
    const RUNTIME_REGISTRY_PROBE_NAMES: &[&str] = &[
        "DFIntS2PhysicsSenderRate",
        "DFFlagDebugDrawBroadPhaseAABBs",
        "FIntCameraFarZPlane",
        "DFIntMinClientSimulationRadius",
        "DFIntMaxClientSimulationRadius",
        "FFlagDebugUseCustomSimRadius",
    ];

    fn read_process_exact(handle: HANDLE, addr: usize, out: &mut [u8]) -> bool {
        let mut bytes_read: usize = 0;
        let ok = unsafe {
            ReadProcessMemory(
                handle,
                addr as *const c_void,
                out.as_mut_ptr() as *mut c_void,
                out.len(),
                &mut bytes_read,
            )
        };
        ok != 0 && bytes_read == out.len()
    }

    fn read_process_u64(handle: HANDLE, addr: usize) -> Option<u64> {
        let mut buf = [0u8; 8];
        read_process_exact(handle, addr, &mut buf).then(|| u64::from_le_bytes(buf))
    }

    fn read_process_i32_bytes(handle: HANDLE, addr: usize) -> Option<[u8; 4]> {
        let mut buf = [0u8; 4];
        read_process_exact(handle, addr, &mut buf).then_some(buf)
    }

    fn main_module_info_windows(handle: HANDLE) -> Option<(usize, usize)> {
        let mut modules: [HMODULE; 1] = [std::ptr::null_mut(); 1];
        let mut needed = 0u32;
        let ok = unsafe {
            EnumProcessModulesEx(
                handle,
                modules.as_mut_ptr(),
                mem::size_of_val(&modules) as u32,
                &mut needed,
                LIST_MODULES_ALL,
            )
        };
        if ok == 0 || modules[0].is_null() {
            return None;
        }

        let mut info: MODULEINFO = unsafe { mem::zeroed() };
        let ok = unsafe {
            GetModuleInformation(
                handle,
                modules[0],
                &mut info,
                mem::size_of::<MODULEINFO>() as u32,
            )
        };
        if ok == 0 || info.lpBaseOfDll.is_null() || info.SizeOfImage == 0 {
            return None;
        }
        Some((info.lpBaseOfDll as usize, info.SizeOfImage as usize))
    }

    fn module_path_windows(handle: HANDLE, hmod: HMODULE) -> Option<String> {
        let mut buf: Vec<u16> = vec![0; MAX_PATH as usize];
        let mut len =
            unsafe { GetModuleFileNameExW(handle, hmod, buf.as_mut_ptr(), buf.len() as u32) };
        while len != 0 && (len as usize) == buf.len() {
            let new_size = buf.len().saturating_mul(2).min(65_536);
            if new_size <= buf.len() {
                break;
            }
            buf.resize(new_size, 0);
            len = unsafe { GetModuleFileNameExW(handle, hmod, buf.as_mut_ptr(), buf.len() as u32) };
        }
        (len != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }

    fn runtime_modules_windows(handle: HANDLE) -> Vec<RuntimeModuleInfo> {
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
            return main_module_info_windows(handle)
                .map(|(base, size)| {
                    vec![RuntimeModuleInfo {
                        base,
                        size,
                        path: None,
                    }]
                })
                .unwrap_or_default();
        }

        let count = needed as usize / mem::size_of::<HMODULE>();
        if count > modules.len() {
            modules.resize(count.min(256 * 1024), std::ptr::null_mut());
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
                return main_module_info_windows(handle)
                    .map(|(base, size)| {
                        vec![RuntimeModuleInfo {
                            base,
                            size,
                            path: None,
                        }]
                    })
                    .unwrap_or_default();
            }
        }

        let count = (needed as usize / mem::size_of::<HMODULE>()).min(modules.len());
        let mut out = Vec::new();
        for &hmod in modules.iter().take(count) {
            if hmod.is_null() {
                continue;
            }
            let mut info: MODULEINFO = unsafe { mem::zeroed() };
            let ok = unsafe {
                GetModuleInformation(handle, hmod, &mut info, mem::size_of::<MODULEINFO>() as u32)
            };
            if ok == 0 || info.lpBaseOfDll.is_null() || info.SizeOfImage == 0 {
                continue;
            }
            out.push(RuntimeModuleInfo {
                base: info.lpBaseOfDll as usize,
                size: info.SizeOfImage as usize,
                path: module_path_windows(handle, hmod),
            });
        }
        out
    }

    fn runtime_module_should_scan(module: &RuntimeModuleInfo, index: usize) -> bool {
        index == 0
            || module
                .path
                .as_deref()
                .map(|path| path.to_lowercase().contains("roblox"))
                .unwrap_or(false)
    }

    fn push_runtime_registry_candidate(
        candidates: &mut Vec<RuntimeRegistryCandidate>,
        singleton: usize,
        slot: Option<usize>,
        source: &'static str,
    ) {
        if candidates
            .iter()
            .any(|candidate| candidate.singleton == singleton)
        {
            return;
        }
        candidates.push(RuntimeRegistryCandidate {
            singleton,
            slot,
            table: singleton.saturating_add(RUNTIME_TABLE_OFFSET_FROM_SINGLETON),
            source,
        });
    }

    fn push_runtime_table_header_candidate(
        candidates: &mut Vec<RuntimeRegistryCandidate>,
        table: usize,
        source: &'static str,
    ) {
        if table < RUNTIME_TABLE_OFFSET_FROM_SINGLETON {
            return;
        }
        push_runtime_registry_candidate(
            candidates,
            table - RUNTIME_TABLE_OFFSET_FROM_SINGLETON,
            None,
            source,
        );
    }

    fn runtime_registry_has_probe_flag(handle: HANDLE, singleton: usize) -> bool {
        RUNTIME_REGISTRY_PROBE_NAMES
            .iter()
            .any(|name| lookup_runtime_flag_entry(handle, singleton, name).is_some())
    }

    fn runtime_registry_has_tracked_flag(handle: HANDLE, singleton: usize) -> bool {
        let mut seen = std::collections::HashSet::new();
        RUNTIME_OVERRIDE_RULES
            .iter()
            .filter_map(|rule| seen.insert(rule.name).then_some(rule.name))
            .any(|name| lookup_runtime_flag_entry(handle, singleton, name).is_some())
    }

    fn runtime_candidates_have_probe(
        handle: HANDLE,
        candidates: &[RuntimeRegistryCandidate],
    ) -> bool {
        candidates
            .iter()
            .any(|candidate| runtime_registry_has_probe_flag(handle, candidate.singleton))
    }

    fn discover_runtime_registry_candidates_in_module(
        handle: HANDLE,
        module: &RuntimeModuleInfo,
        candidates: &mut Vec<RuntimeRegistryCandidate>,
    ) {
        let scan_size = module.size.min(RUNTIME_PATTERN_SCAN_CAP);
        let overlap = RUNTIME_SINGLETON_ACCESSOR_PATTERN
            .len()
            .saturating_sub(1)
            .max(RUNTIME_TABLE_SIZE.saturating_sub(1));
        let mut scratch = vec![0u8; RUNTIME_PATTERN_SCAN_CHUNK + overlap];
        let mut offset = 0usize;

        while offset < scan_size {
            let size = (scan_size - offset).min(RUNTIME_PATTERN_SCAN_CHUNK + overlap);
            let addr = module.base.saturating_add(offset);
            if read_process_exact(handle, addr, &mut scratch[..size]) {
                for slot in find_runtime_singleton_slots(&scratch[..size], addr) {
                    if let Some(singleton) = read_process_u64(handle, slot)
                        .and_then(|p| usize::try_from(p).ok())
                        .filter(|&p| p != 0 && runtime_table_header_looks_valid(handle, p))
                    {
                        push_runtime_registry_candidate(
                            candidates,
                            singleton,
                            Some(slot),
                            "RIP-relative singleton load",
                        );
                    }
                }

                for table_candidate in find_runtime_table_headers(&scratch[..size], addr) {
                    let table = table_candidate.address;
                    if table < RUNTIME_TABLE_OFFSET_FROM_SINGLETON {
                        continue;
                    }
                    let singleton = table - RUNTIME_TABLE_OFFSET_FROM_SINGLETON;
                    if runtime_table_header_looks_valid(handle, singleton)
                        && runtime_registry_has_tracked_flag(handle, singleton)
                    {
                        push_runtime_registry_candidate(
                            candidates,
                            singleton,
                            None,
                            "registry table header scan",
                        );
                    }
                }
            }
            let advance = RUNTIME_PATTERN_SCAN_CHUNK.min(scan_size - offset);
            if advance == 0 {
                break;
            }
            offset = offset.saturating_add(advance);
        }
    }

    fn discover_runtime_registry_candidates(
        handle: HANDLE,
        heap_table_headers: &[RuntimeTableHeaderCandidate],
    ) -> Vec<RuntimeRegistryCandidate> {
        let modules = runtime_modules_windows(handle);
        let mut candidates = Vec::new();

        for (index, module) in modules.iter().enumerate() {
            if runtime_module_should_scan(module, index) {
                discover_runtime_registry_candidates_in_module(handle, module, &mut candidates);
                if runtime_candidates_have_probe(handle, &candidates) {
                    break;
                }
            }
        }

        if !runtime_candidates_have_probe(handle, &candidates) {
            for (index, module) in modules.iter().enumerate() {
                if !runtime_module_should_scan(module, index) {
                    discover_runtime_registry_candidates_in_module(handle, module, &mut candidates);
                    if runtime_candidates_have_probe(handle, &candidates) {
                        break;
                    }
                }
                if index >= 64 {
                    break;
                }
            }
        }

        if !runtime_candidates_have_probe(handle, &candidates) {
            let mut heap_table_headers = heap_table_headers.to_vec();
            heap_table_headers.sort_by(|a, b| b.mask.cmp(&a.mask));
            for table_candidate in heap_table_headers {
                let table = table_candidate.address;
                if table < RUNTIME_TABLE_OFFSET_FROM_SINGLETON {
                    continue;
                }
                let singleton = table - RUNTIME_TABLE_OFFSET_FROM_SINGLETON;
                if runtime_table_header_looks_valid(handle, singleton)
                    && runtime_registry_has_tracked_flag(handle, singleton)
                {
                    push_runtime_table_header_candidate(
                        &mut candidates,
                        table,
                        "heap registry table header scan",
                    );
                    break;
                }
            }
        }

        candidates
    }

    fn runtime_table_header_looks_valid(handle: HANDLE, singleton: usize) -> bool {
        let mut table = [0u8; RUNTIME_TABLE_SIZE];
        if !read_process_exact(
            handle,
            singleton.saturating_add(RUNTIME_TABLE_OFFSET_FROM_SINGLETON),
            &mut table,
        ) {
            return false;
        }

        runtime_table_header_bytes_look_plausible(&table)
    }

    fn remote_node_string_matches(
        handle: HANDLE,
        node_addr: usize,
        node: &[u8; RUNTIME_NODE_SIZE],
        expected: &str,
    ) -> bool {
        let len = u64::from_le_bytes(node[0x20..0x28].try_into().unwrap()) as usize;
        if len != expected.len() || len > MAX_IDENT_BODY_LEN + 16 {
            return false;
        }

        let cap = u64::from_le_bytes(node[0x28..0x30].try_into().unwrap());
        let mut actual = vec![0u8; len];
        if cap <= 0x0f {
            if len > 0x0f {
                return false;
            }
            actual.copy_from_slice(&node[0x10..0x10 + len]);
        } else {
            let ptr = u64::from_le_bytes(node[0x10..0x18].try_into().unwrap()) as usize;
            if ptr == 0 || !read_process_exact(handle, ptr, &mut actual) {
                return false;
            }
        }

        actual == expected.as_bytes()
            || (len <= RUNTIME_NODE_SIZE - 0x10
                && node_addr != 0
                && &node[0x10..0x10 + len] == expected.as_bytes())
    }

    fn lookup_runtime_flag_entry(
        handle: HANDLE,
        singleton: usize,
        flag_name: &str,
    ) -> Option<usize> {
        let mut table = [0u8; RUNTIME_TABLE_SIZE];
        read_process_exact(
            handle,
            singleton.saturating_add(RUNTIME_TABLE_OFFSET_FROM_SINGLETON),
            &mut table,
        )
        .then_some(())?;

        let sentinel = u64::from_le_bytes(table[0x00..0x08].try_into().unwrap()) as usize;
        let buckets = u64::from_le_bytes(table[0x10..0x18].try_into().unwrap()) as usize;
        let mask = u64::from_le_bytes(table[0x28..0x30].try_into().unwrap());
        if buckets == 0 || mask == 0 || mask > RUNTIME_TABLE_MAX_MASK {
            return None;
        }

        let bucket_index = fnv1a64(flag_name.as_bytes()) & mask;
        let bucket_addr = buckets.checked_add((bucket_index as usize).checked_mul(16)?)?;
        let mut bucket = [0u8; 16];
        read_process_exact(handle, bucket_addr, &mut bucket).then_some(())?;

        let first = u64::from_le_bytes(bucket[0x00..0x08].try_into().unwrap()) as usize;
        let second = u64::from_le_bytes(bucket[0x08..0x10].try_into().unwrap()) as usize;
        let orders = [(second, first), (first, second)];

        for (mut current, chain_end) in orders {
            if current == 0 || current == sentinel {
                continue;
            }

            for _ in 0..RUNTIME_MAX_CHAIN_STEPS {
                let mut node = [0u8; RUNTIME_NODE_SIZE];
                if !read_process_exact(handle, current, &mut node) {
                    break;
                }

                if remote_node_string_matches(handle, current, &node, flag_name) {
                    let entry = u64::from_le_bytes(node[0x30..0x38].try_into().unwrap()) as usize;
                    return (entry != 0).then_some(entry);
                }

                if current == chain_end {
                    break;
                }
                let next = u64::from_le_bytes(node[0x08..0x10].try_into().unwrap()) as usize;
                if next == 0 || next == current {
                    break;
                }
                current = next;
            }
        }

        None
    }

    fn inspect_runtime_fflag_registry(
        handle: HANDLE,
        pid: u32,
        heap_table_headers: &[RuntimeTableHeaderCandidate],
        heap_table_header_matches: usize,
    ) -> Vec<ScanFinding> {
        let candidates = discover_runtime_registry_candidates(handle, heap_table_headers);
        let heap_table_header_summary = format!(
            "{}/{} kept",
            heap_table_headers.len(),
            heap_table_header_matches
        );
        if candidates.is_empty() {
            return vec![ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Inconclusive,
                "Live FastFlag registry could not be resolved",
                Some(format!(
                    "PID: {} | Scanned Roblox image modules for strict accessors/Lorno-style RIP-relative singleton loads and {} heap registry-table header candidates, but no validated FastFlag table was found",
                    pid,
                    heap_table_header_summary
                )),
            )];
        }

        let mut findings = Vec::new();
        let mut inspected = 0usize;
        for candidate in &candidates {
            for &rule in RUNTIME_OVERRIDE_RULES {
                let entry = match lookup_runtime_flag_entry(handle, candidate.singleton, rule.name)
                {
                    Some(entry) => entry,
                    None => continue,
                };
                inspected += 1;
                let value_ptr = match read_process_u64(
                    handle,
                    entry.saturating_add(RUNTIME_VALUE_PTR_OFFSET),
                ) {
                    Some(ptr) if ptr != 0 => ptr as usize,
                    _ => continue,
                };
                let raw_value = match read_process_i32_bytes(handle, value_ptr) {
                    Some(raw) => raw,
                    None => continue,
                };
                if !runtime_rule_matches_observed(rule, raw_value) {
                    continue;
                }

                let verdict = get_flag_severity(rule.name);
                let label = match verdict {
                    ScanVerdict::Flagged => "Critical live FastFlag registry override",
                    ScanVerdict::Suspicious => "Suspicious live FastFlag registry override",
                    ScanVerdict::Clean | ScanVerdict::Inconclusive => {
                        "Live FastFlag registry override"
                    }
                };
                findings.push(ScanFinding::new(
                    "memory_scanner",
                    verdict,
                    format!(
                        "{}: \"{}\" = {}",
                        label,
                        rule.name,
                        runtime_value_label(rule.value)
                    ),
                    Some({
                        let origin = candidate
                            .slot
                            .map(|slot| format!("{} at slot 0x{:X}", candidate.source, slot))
                            .unwrap_or_else(|| {
                                format!("{} at table 0x{:X}", candidate.source, candidate.table)
                            });
                        format!(
                            "PID: {} | Singleton: 0x{:X} via {} | Registry entry: 0x{:X} | Value address: 0x{:X} | Detection: resolved Roblox FastFlag hash table with FNV-1a and read the live value storage used by memory injectors",
                            pid, candidate.singleton, origin, entry, value_ptr
                        )
                    }),
                ));
            }
        }

        if findings.is_empty() && inspected > 0 {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Clean,
                "Live FastFlag registry inspected; no curated injected values observed",
                Some(format!(
                    "PID: {} | Singleton candidates: {} | Heap table header candidates: {} | Registry entries read: {}",
                    pid,
                    candidates.len(),
                    heap_table_header_summary,
                    inspected
                )),
            ));
        } else if findings.is_empty() {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Inconclusive,
                "Live FastFlag registry candidate found, but tracked entries could not be read",
                Some(format!(
                    "PID: {} | Singleton candidates: {} | Heap table header candidates: {} | Detection reached registry-like memory, but no probe or curated flag entries were readable",
                    pid,
                    candidates.len(),
                    heap_table_header_summary
                )),
            ));
        }

        findings
    }

    fn inspect_runtime_node_entries(
        handle: HANDLE,
        pid: u32,
        node_entries: &[RuntimeNodeEntryCandidate],
        node_entry_matches: usize,
    ) -> Vec<ScanFinding> {
        let node_entry_summary = format!("{}/{} kept", node_entries.len(), node_entry_matches);
        let mut findings = Vec::new();

        for candidate in node_entries {
            let value_ptr = match read_process_u64(
                handle,
                candidate.entry.saturating_add(RUNTIME_VALUE_PTR_OFFSET),
            ) {
                Some(ptr) if ptr != 0 => ptr as usize,
                _ => continue,
            };
            let raw_value = match read_process_i32_bytes(handle, value_ptr) {
                Some(raw) => raw,
                None => continue,
            };

            for &rule in RUNTIME_OVERRIDE_RULES
                .iter()
                .filter(|rule| rule.name == candidate.name)
            {
                if !runtime_rule_matches_observed(rule, raw_value) {
                    continue;
                }

                let verdict = get_flag_severity(rule.name);
                let label = match verdict {
                    ScanVerdict::Flagged => "Critical live FastFlag registry override",
                    ScanVerdict::Suspicious => "Suspicious live FastFlag registry override",
                    ScanVerdict::Clean | ScanVerdict::Inconclusive => {
                        "Live FastFlag registry override"
                    }
                };
                findings.push(ScanFinding::new(
                    "memory_scanner",
                    verdict,
                    format!(
                        "{}: \"{}\" = {}",
                        label,
                        rule.name,
                        runtime_value_label(rule.value)
                    ),
                    Some(format!(
                        "PID: {} | Registry node: 0x{:X} | Flag string: 0x{:X} | Registry entry: 0x{:X} | Value address: 0x{:X} | Node candidates: {} | Detection: resolved Roblox FastFlag node storage and read the live value storage used by memory injectors",
                        pid,
                        candidate.node_address,
                        candidate.string_address,
                        candidate.entry,
                        value_ptr,
                        node_entry_summary
                    )),
                ));
                break;
            }
        }

        findings
    }

    pub(super) async fn scan_windows(reporter: ScanProgress) -> Vec<ScanFinding> {
        let proc = match find_roblox_process() {
            Some(p) => p,
            None => {
                return vec![ScanFinding::new(
                    "memory_scanner",
                    ScanVerdict::Clean,
                    "Roblox process not found - memory scan skipped",
                    None,
                )];
            }
        };

        let pid = proc.pid;

        // If the Roblox process's exe path doesn't match a known install root
        // we can't vouch for it — but we also can't hard-Flag the user for
        // having installed Roblox in an unusual location (OneDrive-redirected
        // LocalAppData, portable D:\ install, Sober/Rokstrap, custom Bloxstrap
        // root, …). Emit an Inconclusive note and continue the scan — any
        // real decoy will still be caught by the memory / module checks below
        // because a blank binary has no Roblox strings in heap.
        let mut findings: Vec<ScanFinding> = Vec::new();
        if !proc.path_looks_trusted {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Inconclusive,
                "Roblox-named process has an unrecognized executable path — proceeding with memory scan but cannot attest install integrity",
                Some(format!(
                    "PID: {} | Path: {}",
                    pid,
                    proc.exe_path.as_deref().unwrap_or("<unknown>")
                )),
            ));
        }

        let raw_handle: HANDLE =
            unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid) };
        if raw_handle.is_null() {
            // Non-admin / PPL-protected / AV-hooked processes routinely deny
            // PROCESS_VM_READ. This is expected environmental behavior on
            // modern Windows, not evidence of cheating. Inconclusive lets the
            // operator know coverage was zero without accusing the player.
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Inconclusive,
                "Memory scan unavailable: insufficient permissions to read Roblox process (try running as Administrator)",
                Some(format!("PID: {}", pid)),
            ));
            return findings;
        }
        let handle = ScopedHandle(raw_handle);
        let scan_started = std::time::Instant::now();
        let timed_out = Arc::new(AtomicBool::new(false));

        // (1) Enumerate loaded modules, flag any outside trusted paths.
        findings.extend(scan_modules_windows(handle.0, pid));

        // ---- Phase A: enumerate regions (sequential, metadata only). ----
        // VirtualQueryEx is a fast kernel call that just returns region info;
        // the heavy work is the ReadProcessMemory in phase B. Splitting the
        // two lets us fan phase B across rayon workers without serializing
        // the enum loop.
        let mut regions_to_scan: Vec<(usize, usize)> = Vec::new();
        let mut regions_walked = 0usize;
        let mut truncated_regions = 0usize;
        let mut intended_scan_bytes = 0u64;
        let mut truncated_bytes = 0u64;
        let mut scan_completed = false;

        let overlap = chunk_overlap_bytes();

        {
            let mut address: usize = 0;
            let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
            let mem_info_size = mem::size_of::<MEMORY_BASIC_INFORMATION>();

            loop {
                if scan_started.elapsed() >= MAX_SCAN_DURATION {
                    timed_out.store(true, Ordering::Relaxed);
                    break;
                }
                if regions_walked >= MAX_REGIONS_WALKED {
                    break;
                }
                let result = unsafe {
                    VirtualQueryEx(
                        handle.0,
                        address as *const c_void,
                        &mut mem_info,
                        mem_info_size,
                    )
                };
                if result == 0 {
                    scan_completed = true;
                    break;
                }
                regions_walked += 1;

                let region_size = mem_info.RegionSize;
                let protect = mem_info.Protect;
                let state = mem_info.State;
                let region_type = mem_info.Type;

                let is_guard = (protect & PAGE_GUARD) != 0;
                let base_protect = protect & 0xFF;

                if state == MEM_COMMIT && region_size > 0 && !is_guard {
                    let is_readable = matches!(
                        base_protect,
                        PAGE_READONLY
                            | PAGE_READWRITE
                            | PAGE_WRITECOPY
                            | PAGE_EXECUTE_READ
                            | PAGE_EXECUTE_READWRITE
                            | PAGE_EXECUTE_WRITECOPY
                    );

                    // Only scan heap/private/mapped regions for strings.
                    // MEM_IMAGE (file-backed .text/.rdata) contains every
                    // flag name as a literal on a vanilla client, producing
                    // false positives we can't disambiguate for the ASCII
                    // scan.
                    let is_image = region_type == MEM_IMAGE;
                    if is_readable && !is_image {
                        let effective_size = region_size.min(ABS_REGION_CAP);
                        intended_scan_bytes =
                            intended_scan_bytes.saturating_add(region_size as u64);
                        if effective_size < region_size {
                            truncated_regions += 1;
                            truncated_bytes = truncated_bytes
                                .saturating_add((region_size - effective_size) as u64);
                        }
                        regions_to_scan.push((address, effective_size));
                    }
                }

                if region_size == 0 {
                    break;
                }
                let next = address.wrapping_add(region_size);
                if next <= address {
                    scan_completed = true;
                    break;
                }
                address = next;
            }
        }

        // ---- Phase B: parallel region scan. ----
        // Each rayon worker owns a reusable scratch buffer and a local
        // FlagHitTable; tables are merged at the end via `.reduce`.
        let bytes_scanned = Arc::new(AtomicU64::new(0));
        let regions_scanned = Arc::new(AtomicUsize::new(0));
        let read_failures = Arc::new(AtomicUsize::new(0));
        let read_failed_bytes = Arc::new(AtomicU64::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));

        // Watchdog + heartbeat: a single thread that both emits periodic
        // progress events and flips the shared `timed_out` flag when the
        // wall-clock cap is hit. Workers poll `timed_out` between chunks,
        // giving a ~1× chunk worst-case abort latency (~500ms on modern HW).
        let hb_bytes = bytes_scanned.clone();
        let hb_regions = regions_scanned.clone();
        let hb_timeout = timed_out.clone();
        let hb_shutdown = shutdown.clone();
        let hb_reporter = reporter.clone();
        let hb_scan_started = scan_started;
        let hb_thread = std::thread::spawn(move || {
            let interval = std::time::Duration::from_millis(400);
            loop {
                std::thread::park_timeout(interval);
                if hb_scan_started.elapsed() >= MAX_SCAN_DURATION {
                    hb_timeout.store(true, Ordering::Relaxed);
                    break;
                }
                if hb_shutdown.load(Ordering::Relaxed) {
                    break;
                }
                hb_reporter.heartbeat(
                    "memory_scanner",
                    hb_regions.load(Ordering::Relaxed),
                    hb_bytes.load(Ordering::Relaxed),
                );
            }
        });

        // Pass the HANDLE as a `usize` bit-pattern across thread boundaries.
        // `HANDLE` is `*mut c_void`, which is neither `Send` nor `Sync`, and
        // rayon's closure must be both. A wrapper struct with
        // `unsafe impl Sync` doesn't help here because Rust's disjoint-field
        // capture rules make the closure capture `&*mut c_void` directly
        // rather than `&Wrapper`. `usize` is unconditionally `Send + Sync`
        // and round-trips losslessly back to `HANDLE` inside the closure.
        // ReadProcessMemory is documented as safe to call concurrently on
        // the same handle, and `ScopedHandle` only closes after this block.
        let handle_usize = handle.0 as usize;
        let table = regions_to_scan
            .par_iter()
            .fold(
                || {
                    (
                        FlagHitTable::default(),
                        Vec::<u8>::with_capacity(MAX_CHUNK_BYTES),
                    )
                },
                |(mut local, mut scratch), &(addr, size)| {
                    if !timed_out.load(Ordering::Relaxed) {
                        scan_region_into(
                            &mut local,
                            &mut scratch,
                            handle_usize as HANDLE,
                            addr,
                            size,
                            overlap,
                            &bytes_scanned,
                            &regions_scanned,
                            &read_failures,
                            &read_failed_bytes,
                            &timed_out,
                        );
                    }
                    (local, scratch)
                },
            )
            .map(|(t, _)| t)
            .reduce(FlagHitTable::default, |mut a, b| {
                a.merge(b);
                a
            });

        if scan_started.elapsed() >= MAX_SCAN_DURATION {
            timed_out.store(true, Ordering::Relaxed);
        }

        // Stop the heartbeat thread. `unpark` wakes it immediately so we
        // don't pay up to 400ms of sleep latency at the end of every scan.
        shutdown.store(true, Ordering::Relaxed);
        hb_thread.thread().unpark();
        let _ = hb_thread.join();

        let bytes_scanned_final = bytes_scanned.load(Ordering::Relaxed);
        let regions_scanned_final = regions_scanned.load(Ordering::Relaxed);
        let read_failures_final = read_failures.load(Ordering::Relaxed);
        let read_failed_bytes_final = read_failed_bytes.load(Ordering::Relaxed);
        let timed_out_final = timed_out.load(Ordering::Relaxed);
        // Shadow the names the legacy reporting block below used, so the
        // diff between old and new is minimal.
        let bytes_scanned = bytes_scanned_final;
        let regions_scanned = regions_scanned_final;
        let read_failures = read_failures_final;
        let read_failed_bytes = read_failed_bytes_final;
        let timed_out = timed_out_final;
        let coverage = MemoryCoverage {
            intended_bytes: intended_scan_bytes,
            bytes_scanned,
            regions_scanned,
            truncated_regions,
            truncated_bytes,
            read_failures,
            read_failed_bytes,
        };
        let coverage_details = coverage.details();
        let no_successful_memory_reads = coverage.no_successful_reads();
        let material_coverage_gap = coverage.material_gap();

        // Emit flag findings.
        findings.extend(findings_from_table(&table));
        let registry_findings = inspect_runtime_fflag_registry(
            handle.0,
            pid,
            &table.runtime_table_headers,
            table.runtime_table_header_matches,
        );
        let runtime_node_entries = resolved_runtime_node_entries(&table);
        let node_findings = inspect_runtime_node_entries(
            handle.0,
            pid,
            &runtime_node_entries,
            table
                .runtime_node_entry_matches
                .saturating_add(table.runtime_long_string_node_matches),
        );
        let mut runtime_elevated = false;
        let mut runtime_non_elevated = Vec::new();
        let mut seen_runtime_descriptions = HashSet::new();
        for finding in registry_findings.into_iter().chain(node_findings) {
            if matches!(
                finding.verdict,
                ScanVerdict::Flagged | ScanVerdict::Suspicious
            ) {
                runtime_elevated = true;
                if seen_runtime_descriptions.insert(finding.description.clone()) {
                    findings.push(finding);
                }
            } else {
                runtime_non_elevated.push(finding);
            }
        }
        if !runtime_elevated {
            findings.extend(runtime_non_elevated);
        }

        // Honest summary. Environmental / coverage failures are
        // Inconclusive, not Suspicious — slow disks, large processes, and
        // truncated kernel enums are not evidence of cheating.
        if timed_out {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Inconclusive,
                format!(
                    "Memory scan aborted after {}s wall-clock cap — cannot attest clean state",
                    MAX_SCAN_DURATION.as_secs()
                ),
                Some(format!(
                    "PID: {}, regions_walked: {}, regions_scanned: {}, bytes_scanned: {} | {}",
                    pid, regions_walked, regions_scanned, bytes_scanned, coverage_details
                )),
            ));
        } else if !scan_completed {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Inconclusive,
                "Memory scan incomplete: region enumeration terminated early — cannot attest clean state",
                Some(format!(
                    "PID: {}, regions_walked: {}, regions_scanned: {}, bytes_scanned: {} | {}",
                    pid, regions_walked, regions_scanned, bytes_scanned, coverage_details
                )),
            ));
        } else if no_successful_memory_reads {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Inconclusive,
                "Memory scan incomplete: no readable Roblox memory bytes could be read",
                Some(format!(
                    "PID: {}, regions_walked: {}, regions_queued: {} | {}",
                    pid,
                    regions_walked,
                    regions_to_scan.len(),
                    coverage_details
                )),
            ));
        } else if regions_scanned == 0 {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Inconclusive,
                "Memory scan incomplete: no readable Roblox memory regions were scanned",
                Some(format!(
                    "PID: {}, regions_walked: {}, regions_queued: {} | {}",
                    pid,
                    regions_walked,
                    regions_to_scan.len(),
                    coverage_details
                )),
            ));
        } else if material_coverage_gap {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Inconclusive,
                "Material memory coverage gap — cannot fully attest Roblox process memory",
                Some(format!(
                    "PID: {}, intended_bytes: {}, bytes_scanned: {}, truncated_bytes: {}, read_failed_bytes: {}, {}",
                    pid,
                    coverage.intended_bytes,
                    bytes_scanned,
                    truncated_bytes,
                    read_failed_bytes,
                    coverage_details
                )),
            ));
        } else if table.total_flags() == 0 {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Clean,
                "No suspicious FFlags found in Roblox process memory",
                Some(format!(
                    "PID: {}, regions_scanned: {}, bytes_scanned: {} | {}",
                    pid, regions_scanned, bytes_scanned, coverage_details
                )),
            ));
        } else {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Clean,
                "Memory scan completed with acceptable coverage",
                Some(format!(
                    "PID: {}, regions_scanned: {} | {}",
                    pid, regions_scanned, coverage_details
                )),
            ));
        }
        findings
    }

    /// Enumerate modules loaded into the target process and flag any whose path
    /// is not under a trusted directory. Uses a growing buffer so truncation
    /// is detected and compensated for.
    fn scan_modules_windows(handle: HANDLE, pid: u32) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        let mut modules: Vec<HMODULE> = vec![std::ptr::null_mut(); 1024];
        let mut needed: u32;

        loop {
            let cb_bytes = (mem::size_of::<HMODULE>() * modules.len()) as u32;
            needed = 0;
            let ok = unsafe {
                EnumProcessModulesEx(
                    handle,
                    modules.as_mut_ptr(),
                    cb_bytes,
                    &mut needed,
                    LIST_MODULES_ALL,
                )
            };
            if ok == 0 {
                // EnumProcessModulesEx returning 0 is common during DLL
                // load/unload races, with AV/EDR hooks, or on PPL-protected
                // processes — not cheat evidence.
                findings.push(ScanFinding::new(
                    "memory_scanner",
                    ScanVerdict::Inconclusive,
                    "Could not enumerate modules in Roblox process",
                    Some(format!("PID: {}", pid)),
                ));
                return findings;
            }
            if (needed as usize) <= cb_bytes as usize {
                break;
            }
            // Truncated — grow the buffer and retry. Cap growth to prevent DoS.
            let new_len = (needed as usize / mem::size_of::<HMODULE>())
                .saturating_add(256)
                .min(256 * 1024);
            if new_len <= modules.len() {
                findings.push(ScanFinding::new(
                    "memory_scanner",
                    ScanVerdict::Inconclusive,
                    "Module enumeration truncated; could not grow buffer",
                    Some(format!("PID: {}, needed: {}", pid, needed)),
                ));
                return findings;
            }
            modules.resize(new_len, std::ptr::null_mut());
        }

        let count = needed as usize / mem::size_of::<HMODULE>();

        let mut untrusted = 0usize;
        let mut total = 0usize;

        for i in 0..count {
            let hmod = modules[i];
            if hmod.is_null() {
                continue;
            }

            let mut buf: Vec<u16> = vec![0; MAX_PATH as usize];
            let mut len =
                unsafe { GetModuleFileNameExW(handle, hmod, buf.as_mut_ptr(), buf.len() as u32) };
            while len != 0 && (len as usize) == buf.len() {
                let new_size = buf.len().saturating_mul(2).min(65_536);
                if new_size <= buf.len() {
                    break;
                }
                buf.resize(new_size, 0);
                len = unsafe {
                    GetModuleFileNameExW(handle, hmod, buf.as_mut_ptr(), buf.len() as u32)
                };
            }
            if len == 0 {
                // Transient: module unloaded between enumeration and path
                // query, or path is restricted by PPL. Not cheat evidence.
                findings.push(ScanFinding::new(
                    "memory_scanner",
                    ScanVerdict::Inconclusive,
                    "Module present in Roblox process with unreadable path",
                    Some(format!("PID: {}", pid)),
                ));
                continue;
            }

            total += 1;

            let path = String::from_utf16_lossy(&buf[..len as usize]);
            let lower = path.to_lowercase();

            if is_trusted_module_path(&lower) {
                continue;
            }

            untrusted += 1;
            let verdict = if is_high_risk_module_path(&lower) {
                ScanVerdict::Flagged
            } else {
                ScanVerdict::Suspicious
            };

            let filename = std::path::Path::new(&path)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| path.clone());

            findings.push(ScanFinding::new(
                "memory_scanner",
                verdict,
                format!("Untrusted module loaded into Roblox: \"{}\"", filename),
                Some(format!("Path: {}, PID: {}", path, pid)),
            ));
        }

        if untrusted == 0 {
            findings.push(ScanFinding::new(
                "memory_scanner",
                ScanVerdict::Clean,
                "All loaded modules are from trusted locations",
                Some(format!("Modules inspected: {}, PID: {}", total, pid)),
            ));
        }

        findings
    }

    pub(super) fn trusted_windows_roblox_roots() -> Vec<String> {
        // UWP locations are scoped to the ROBLOXCORPORATION package family
        // rather than the entire WindowsApps / Packages tree, so an unrelated
        // UWP app cannot pass the trust check. Bloxstrap / Fishstrap install
        // per-version Roblox copies under their own `Versions\` directory;
        // these launchers are explicitly treated as legitimate elsewhere in
        // the scanner (see KNOWN_BOOTSTRAPPER_DIRS), so refusing to scan
        // their RobloxPlayerBeta.exe would leave the memory scanner
        // effectively disabled for the majority of real users.
        let mut roots = Vec::new();
        if let Ok(pf) = std::env::var("ProgramFiles") {
            roots.push(format!("{}\\Roblox", pf));
            roots.push(format!("{}\\WindowsApps\\ROBLOXCORPORATION.", pf));
        }
        if let Ok(pfx86) = std::env::var("ProgramFiles(x86)") {
            roots.push(format!("{}\\Roblox", pfx86));
        }
        if let Ok(local) = std::env::var("LocalAppData") {
            roots.push(format!("{}\\Roblox", local));
            roots.push(format!("{}\\Packages\\ROBLOXCORPORATION.", local));
            roots.push(format!("{}\\Bloxstrap\\Versions\\", local));
            roots.push(format!("{}\\Fishstrap\\Versions\\", local));
        }
        roots
    }

    fn trusted_module_roots_lower() -> Vec<String> {
        let mut roots = Vec::new();

        let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        roots.push(format!("{}\\System32\\", sys_root).to_lowercase());
        roots.push(format!("{}\\SysWOW64\\", sys_root).to_lowercase());
        roots.push(format!("{}\\WinSxS\\", sys_root).to_lowercase());
        roots.push(format!("{}\\assembly\\", sys_root).to_lowercase());
        roots.push(format!("{}\\Microsoft.NET\\", sys_root).to_lowercase());

        // Common third-party publishers whose DLLs routinely get injected
        // system-wide: GPU drivers, peripheral control suites, overlay
        // software, anti-cheat shims. Without these, every gamer with
        // normal hardware trips the untrusted-module heuristic.
        for pf_var in ["ProgramFiles", "ProgramFiles(x86)"] {
            if let Ok(pf) = std::env::var(pf_var) {
                let pf_lower = pf.to_lowercase();
                roots.push(format!("{}\\roblox\\", pf_lower));
                roots.push(format!("{}\\nvidia corporation\\", pf_lower));
                roots.push(format!("{}\\amd\\", pf_lower));
                roots.push(format!("{}\\intel\\", pf_lower));
                roots.push(format!("{}\\realtek\\", pf_lower));
                roots.push(format!("{}\\razer\\", pf_lower));
                roots.push(format!("{}\\logitech\\", pf_lower));
                roots.push(format!("{}\\corsair\\", pf_lower));
                roots.push(format!("{}\\steelseries\\", pf_lower));
                roots.push(format!("{}\\steam\\", pf_lower));
                roots.push(format!("{}\\discord\\", pf_lower));
                roots.push(format!("{}\\obs-studio\\", pf_lower));
                roots.push(format!("{}\\easyanticheat\\", pf_lower));
                roots.push(format!("{}\\battleye\\", pf_lower));
                roots.push(format!("{}\\common files\\", pf_lower));
                // Roblox UWP package family (not the entire Store).
                if pf_var == "ProgramFiles" {
                    roots.push(format!("{}\\windowsapps\\robloxcorporation.", pf_lower));
                }
            }
        }

        if let Ok(local) = std::env::var("LocalAppData") {
            let local_lower = local.to_lowercase();
            roots.push(format!("{}\\roblox\\", local_lower));
            // Only Roblox UWP package family, not every per-user UWP package.
            roots.push(format!("{}\\packages\\robloxcorporation.", local_lower));
            // Bloxstrap / Fishstrap ship legitimate Roblox binaries under
            // these paths; required so modules loaded by a bootstrap-launched
            // Roblox are not treated as untrusted.
            roots.push(format!("{}\\bloxstrap\\versions\\", local_lower));
            roots.push(format!("{}\\fishstrap\\versions\\", local_lower));
            // User-scoped installs of Discord (Electron in %LocalAppData%)
            // and NVIDIA overlay components.
            roots.push(format!("{}\\discord\\", local_lower));
            roots.push(format!("{}\\nvidia\\", local_lower));
            roots.push(format!("{}\\nvidia corporation\\", local_lower));
        }

        roots
    }

    fn is_trusted_module_path(path_lower: &str) -> bool {
        if path_lower.contains("\\..\\") {
            return false;
        }
        let roots = trusted_module_roots_lower();
        roots.iter().any(|r| path_lower.starts_with(r))
    }

    fn is_high_risk_module_path(path_lower: &str) -> bool {
        // Anchor `\desktop\` and `\downloads\` to the resolved user profile
        // prefix rather than matching anywhere in the path. Previously any
        // DLL path containing those segments (e.g. `C:\games\Desktop Widgets`
        // or `C:\...\OneDrive - Work\Desktop\...`) produced a hard Flagged
        // verdict. The anchored form still catches a real injector running
        // from the user's actual Downloads/Desktop folder.
        let userprofile_lower = std::env::var("UserProfile").ok().map(|p| p.to_lowercase());
        if let Some(up) = userprofile_lower {
            let user_desktop = format!("{}\\desktop\\", up);
            let user_downloads = format!("{}\\downloads\\", up);
            if path_lower.starts_with(&user_desktop) || path_lower.starts_with(&user_downloads) {
                return true;
            }
        }
        // Writable staging directories retain unanchored substring match —
        // legitimate software almost never loads DLLs from %TEMP%, and an
        // `\injected\` segment is intentionally named that way by tooling.
        const HIGH_RISK_SUBSTRS: &[&str] = &[
            "\\temp\\",
            "\\tmp\\",
            "\\appdata\\local\\temp\\",
            "\\injected\\",
        ];
        HIGH_RISK_SUBSTRS.iter().any(|s| path_lower.contains(s))
    }
}

#[cfg(all(target_os = "windows", target_pointer_width = "64"))]
fn trusted_windows_roblox_roots() -> Vec<String> {
    windows_impl::trusted_windows_roblox_roots()
}

#[cfg(all(target_os = "windows", target_pointer_width = "64"))]
async fn scan_windows(reporter: ScanProgress) -> Vec<ScanFinding> {
    windows_impl::scan_windows(reporter).await
}

// ============================
// Tests
// ============================
#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn small_memory_coverage_gaps_are_not_material() {
        let intended = 4 * 1024 * 1024 * 1024u64;
        let missing = 256 * 1024 * 1024u64;
        assert!(
            !coverage_gap_is_material(missing, intended),
            "normal transient unreadable chunks should stay in details"
        );
    }

    #[test]
    fn large_memory_coverage_gaps_are_material() {
        let intended = 10 * 1024 * 1024 * 1024u64;
        let missing = 1024 * 1024 * 1024u64;
        assert!(
            coverage_gap_is_material(missing, intended),
            "large skipped/unreadable memory spans should remain visible"
        );
    }

    #[test]
    fn high_percent_but_tiny_memory_coverage_gaps_are_not_material() {
        let intended = 1024 * 1024 * 1024u64;
        let missing = 300 * 1024 * 1024u64;
        assert!(
            !coverage_gap_is_material(missing, intended),
            "moderate churn should not become a top-level warning unless the byte gap is also large"
        );
    }

    #[test]
    fn near_total_memory_coverage_loss_is_material_even_below_one_gib() {
        let intended = 512 * 1024 * 1024u64;
        let missing = 511 * 1024 * 1024u64;
        assert!(
            coverage_gap_is_material(missing, intended),
            "a nearly unreadable small scan must not report clean"
        );
    }

    #[test]
    fn memory_coverage_details_keep_non_material_gap_context() {
        let coverage = MemoryCoverage {
            intended_bytes: 4 * 1024 * 1024 * 1024u64,
            bytes_scanned: 3 * 1024 * 1024 * 1024u64,
            regions_scanned: 12,
            truncated_regions: 1,
            truncated_bytes: 128 * 1024 * 1024u64,
            read_failures: 2,
            read_failed_bytes: 64 * 1024 * 1024u64,
        };

        assert!(!coverage.material_gap());
        let details = coverage.details();
        assert!(details.contains("coverage_gap_bytes: 201326592"));
        assert!(details.contains("coverage_gap_percent: 4%"));
        assert!(details.contains("truncated_regions: 1"));
        assert!(details.contains("read_failures: 2"));
    }

    #[test]
    fn zero_successful_memory_reads_are_never_clean_coverage() {
        let coverage = MemoryCoverage {
            intended_bytes: 512 * 1024 * 1024u64,
            bytes_scanned: 0,
            regions_scanned: 0,
            truncated_regions: 0,
            truncated_bytes: 0,
            read_failures: 128,
            read_failed_bytes: 512 * 1024 * 1024u64,
        };

        assert!(coverage.no_successful_reads());
        assert!(coverage.material_gap());
    }

    #[test]
    fn memory_coverage_gap_combines_truncation_and_read_failures() {
        let coverage = MemoryCoverage {
            intended_bytes: 8 * 1024 * 1024 * 1024u64,
            bytes_scanned: 6 * 1024 * 1024 * 1024u64,
            regions_scanned: 42,
            truncated_regions: 1,
            truncated_bytes: 700 * 1024 * 1024u64,
            read_failures: 3,
            read_failed_bytes: 400 * 1024 * 1024u64,
        };

        assert_eq!(coverage.gap_bytes(), 1_153_433_600);
        assert!(coverage.material_gap());
    }

    /// Regression guard: Bloxstrap / Fishstrap install Roblox under their
    /// own `Versions\` subdirectories. Those launchers are explicitly
    /// treated as legitimate elsewhere in the scanner, so the memory-scan
    /// trust check must accept their RobloxPlayerBeta.exe paths — otherwise
    /// a Bloxstrap-launched Roblox gets "untrusted path, refusing to scan"
    /// and the memory scanner is effectively disabled for most real users.
    #[cfg(all(target_os = "windows", target_pointer_width = "64"))]
    #[test]
    fn trust_roots_include_bloxstrap_and_fishstrap() {
        let old_local_app_data = std::env::var_os("LocalAppData");
        std::env::set_var("LocalAppData", "C:\\Users\\test\\AppData\\Local");
        let roots = windows_impl::trusted_windows_roblox_roots();
        if let Some(value) = old_local_app_data {
            std::env::set_var("LocalAppData", value);
        } else {
            std::env::remove_var("LocalAppData");
        }

        let has_bloxstrap = roots.iter().any(|r| {
            r.eq_ignore_ascii_case("C:\\Users\\test\\AppData\\Local\\Bloxstrap\\Versions\\")
        });
        let has_fishstrap = roots.iter().any(|r| {
            r.eq_ignore_ascii_case("C:\\Users\\test\\AppData\\Local\\Fishstrap\\Versions\\")
        });
        assert!(
            has_bloxstrap,
            "Bloxstrap Versions path missing from trust list: {roots:?}"
        );
        assert!(
            has_fishstrap,
            "Fishstrap Versions path missing from trust list: {roots:?}"
        );
    }

    #[test]
    fn prefix_scan_finds_known_flag() {
        let b = bytes("{\"DFIntS2PhysicsSenderRate\":1}");
        let hits = scan_prefix_hits(&b);
        assert!(hits
            .iter()
            .any(|(_, n, known)| n == "DFIntS2PhysicsSenderRate" && *known));
    }

    #[test]
    fn prefix_scan_finds_unknown_flag() {
        let b = bytes("junk\"FFlagTotallyMadeUpNewFlag\":true more junk");
        let hits = scan_prefix_hits(&b);
        let got = hits
            .iter()
            .find(|(_, n, known)| n == "FFlagTotallyMadeUpNewFlag" && !*known);
        assert!(got.is_some(), "unknown flag must still be reported");
    }

    #[test]
    fn prefix_scan_rejects_substring_inside_longer_ident() {
        // Would previously match FFlagFoo inside FFlagFooBar.
        let b = bytes("FFlagFooBar stuff");
        let hits = scan_prefix_hits(&b);
        // The extractor takes the full identifier FFlagFooBar, so we should see
        // that name exactly — never a truncated "FFlagFoo".
        assert!(hits.iter().any(|(_, n, _)| n == "FFlagFooBar"));
        assert!(!hits.iter().any(|(_, n, _)| n == "FFlagFoo"));
    }

    #[test]
    fn prefix_scan_rejects_lowercase_body_start() {
        // `FFlagabc` — real flags never have a lowercase first body letter.
        let b = bytes("\"FFlagabc\":1");
        let hits = scan_prefix_hits(&b);
        assert!(hits.is_empty(), "expected no hits, got {:?}", hits);
    }

    #[test]
    fn prefix_scan_rejects_too_short_body() {
        let b = bytes("\"FFlagA\":1");
        let hits = scan_prefix_hits(&b);
        assert!(hits.is_empty(), "single-letter bodies are noise");
    }

    #[test]
    fn prefix_scan_rejects_ident_prefix_boundary() {
        // "xFFlagBar" — the F is inside a larger identifier, should not match.
        let b = bytes("xFFlagBarValue=1");
        let hits = scan_prefix_hits(&b);
        assert!(hits.is_empty(), "expected no hits, got {:?}", hits);
    }

    #[test]
    fn boundary_ok_accepts_end_of_buffer() {
        let b = bytes("hello");
        assert!(is_boundary_ok(&b, 0, b.len()));
    }

    #[test]
    fn contextual_match_requires_delimiter_context() {
        // No delimiter before the prefix. The byte before 'F' is 'y' — an
        // ident byte — so the boundary check should reject.
        let b = bytes("randombinaryFFlagDebugXY");
        assert!(!is_contextual_match(&b, 12, 14));
    }

    #[test]
    fn wide_scan_matches_known_flag() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&to_utf16le("DFIntS2PhysicsSenderRate"));
        buf.extend_from_slice(&[0u8; 4]);
        let mut table = FlagHitTable::default();
        scan_wide_known(&buf, 0x1000, &[], &mut table);
        let hit = table.hits.get("DFIntS2PhysicsSenderRate").expect("hit");
        assert_eq!(hit.count, 1);
        assert!(hit.seen_wide);
    }

    #[test]
    fn scan_buffer_aggregates_ascii_and_wide() {
        let flag = "DFIntS2PhysicsSenderRate";
        let mut buf = Vec::new();
        buf.extend_from_slice(b"\"");
        buf.extend_from_slice(flag.as_bytes());
        // Non-ident byte ',' followed by two NUL bytes keeps the wide-boundary
        // check from mistaking the preceding ASCII for a UTF-16 identifier code
        // unit. Real process memory typically has non-ident filler between
        // adjacent strings, so this matches realistic layouts.
        buf.extend_from_slice(b"\",\x00\x00");
        buf.extend_from_slice(&to_utf16le(flag));
        buf.extend_from_slice(&[0, 0]);
        let mut table = FlagHitTable::default();
        scan_buffer(&buf, 0x2000, &mut table);
        let hit = table.hits.get(flag).expect("flag present");
        assert!(hit.seen_ascii, "ascii match missing");
        assert!(hit.seen_wide, "wide match missing");
        assert_eq!(hit.count, 2);
    }

    #[test]
    fn findings_skip_allowlisted_flag() {
        // Pretend we saw an allowlisted flag in memory — it should not produce a finding.
        let mut table = FlagHitTable::default();
        table.record_with_value("FFlagDebugGraphicsPreferD3D11", 0x1000, false, None, None);
        let findings = findings_from_table(&table);
        assert!(
            findings.is_empty(),
            "allowlisted flag must not be a finding"
        );
    }

    #[test]
    fn findings_report_unknown_as_clean_informational() {
        // "Unknown FFlag-shaped identifier" really means "not in our
        // hand-curated suspicious database" — Roblox itself has tens of
        // thousands of FFlag names resident in heap on every run, so
        // surfacing these as Suspicious would trip the scan verdict on
        // every legitimate client. The grouped summary is emitted as
        // Clean/informational so count + samples remain inspectable
        // without polluting the overall verdict.
        let mut table = FlagHitTable::default();
        table.record_with_value("FFlagCompletelyUnknownThing", 0x2000, false, None, None);
        let findings = findings_from_table(&table);
        assert_eq!(findings.len(), 1);
        match &findings[0].verdict {
            ScanVerdict::Clean => {}
            other => panic!("expected Clean, got {:?}", other),
        }
    }

    #[test]
    fn findings_never_emit_suspicious_or_flagged_for_known_names() {
        // v0.5.2: memory-side flag NAME emission was retired. Even when
        // a known CRITICAL flag with an adjacent JSON-shaped value lands
        // in the hit table, `findings_from_table` must NOT emit a
        // Suspicious or Flagged finding — Roblox's remote flag-config
        // response provides the same `"Name":value` byte shape in heap
        // on every vanilla client, so matching there produces
        // false positives on legitimate players. The authoritative
        // override-detection path is client_settings_scanner.
        let mut table = FlagHitTable::default();
        table.record_with_value(
            "DFIntS2PhysicsSenderRate",
            0x1000,
            false,
            Some("1".to_string()),
            None,
        );
        table.record_with_value(
            "FIntCameraFarZPlane",
            0x2000,
            false,
            Some("1".to_string()),
            None,
        );
        table.record_with_value(
            "DFIntCSGv2LodsToGenerate",
            0x3000,
            false,
            Some("0".to_string()),
            None,
        );
        let findings = findings_from_table(&table);
        for f in &findings {
            assert!(
                matches!(f.verdict, ScanVerdict::Clean),
                "memory scanner must not emit {:?} for known names: {:?}",
                f.verdict,
                f
            );
        }
    }

    #[test]
    fn serialized_injector_fflags_json_with_critical_flag_is_flagged() {
        let b = bytes(r#"fflags.json address.json {"DFIntS2PhysicsSenderRate":1}"#);
        let mut table = FlagHitTable::default();
        scan_buffer(&b, 0x5000, &mut table);

        let findings = findings_from_table(&table);
        assert!(
            findings.iter().any(|f| {
                matches!(f.verdict, ScanVerdict::Flagged)
                    && f.description.contains("DFIntS2PhysicsSenderRate")
                    && f.description.contains("= 1")
            }),
            "expected Flagged runtime-injection evidence, got: {:?}",
            findings
        );
    }

    #[test]
    fn serialized_injector_fflags_json_with_high_flag_is_suspicious() {
        let b = bytes(r#"fflags.json address.json {"FIntCameraFarZPlane":1}"#);
        let mut table = FlagHitTable::default();
        scan_buffer(&b, 0x6000, &mut table);

        let findings = findings_from_table(&table);
        assert!(
            findings.iter().any(|f| {
                matches!(f.verdict, ScanVerdict::Suspicious)
                    && f.description.contains("FIntCameraFarZPlane")
            }),
            "expected Suspicious runtime-injection evidence, got: {:?}",
            findings
        );
    }

    #[test]
    fn assignment_style_injector_value_is_parsed() {
        let b = bytes(r#"fflags.json address.json DFIntS2PhysicsSenderRate=1"#);
        let mut table = FlagHitTable::default();
        scan_buffer(&b, 0x7000, &mut table);

        let findings = findings_from_table(&table);
        assert!(
            findings.iter().any(|f| {
                matches!(f.verdict, ScanVerdict::Flagged)
                    && f.description.contains("DFIntS2PhysicsSenderRate")
                    && f.description.contains("= 1")
            }),
            "expected assignment-style value evidence, got: {:?}",
            findings
        );
    }

    #[test]
    fn ascii_known_scan_catches_non_fflag_prefix_names() {
        let b = bytes(r#"fflags.json address.json {"NextGenReplicatorEnabledWrite4":false}"#);
        let mut table = FlagHitTable::default();
        scan_buffer(&b, 0x8000, &mut table);

        let findings = findings_from_table(&table);
        assert!(
            findings.iter().any(|f| {
                matches!(f.verdict, ScanVerdict::Flagged)
                    && f.description.contains("NextGenReplicatorEnabledWrite4")
            }),
            "expected non-prefix critical flag to be detected, got: {:?}",
            findings
        );
    }

    #[test]
    fn vanilla_remote_config_blob_with_known_flag_values_stays_clean() {
        let b = bytes(r#"{"DFIntS2PhysicsSenderRate":1,"FIntCameraFarZPlane":1}"#);
        let mut table = FlagHitTable::default();
        scan_buffer(&b, 0x9000, &mut table);
        assert!(
            table.hits.contains_key("DFIntS2PhysicsSenderRate"),
            "test setup must exercise a real memory hit"
        );

        let findings = findings_from_table(&table);
        assert!(
            findings
                .iter()
                .all(|f| matches!(f.verdict, ScanVerdict::Clean)),
            "plain Roblox-style config blob must stay informational, got: {:?}",
            findings
        );
    }

    #[test]
    fn injector_markers_with_allowlisted_only_do_not_raise_verdict() {
        let b = bytes(r#"fflags.json address.json {"FFlagDebugGraphicsPreferD3D11":true}"#);
        let mut table = FlagHitTable::default();
        scan_buffer(&b, 0xA000, &mut table);
        assert!(
            table.hits.contains_key("FFlagDebugGraphicsPreferD3D11"),
            "test setup must exercise an allowlisted memory hit"
        );

        let findings = findings_from_table(&table);
        assert!(
            findings
                .iter()
                .all(|f| matches!(f.verdict, ScanVerdict::Clean)),
            "allowlisted-only injector-shaped blob must not raise verdict, got: {:?}",
            findings
        );
    }

    #[test]
    fn distant_injector_marker_does_not_taint_vanilla_config_blob() {
        let mut b = bytes("fflags.json address.json");
        b.extend(std::iter::repeat(b' ').take(INJECTOR_CONTEXT_WINDOW_BYTES + 512));
        b.extend_from_slice(br#"{"DFIntS2PhysicsSenderRate":1}"#);

        let mut table = FlagHitTable::default();
        scan_buffer(&b, 0xB000, &mut table);
        assert!(
            table.hits.contains_key("DFIntS2PhysicsSenderRate"),
            "test setup must exercise a real memory hit"
        );

        let findings = findings_from_table(&table);
        assert!(
            findings
                .iter()
                .all(|f| matches!(f.verdict, ScanVerdict::Clean)),
            "distant marker must not taint flag value, got: {:?}",
            findings
        );
    }

    #[test]
    fn serialized_wide_injector_config_with_critical_flag_is_flagged() {
        let b = to_utf16le(r#"fflags.json address.json {"DFIntS2PhysicsSenderRate":1}"#);
        let mut table = FlagHitTable::default();
        scan_buffer(&b, 0xC000, &mut table);

        let findings = findings_from_table(&table);
        assert!(
            findings.iter().any(|f| {
                matches!(f.verdict, ScanVerdict::Flagged)
                    && f.description.contains("DFIntS2PhysicsSenderRate")
            }),
            "expected UTF-16 injector evidence to be flagged, got: {:?}",
            findings
        );
    }

    #[test]
    fn newline_separated_injector_value_is_parsed() {
        let b = bytes("fflags.json\r\naddress.json\r\n{\"DFIntS2PhysicsSenderRate\":\r\n 1}");
        let mut table = FlagHitTable::default();
        scan_buffer(&b, 0xD000, &mut table);

        let findings = findings_from_table(&table);
        assert!(
            findings.iter().any(|f| {
                matches!(f.verdict, ScanVerdict::Flagged)
                    && f.description.contains("DFIntS2PhysicsSenderRate")
                    && f.description.contains("= 1")
            }),
            "expected CRLF-separated value evidence to be flagged, got: {:?}",
            findings
        );
    }

    #[test]
    fn malformed_adjacent_literals_do_not_create_injection_evidence() {
        let b = bytes(
            r#"fflags.json address.json {"DFIntS2PhysicsSenderRate":1eZ,"FIntCameraFarZPlane":"unterminated}"#,
        );
        let mut table = FlagHitTable::default();
        scan_buffer(&b, 0xD100, &mut table);
        assert!(
            table.hits.contains_key("DFIntS2PhysicsSenderRate"),
            "test setup must still observe the critical flag name"
        );

        let findings = findings_from_table(&table);
        assert!(
            findings
                .iter()
                .all(|f| matches!(f.verdict, ScanVerdict::Clean)),
            "malformed literals must not create elevated evidence, got: {:?}",
            findings
        );
    }

    #[test]
    fn single_tool_marker_alone_does_not_taint_flag_value() {
        let b = bytes(r#"lornofix {"DFIntS2PhysicsSenderRate":1}"#);
        let mut table = FlagHitTable::default();
        scan_buffer(&b, 0xD200, &mut table);
        assert!(table.tool_markers.contains_key("lornofix"));

        let findings = findings_from_table(&table);
        assert!(
            findings
                .iter()
                .all(|f| matches!(f.verdict, ScanVerdict::Clean)),
            "single strong marker must not taint a value, got: {:?}",
            findings
        );
    }

    #[test]
    fn marker_substrings_are_not_context_markers() {
        let b =
            bytes(r#"myfflags.json.backup address.json.example {"DFIntS2PhysicsSenderRate":1}"#);
        let mut table = FlagHitTable::default();
        scan_buffer(&b, 0xD300, &mut table);
        assert!(
            table.tool_markers.is_empty(),
            "marker substrings should not be recorded: {:?}",
            marker_summary(&table)
        );

        let findings = findings_from_table(&table);
        assert!(
            findings
                .iter()
                .all(|f| matches!(f.verdict, ScanVerdict::Clean)),
            "substring marker matches must not taint a value, got: {:?}",
            findings
        );
    }

    #[test]
    fn runtime_hash_matches_lorno_lookup_algorithm() {
        assert_eq!(fnv1a64(b"DFIntS2PhysicsSenderRate"), 0x6a17_20d7_9b16_e211);
        assert_eq!(
            fnv1a64(b"DFFlagDebugDrawBroadPhaseAABBs"),
            0x6bfd_cc53_cb96_e6b8
        );
        assert_eq!(fnv1a64(b"FIntCameraFarZPlane"), 0x94f7_f3f0_4cb3_729a);
    }

    #[test]
    fn runtime_singleton_locator_accepts_lorno_style_rip_load() {
        let base = 0x1000_0000usize;
        let instr_offset = 3usize;
        let slot = 0x1000_1000usize;
        let rip_after_mov = base + instr_offset + 7;
        let disp = (slot as isize - rip_after_mov as isize) as i32;

        let mut buffer = vec![0x90, 0x90, 0x90, 0x48, 0x8B, 0x0D];
        buffer.extend_from_slice(&disp.to_le_bytes());

        assert_eq!(find_runtime_singleton_slots(&buffer, base), vec![slot]);
    }

    #[test]
    fn runtime_singleton_locator_dedupes_strict_and_generic_matches() {
        let base = 0x2000_0000usize;
        let slot = 0x2000_4000usize;
        let rip_after_mov = base + 11;
        let disp = (slot as isize - rip_after_mov as isize) as i32;
        let mut buffer = vec![0x48, 0x83, 0xEC, 0x38, 0x48, 0x8B, 0x0D];
        buffer.extend_from_slice(&disp.to_le_bytes());
        buffer.extend_from_slice(&[0x4C, 0x8D, 0x05, 0, 0, 0, 0]);

        assert_eq!(find_runtime_singleton_slots(&buffer, base), vec![slot]);
    }

    #[test]
    fn runtime_table_header_locator_accepts_plausible_aligned_header() {
        let base = 0x3000_0000usize;
        let table = base + 16;
        let mut buffer = vec![0u8; 16 + RUNTIME_TABLE_SIZE + 8];
        buffer[16..24].copy_from_slice(&0x5000_0000u64.to_le_bytes());
        buffer[32..40].copy_from_slice(&0x6000_0000u64.to_le_bytes());
        buffer[56..64].copy_from_slice(&0xffu64.to_le_bytes());

        let headers = find_runtime_table_headers(&buffer, base);
        assert_eq!(
            headers,
            vec![RuntimeTableHeaderCandidate {
                address: table,
                mask: 0xff
            }]
        );
    }

    #[test]
    fn runtime_table_header_locator_rejects_unaligned_pointers() {
        let base = 0x3000_0000usize;
        let mut buffer = vec![0u8; RUNTIME_TABLE_SIZE];
        buffer[0..8].copy_from_slice(&0x5000_0001u64.to_le_bytes());
        buffer[0x10..0x18].copy_from_slice(&0x6000_0000u64.to_le_bytes());
        buffer[0x28..0x30].copy_from_slice(&0xffu64.to_le_bytes());

        assert!(find_runtime_table_headers(&buffer, base).is_empty());
    }

    #[test]
    fn runtime_table_header_locator_rejects_non_mask_values() {
        let base = 0x3000_0000usize;
        let mut buffer = vec![0u8; RUNTIME_TABLE_SIZE];
        buffer[0..8].copy_from_slice(&0x5000_0000u64.to_le_bytes());
        buffer[0x10..0x18].copy_from_slice(&0x6000_0000u64.to_le_bytes());
        buffer[0x28..0x30].copy_from_slice(&0xf0u64.to_le_bytes());

        assert!(find_runtime_table_headers(&buffer, base).is_empty());
    }

    #[test]
    fn scan_buffer_records_heap_runtime_table_headers() {
        let base = 0x4000_0000usize;
        let table = base + 24;
        let mut buffer = vec![0u8; 24 + RUNTIME_TABLE_SIZE + 8];
        buffer[24..32].copy_from_slice(&0x5000_0000u64.to_le_bytes());
        buffer[40..48].copy_from_slice(&0x6000_0000u64.to_le_bytes());
        buffer[64..72].copy_from_slice(&0xffu64.to_le_bytes());

        let mut hits = FlagHitTable::default();
        scan_buffer(&buffer, base, &mut hits);

        assert_eq!(
            hits.runtime_table_headers,
            vec![RuntimeTableHeaderCandidate {
                address: table,
                mask: 0xff
            }]
        );
        assert_eq!(hits.runtime_table_header_matches, 1);
    }

    #[test]
    fn scan_buffer_records_runtime_long_string_node_entries() {
        let base = 0x5000_0000usize;
        let name = "DFFlagDebugDrawBroadPhaseAABBs";
        let string_offset = 0x180usize;
        let node_offset = 0x40usize;
        let entry = 0x7000_0000usize;
        let mut buffer = vec![0u8; 0x220];

        buffer[string_offset..string_offset + name.len()].copy_from_slice(name.as_bytes());
        buffer[node_offset + RUNTIME_NODE_STRING_OFFSET
            ..node_offset + RUNTIME_NODE_STRING_OFFSET + 8]
            .copy_from_slice(&((base + string_offset) as u64).to_le_bytes());
        buffer[node_offset + RUNTIME_NODE_LEN_OFFSET..node_offset + RUNTIME_NODE_LEN_OFFSET + 8]
            .copy_from_slice(&(name.len() as u64).to_le_bytes());
        buffer[node_offset + RUNTIME_NODE_CAP_OFFSET..node_offset + RUNTIME_NODE_CAP_OFFSET + 8]
            .copy_from_slice(&(name.len() as u64).to_le_bytes());
        buffer
            [node_offset + RUNTIME_NODE_ENTRY_OFFSET..node_offset + RUNTIME_NODE_ENTRY_OFFSET + 8]
            .copy_from_slice(&(entry as u64).to_le_bytes());

        let mut hits = FlagHitTable::default();
        scan_buffer(&buffer, base, &mut hits);

        assert_eq!(
            hits.runtime_node_entries,
            vec![RuntimeNodeEntryCandidate {
                name,
                node_address: base + node_offset,
                string_address: base + string_offset,
                entry,
            }]
        );
        assert_eq!(hits.runtime_node_entry_matches, 1);
    }

    #[test]
    fn runtime_node_entry_locator_rejects_wrong_length_nodes() {
        let base = 0x5100_0000usize;
        let name = "FIntCameraFarZPlane";
        let string_offset = 0x180usize;
        let node_offset = 0x40usize;
        let entry = 0x7100_0000usize;
        let mut buffer = vec![0u8; 0x220];

        buffer[string_offset..string_offset + name.len()].copy_from_slice(name.as_bytes());
        buffer[node_offset + RUNTIME_NODE_STRING_OFFSET
            ..node_offset + RUNTIME_NODE_STRING_OFFSET + 8]
            .copy_from_slice(&((base + string_offset) as u64).to_le_bytes());
        buffer[node_offset + RUNTIME_NODE_LEN_OFFSET..node_offset + RUNTIME_NODE_LEN_OFFSET + 8]
            .copy_from_slice(&((name.len() as u64) - 1).to_le_bytes());
        buffer[node_offset + RUNTIME_NODE_CAP_OFFSET..node_offset + RUNTIME_NODE_CAP_OFFSET + 8]
            .copy_from_slice(&(name.len() as u64).to_le_bytes());
        buffer
            [node_offset + RUNTIME_NODE_ENTRY_OFFSET..node_offset + RUNTIME_NODE_ENTRY_OFFSET + 8]
            .copy_from_slice(&(entry as u64).to_le_bytes());

        let mut hits = FlagHitTable::default();
        scan_buffer(&buffer, base, &mut hits);

        assert!(hits.runtime_node_entries.is_empty());
        assert_eq!(hits.runtime_node_entry_matches, 0);
    }

    #[test]
    fn runtime_node_entries_resolve_when_string_and_node_are_in_different_chunks() {
        let string_base = 0x5200_0000usize;
        let node_base = 0x5300_0000usize;
        let name = "FIntCameraFarZPlane";
        let string_offset = 0x80usize;
        let node_offset = 0x40usize;
        let entry = 0x7200_0000usize;

        let mut hits = FlagHitTable::default();
        let mut string_buffer = vec![0u8; 0x120];
        string_buffer[string_offset..string_offset + name.len()].copy_from_slice(name.as_bytes());
        scan_buffer(&string_buffer, string_base, &mut hits);

        let mut node_buffer = vec![0u8; 0x120];
        node_buffer[node_offset + RUNTIME_NODE_STRING_OFFSET
            ..node_offset + RUNTIME_NODE_STRING_OFFSET + 8]
            .copy_from_slice(&((string_base + string_offset) as u64).to_le_bytes());
        node_buffer
            [node_offset + RUNTIME_NODE_LEN_OFFSET..node_offset + RUNTIME_NODE_LEN_OFFSET + 8]
            .copy_from_slice(&(name.len() as u64).to_le_bytes());
        node_buffer
            [node_offset + RUNTIME_NODE_CAP_OFFSET..node_offset + RUNTIME_NODE_CAP_OFFSET + 8]
            .copy_from_slice(&(name.len() as u64).to_le_bytes());
        node_buffer
            [node_offset + RUNTIME_NODE_ENTRY_OFFSET..node_offset + RUNTIME_NODE_ENTRY_OFFSET + 8]
            .copy_from_slice(&(entry as u64).to_le_bytes());
        scan_buffer(&node_buffer, node_base, &mut hits);

        assert!(hits.runtime_node_entries.is_empty());
        assert_eq!(
            resolved_runtime_node_entries(&hits),
            vec![RuntimeNodeEntryCandidate {
                name,
                node_address: node_base + node_offset,
                string_address: string_base + string_offset,
                entry,
            }]
        );
    }

    #[test]
    fn runtime_override_values_match_exact_cheat_values() {
        let rule = RuntimeOverrideRule {
            name: "DFFlagDebugDrawBroadPhaseAABBs",
            value: RuntimeFlagValue::Bool(true),
        };
        assert!(runtime_rule_matches_observed(rule, 1i32.to_le_bytes()));
        assert!(!runtime_rule_matches_observed(rule, 0i32.to_le_bytes()));

        let rule = RuntimeOverrideRule {
            name: "DFIntS2PhysicsSenderRate",
            value: RuntimeFlagValue::Int(-30),
        };
        assert!(runtime_rule_matches_observed(rule, (-30i32).to_le_bytes()));
        assert!(!runtime_rule_matches_observed(rule, 30i32.to_le_bytes()));
    }

    #[test]
    fn runtime_bool_rejects_superficially_similar_non_bool_ints() {
        let rule = RuntimeOverrideRule {
            name: "NextGenReplicatorEnabledWrite4",
            value: RuntimeFlagValue::Bool(false),
        };
        assert!(runtime_rule_matches_observed(rule, 0i32.to_le_bytes()));
        assert!(!runtime_rule_matches_observed(rule, 2i32.to_le_bytes()));
        assert!(!runtime_rule_matches_observed(rule, (-1i32).to_le_bytes()));
    }

    #[test]
    fn unknown_injected_fflag_with_context_is_suspicious() {
        let b = bytes(r#"fflags.json address.json {"FFlagTotallyMadeUpNewFlag":true}"#);
        let mut table = FlagHitTable::default();
        scan_buffer(&b, 0xD400, &mut table);

        let findings = findings_from_table(&table);
        assert!(
            findings.iter().any(|f| {
                matches!(f.verdict, ScanVerdict::Suspicious)
                    && f.description.contains("FFlagTotallyMadeUpNewFlag")
            }),
            "unknown context-backed FFlag should be suspicious, got: {:?}",
            findings
        );
    }

    #[test]
    fn context_sample_survives_value_sample_cap() {
        let mut table = FlagHitTable::default();
        for value in 0..MAX_VALUE_SAMPLES_PER_FLAG {
            table.record_with_value(
                "DFIntS2PhysicsSenderRate",
                0xE000 + value,
                false,
                Some(value.to_string()),
                None,
            );
        }
        table.record_with_value(
            "DFIntS2PhysicsSenderRate",
            0xE100,
            false,
            Some("999".to_string()),
            Some("fflags.json, address.json".to_string()),
        );

        let findings = findings_from_table(&table);
        assert!(
            findings.iter().any(|f| {
                matches!(f.verdict, ScanVerdict::Flagged)
                    && f.description.contains("DFIntS2PhysicsSenderRate")
                    && f.description.contains("= 999")
            }),
            "context-backed sample should replace non-context samples, got: {:?}",
            findings
        );
    }

    #[test]
    fn wide_known_scan_prefers_longest_prefix_sharing_flag() {
        let b = to_utf16le(
            r#"fflags.json address.json {"DFIntPhysicsSenderMaxBandwidthBpsScaling":0}"#,
        );
        let mut table = FlagHitTable::default();
        scan_buffer(&b, 0xE200, &mut table);

        let findings = findings_from_table(&table);
        assert!(
            findings.iter().any(|f| {
                matches!(f.verdict, ScanVerdict::Flagged)
                    && f.description
                        .contains("DFIntPhysicsSenderMaxBandwidthBpsScaling")
                    && f.description.contains("= 0")
            }),
            "longer UTF-16 flag should win over its prefix, got: {:?}",
            findings
        );
    }

    #[test]
    fn chunked_boundary_hit_is_recoverable() {
        // Simulate a chunk boundary: split a flag identifier across two
        // chunks, with an overlap large enough to recover the straddler.
        // Previous version of this test let `second_start` saturate to 0,
        // which meant chunk_b was the full payload and the test was vacuous.
        // Here the second chunk starts at a non-zero replay offset before the
        // flag and contains the complete identifier only because of overlap.
        let flag = "DFIntS2PhysicsSenderRate";
        let prefix = "x".repeat(96);
        let payload = format!("{}{{\"{}\":1}}", prefix, flag);
        let bytes = payload.as_bytes();
        let flag_start = payload.find(flag).expect("flag start");

        // Cut inside `DFInt...`; the replay starts before the flag but not at
        // byte 0, proving the second scan is a genuine overlapped chunk.
        let cut = flag_start + 12;
        let overlap = 24usize;
        let second_start = cut.saturating_sub(overlap);
        let chunk_a = &bytes[..cut];
        let chunk_b = &bytes[second_start..];

        // Sanity-check the test setup: chunk_a lacks the full identifier,
        // while chunk_b contains it only due to non-zero overlap replay.
        let chunk_a_str = std::str::from_utf8(chunk_a).unwrap();
        let chunk_b_str = std::str::from_utf8(chunk_b).unwrap();
        assert!(second_start > 0, "test setup must not replay from byte 0");
        assert!(second_start < flag_start, "replay must start before flag");
        assert!(
            !chunk_a_str.contains(flag),
            "test setup: chunk_a must not contain whole flag"
        );
        assert!(
            chunk_b_str.contains(flag),
            "test setup: overlap chunk must recover whole flag"
        );

        let mut table = FlagHitTable::default();
        scan_buffer(chunk_a, 0, &mut table);
        scan_buffer(chunk_b, second_start, &mut table);

        assert!(
            table.hits.contains_key(flag),
            "chunk-straddling flag must be found after overlap replay; chunk_b str: {:?}",
            chunk_b_str
        );
    }
}
