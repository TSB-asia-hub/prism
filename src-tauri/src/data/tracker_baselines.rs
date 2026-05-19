//! Vanilla FFlag values pulled from MaximumADHD/Roblox-FFlag-Tracker.
//!
//! The tracker repository snapshots Roblox's public `/v1/settings/application`
//! endpoint roughly in real-time — the same flag values Roblox pushes to
//! every live client at startup. When a live FVar's value diverges from the
//! tracker's recorded value, an external write happened *somewhere* in the
//! pipeline (most plausibly a memory injector).
//!
//! ## Trust model — this path is capped at `Suspicious`
//!
//! The bundled JSON is a *snapshot*. Roblox A/B-rolls flag values continuously,
//! so a flag that diverged from the bundle's value at scan time may simply
//! reflect a fresh Roblox-side rollout the bundle hasn't caught yet. For
//! tournament integrity we cannot let that become a Flagged verdict against
//! a real player. The bridge that consumes this module deliberately caps
//! tracker-derived findings at `Suspicious` regardless of the underlying
//! flag's `suspicious_flags.rs` tier.
//!
//! The complementary detection paths (`RUNTIME_OVERRIDE_RULES` exact-value
//! matches and the hand-curated `RUNTIME_FLAG_BASELINES`) remain the source
//! of truth for `Flagged` verdicts.
//!
//! ## Coverage
//!
//! The tracker only carries flags Roblox exposes via the public
//! application-settings endpoint — roughly 20k entries on the PC desktop
//! client at last fetch. Many cheat-target flags are internal/debug flags
//! Roblox never publishes; those are absent from the tracker and continue
//! to rely on `RUNTIME_OVERRIDE_RULES` curation.
//!
//! Bool and int flags are usable for the 4-byte i32 comparison the bare-key
//! bridge does. String flags are skipped — the i32 read at `entry+0xC0`
//! against a `std::string` slot is a heap pointer, not a comparable value.

use std::collections::HashMap;
use std::sync::OnceLock;

/// Tracker-recorded value for a single flag. We only retain types that can
/// be compared against a live i32 read at `entry+0xC0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrackerValue {
    /// The flag is bool-typed; the tracker recorded this boolean.
    Bool(bool),
    /// The flag is int-typed; the tracker recorded this i32.
    Int(i32),
}

impl TrackerValue {
    /// Compare against a 4-byte little-endian read from `entry+0xC0`.
    /// For bool flags only the first byte (0 / non-0) participates so that
    /// adjacent padding cannot fail the equality check on the int path.
    pub fn matches_live_i32(self, raw: [u8; 4]) -> bool {
        match self {
            TrackerValue::Int(expected) => i32::from_le_bytes(raw) == expected,
            TrackerValue::Bool(expected) => {
                let observed = raw[0] != 0;
                observed == expected
            }
        }
    }

    /// Human-readable label used in finding descriptions.
    pub fn render(self) -> String {
        match self {
            TrackerValue::Int(v) => v.to_string(),
            TrackerValue::Bool(v) => v.to_string(),
        }
    }
}

/// Raw JSON snapshot of `PCDesktopClient.json` from MaximumADHD's tracker,
/// embedded at compile time. Refresh path: replace
/// `src-tauri/src/data/tracker/pc_desktop_client.json` with a fresh copy
/// from the upstream repo. A nightly CI workflow keeps this current.
const TRACKER_JSON_PC_DESKTOP: &str =
    include_str!("tracker/pc_desktop_client.json");

/// Build the developer-facing-name → `TrackerValue` map once. The tracker
/// already uses prefixed names as keys (`DFIntS2PhysicsSenderRate`, etc.)
/// which matches the `display_name` the bare-key bridge classifies into,
/// so no further normalization is needed.
fn build_map() -> HashMap<&'static str, TrackerValue> {
    let parsed: serde_json::Value = match serde_json::from_str(TRACKER_JSON_PC_DESKTOP) {
        Ok(v) => v,
        Err(_) => return HashMap::new(),
    };
    let Some(object) = parsed.as_object() else {
        return HashMap::new();
    };

    let mut map: HashMap<&'static str, TrackerValue> = HashMap::with_capacity(object.len());
    for (key, value) in object {
        // Leak the key into a `&'static str`. The map is built exactly
        // once and lives for the entire process; the leak is bounded and
        // intentional (avoids cloning ~20k Strings per lookup).
        let key_static: &'static str = Box::leak(key.clone().into_boxed_str());

        let parsed_value = match value {
            serde_json::Value::Bool(b) => TrackerValue::Bool(*b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    if let Ok(i32_value) = i32::try_from(i) {
                        TrackerValue::Int(i32_value)
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            }
            serde_json::Value::String(s) => {
                // Some bool flags ship as quoted "true"/"false" strings
                // rather than JSON bools. Accept that form too.
                match s.as_str() {
                    "true" => TrackerValue::Bool(true),
                    "false" => TrackerValue::Bool(false),
                    _ => continue,
                }
            }
            _ => continue,
        };
        map.insert(key_static, parsed_value);
    }
    map
}

fn map_cached() -> &'static HashMap<&'static str, TrackerValue> {
    static CACHE: OnceLock<HashMap<&'static str, TrackerValue>> = OnceLock::new();
    CACHE.get_or_init(build_map)
}

/// Look up the tracker's recorded vanilla value for `prefixed_name` (the
/// developer-facing form: `DFIntS2PhysicsSenderRate`, `FFlagFoo`, …).
/// Returns `None` when the tracker does not know this flag (typical for
/// debug / internal flags Roblox doesn't expose publicly).
pub fn tracker_baseline_for_name(prefixed_name: &str) -> Option<TrackerValue> {
    map_cached().get(prefixed_name).copied()
}

/// Total number of flags currently bundled. Exposed for diagnostic /
/// telemetry reporting and unit tests.
pub fn bundled_entry_count() -> usize {
    map_cached().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_bundle_loads_and_is_non_trivial() {
        // The bundled JSON should parse and yield at least an order of
        // magnitude of entries. A trivial result usually means the file
        // was replaced with an empty or invalid JSON during refresh.
        let count = bundled_entry_count();
        assert!(
            count > 10_000,
            "tracker bundle should contain >10k flags, got {}",
            count
        );
    }

    #[test]
    fn tracker_finds_known_int_flag() {
        // Spot-check that a well-known int flag has the value we observed
        // in the tracker at integration time. If Roblox rolls this away
        // from 15, the test pin still catches the unexpected shift in our
        // bundle.
        assert_eq!(
            tracker_baseline_for_name("DFIntS2PhysicsSenderRate"),
            Some(TrackerValue::Int(15))
        );
    }

    #[test]
    fn tracker_finds_log_network_at_seven() {
        // `FLogNetwork = 7` is Roblox's publicly rolled-out value. Pin it
        // here so a future false-positive cheat-rule on this name (we had
        // one in v0.8.7) can be caught against the recorded vanilla.
        assert_eq!(
            tracker_baseline_for_name("FLogNetwork"),
            Some(TrackerValue::Int(7))
        );
    }

    #[test]
    fn tracker_returns_none_for_debug_only_flag() {
        // `DFIntRakNetLoopMs` is an internal flag Roblox does not expose
        // via `/v1/settings/application`. The tracker has no record of it.
        // This is the expected gap — debug-only flags continue to rely on
        // `RUNTIME_OVERRIDE_RULES` curation.
        assert_eq!(tracker_baseline_for_name("DFIntRakNetLoopMs"), None);
    }

    #[test]
    fn tracker_value_matches_live_i32_for_int() {
        // 15 as little-endian i32 bytes
        assert!(TrackerValue::Int(15).matches_live_i32([0x0F, 0x00, 0x00, 0x00]));
        assert!(!TrackerValue::Int(15).matches_live_i32([0x01, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn tracker_value_matches_live_i32_for_bool() {
        // bool true accepts any non-zero first byte
        assert!(TrackerValue::Bool(true).matches_live_i32([0x01, 0x00, 0x00, 0x00]));
        assert!(TrackerValue::Bool(true).matches_live_i32([0xFF, 0xAA, 0x55, 0x00]));
        // bool false requires first byte == 0; high bytes are ignored as
        // padding so an `int32 value 0` stored in a bool slot still
        // matches.
        assert!(TrackerValue::Bool(false).matches_live_i32([0x00, 0x00, 0x00, 0x00]));
        assert!(TrackerValue::Bool(false).matches_live_i32([0x00, 0xFF, 0xFF, 0xFF]));
        // mismatch
        assert!(!TrackerValue::Bool(false).matches_live_i32([0x01, 0x00, 0x00, 0x00]));
        assert!(!TrackerValue::Bool(true).matches_live_i32([0x00, 0x00, 0x00, 0x00]));
    }
}
