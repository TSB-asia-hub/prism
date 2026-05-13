/// Known cheat/injection tool process names (lowercase, token-boundary match).
///
/// Curation rules:
/// - Substrings must be specific enough to avoid false positives. `"ida"`
///   would match kindle/nvidia/mediaserver and was removed in favor of the
///   exact filename match `"ida64.exe"` in KNOWN_TOOL_FILENAMES.
/// - Do not add bare consumer-app words here. Names like "synapse", "wave",
///   "bolt", "comet", "electron", "velocity", and "delta" collide with
///   real hardware/software products and should only be represented by more
///   specific executable filenames or binary fingerprints.
/// - Wireshark is widely used by legitimate developers and is intentionally
///   excluded.
/// - Legitimate Roblox launchers are NOT listed here — see
///   KNOWN_BOOTSTRAPPER_PROCESS_NAMES below for the informational-tier list.
///   Voidstrap remains here because earlier scanner policy classified it as a
///   high-risk fork; do not generalize that to every Bloxstrap clone.
pub static KNOWN_PROCESS_NAMES: &[&str] = &[
    // Roblox-targeted FFlag tooling
    "voidstrap",
    "fflag injector",
    "fflagtoolkit",
    "lornobypass",
    "lorno bypass",
    "lornofix",
    "lorno fix",
    // Internal build-target name of LornoFix (see PDB path in binary)
    "odessa",
    "fflag-manager",
    // MxStrap — Python+pywebview GUI wrapper around a rebuilt fflag-manager
    // (odessa) binary. Distributed as Nuitka onefile + Inno Setup installer.
    // Auto-updates per-Roblox-release, which is why it works where Lorno
    // (stale offsets) doesn't.
    "mxstrap",
    "mx strap",
    "mxstrap client",
    // Wen Bootstrapper — Roblox-targeted FFlag cheat bootstrapper reported
    // in the wider ecosystem. Binary not yet on file for hashing/fingerprint;
    // name-only detection until samples are recovered.
    "wenbootstrapper",
    "wen bootstrapper",
    "wenstrap",
    // Roblox executors / DLL frameworks (2026 ecosystem)
    "krnl",
    "fluxus",
    "solara",
    "krampus",
    "valyse",
    "sirhurt",
    "jjsploit",
    "nezur",
    // "swift" was previously listed as a Roblox executor substring but it
    // matches a huge class of legitimate processes — SwiftTunnel (Apple's
    // Network Extension framework used by most macOS VPNs), Swift
    // Playgrounds, swiftformat, swift-build, and so on. Any standalone
    // Swift-branded Roblox tooling should ship with a more specific name
    // under KNOWN_TOOL_FILENAMES instead of a bare three-letter-ish
    // substring.
    "vega-x",
    "vegax",
    "macsploit",
    // Generic memory inspection / reverse engineering tools
    "cheatengine",
    "cheat engine",
    "x64dbg",
    "x32dbg",
    "processhacker",
    "process hacker",
    "systeminformer",
    "reclass",
    "reclass.net",
    "hxd",
    "extremeinjector",
    "extreme injector",
    "dll injector",
    "xenos",
    "gh injector",
    "process explorer",
    "ollydbg",
    "windbg",
    "immunity debugger",
    "pe-bear",
    "detect it easy",
    "cff explorer",
    "api monitor",
    "rohitab",
];

/// Known executable filenames for case-insensitive whole-name matching.
pub static KNOWN_TOOL_FILENAMES: &[&str] = &[
    "Voidstrap.exe",
    "Synapse X.exe",
    "Synapse Z.exe",
    "KRNL.exe",
    "Fluxus.exe",
    "Hydrogen.exe",
    "Solara.exe",
    "Krampus.exe",
    "Arceus X.exe",
    "Delta Executor.exe",
    "Trigon Evo.exe",
    "Valyse.exe",
    "SirHurt.exe",
    "JJSploit.exe",
    "Nezur.exe",
    "VegaX.exe",
    "Vega-X.exe",
    "MacSploit.exe",
    "CheatEngine.exe",
    "cheatengine-x86_64.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "ProcessHacker.exe",
    "SystemInformer.exe",
    "ReClass.NET.exe",
    "HxD.exe",
    "ExtremeInjector.exe",
    "Xenos64.exe",
    "Xenos.exe",
    "GH Injector.exe",
    "ida.exe",
    "ida64.exe",
    "RobloxOffsetDumper.exe",
    "offset_dumper.exe",
    "fflag_injector.exe",
    "fflag-manager.exe",
    "LornoBypass.exe",
    "LornoFix.exe",
    "Lorno Fix.exe",
    "odessa.exe",
    // MxStrap — Python+pywebview GUI front-end that bundles a rebuilt
    // fflag-manager (odessa) binary as `session.exe` inside a Nuitka onefile
    // archive. The wrapper exe varies by version; the version suffix is
    // matched at the directory level (`MxStrap`) and via SHA-256 entries.
    "MxStrap.exe",
    "MxStrap_v1.0.10.exe",
    "MxStrap_Setup_v1.0.10.exe",
    "MxStrap_UpdateChecker.exe",
    // Wen Bootstrapper — Roblox FFlag cheat bootstrapper.
    "WenBootstrapper.exe",
    "Wen Bootstrapper.exe",
    "WenStrap.exe",
];

/// Directory names for Roblox-specific FFlag injection / bypass tools. These
/// have no legitimate non-cheat use and warrant a Suspicious verdict.
pub static ROBLOX_CHEAT_DIRS: &[&str] = &[
    "Voidstrap",
    "ExtremeInjector",
    "FFlagToolkit",
    "LornoBypass",
    "fflag-manager",
    "MxStrap",
    "WenBootstrapper",
];

/// Directory names for generic reverse-engineering / debugging tools. These
/// have well-known legitimate uses (CTF, malware analysis, driver debugging,
/// security research) and firing Suspicious on presence alone punishes the
/// entire security community. Recorded as Clean informational notes only.
pub static GENERIC_RE_TOOL_DIRS: &[&str] = &[
    "CheatEngine",
    "Cheat Engine",
    "x64dbg",
    "ProcessHacker",
    "SystemInformer",
    "ReClass.NET",
    "HxD",
];

// Legacy `KNOWN_TOOL_DIRS` constant removed — use `ROBLOX_CHEAT_DIRS` (emit
// Suspicious) or `GENERIC_RE_TOOL_DIRS` (emit Clean informational) directly
// so each call site picks the right severity explicitly.

/// Known tool executable SHA-256 hashes (lowercase hex). Matched even when the
/// binary has been renamed. Keep this list to cross-platform artefacts the
/// scanner is expected to catch in Downloads/Desktop/Documents.
///
/// Entries: (sha256_lowercase_hex, display_name, note).
pub static KNOWN_TOOL_HASHES: &[(&str, &str, &str)] = &[
    (
        "37cfcd6bf1d3001f95229c76e84709efc4fad822babe8e6e7631912cf2027648",
        "LornoFix.exe",
        "LornoBypass FFlag injector (odessa/fflag-manager build) — writes flags to RobloxPlayerBeta via WriteProcessMemory",
    ),
    (
        "ffaae0bf82a93f662071a76c0165f258db99bae2bfc816e18ebb3e1277a0e3bc",
        "LornoBypass.zip",
        "Distribution archive for the LornoBypass FFlag injector",
    ),
    // MxStrap v1.0.10 — Python+pywebview GUI wrapper. Auto-updates frequently,
    // so this hash will drift; the directory and process-name signals are more
    // durable. Kept here so the current build is identifiable when seen on
    // disk independently of the install dir.
    (
        "e2cf1c954d8165cf45995a7250f2ee263fa4e471c57af9048b0a02e795dfb7f2",
        "MxStrap_v1.0.10.exe",
        "MxStrap FFlag-injector GUI — Nuitka onefile bundle wrapping a rebuilt fflag-manager (odessa) session.exe",
    ),
    (
        "1aca66cbfae55b1d46479794f2a7987d4c8eea66d9ef3390d4ba3847c115ed44",
        "MxStrap_Setup_v1.0.10.exe",
        "Inno Setup installer for MxStrap; registers HKLM\\...\\Uninstall\\MxStrap Client_is1",
    ),
    (
        "c239e8deaf6c96c10c666c7cd7bca74c19148affcd6906a20a7936152c64bec5",
        "MxStrap_UpdateChecker.exe",
        "MxStrap auto-update component — fetches new offsets per Roblox release, which is why MxStrap works on builds where stale LornoFix fails",
    ),
    (
        "e18e07129ccad150b29a5fb0e03a90a4bbb7333e66111b8bab3c11100b0285b1",
        "session.exe",
        "fflag-manager/odessa rebuild bundled inside MxStrap's Nuitka archive (1106 strings identical to LornoFix except PDB path)",
    ),
];

/// Filenames that, when co-located with a PE executable, indicate that the PE
/// is almost certainly an FFlag injector. LornoFix ships `fflags.json` (the
/// flags to inject) plus `address.json` (the cached singleton offset) next to
/// the binary; the combination is a strong signal even without a hash match.
pub static INJECTOR_SIBLING_CONFIG_FILES: &[&str] = &["fflags.json", "address.json"];

/// A content-based fingerprint for a known tool binary. Scanner reads the
/// candidate PE bytes and reports a Flagged match iff *every* byte string in
/// `required_markers` appears somewhere in the file.
///
/// This catches binaries that have been renamed (filename match misses) AND
/// recompiled (SHA-256 match misses), as long as the source-tree string
/// literals or build paths are preserved — which is the common case for
/// hobbyist cheat tools that just re-link.
///
/// Picking markers: each must be specific enough that an unrelated PE in
/// Downloads/Desktop is essentially zero risk of containing it. Combine
/// multiple markers with AND for defense-in-depth.
pub struct BinaryFingerprint {
    pub display_name: &'static str,
    pub note: &'static str,
    pub required_markers: &'static [EncodedMarker],
}

/// A binary marker stored in encoded form so Prism's own release executable
/// does not contain the exact byte signatures it scans other binaries for.
pub struct EncodedMarker {
    pub bytes: &'static [u8],
    pub xor_key: u8,
}

impl EncodedMarker {
    pub fn decode(&self) -> Vec<u8> {
        self.bytes.iter().map(|byte| byte ^ self.xor_key).collect()
    }
}

/// Content fingerprints for known tools. Strings drawn from the recovered
/// source tree at `artifacts/lorno-reversed/`; see `meta/call_graph.txt`
/// for provenance.
pub static KNOWN_TOOL_BINARY_FINGERPRINTS: &[BinaryFingerprint] = &[
    BinaryFingerprint {
        display_name: "LornoFix.exe",
        note:
            "LornoBypass FFlag injector — internal log strings match (odessa/fflag-manager source)",
        required_markers: &[
            // Three Lorno-specific log strings emitted by find_singleton and
            // the flag-application loop. All three together are unique to
            // this codebase.
            EncodedMarker {
                bytes: &[
                    0xc3, 0xca, 0xd0, 0xcb, 0xc1, 0x85, 0xd6, 0xcc, 0xcb, 0xc2, 0xc9, 0xc0, 0xd1,
                    0xca, 0xcb, 0x85, 0xfe, 0xc6, 0xc4, 0xc6, 0xcd, 0xc0, 0xc1, 0xf8,
                ],
                xor_key: 0xa5,
            },
            EncodedMarker {
                bytes: &[
                    0xc3, 0xca, 0xd0, 0xcb, 0xc1, 0x85, 0xd6, 0xcc, 0xcb, 0xc2, 0xc9, 0xc0, 0xd1,
                    0xca, 0xcb, 0x85, 0xfe, 0xd5, 0xc4, 0xd1, 0xd1, 0xc0, 0xd7, 0xcb, 0xf8,
                ],
                xor_key: 0xa5,
            },
            EncodedMarker {
                bytes: &[
                    0xc3, 0xc3, 0xc9, 0xc4, 0xc2, 0x85, 0xfe, 0xde, 0xd8, 0xf8, 0x85, 0xcd, 0xc4,
                    0xd6, 0x85, 0xd0, 0xcb, 0xd7, 0xc0, 0xc2, 0xcc, 0xd6, 0xd1, 0xc0, 0xd7, 0xc0,
                    0xc1, 0x85, 0xc2, 0xc0, 0xd1, 0xd6, 0xc0, 0xd1, 0x89, 0x85, 0xd6, 0xce, 0xcc,
                    0xd5, 0xd5, 0xcc, 0xcb, 0xc2,
                ],
                xor_key: 0xa5,
            },
        ],
    },
    BinaryFingerprint {
        display_name: "LornoFix.exe",
        note: "LornoBypass FFlag injector — leaked PDB path from MSVC release build",
        required_markers: &[
            // The PDB path embedded in the Debug Directory of MSVC release
            // builds. Survives string-stripping because it's in a header.
            // Two slightly different substrings to handle path-separator
            // and trailing-component variation across rebuilds.
            EncodedMarker {
                bytes: &[
                    0xf9, 0xc3, 0xc3, 0xc9, 0xc4, 0xc2, 0x88, 0xc8, 0xc4, 0xcb, 0xc4, 0xc2, 0xc0,
                    0xd7, 0xf9, 0xc7, 0xc9, 0xc1, 0xf9, 0xd7, 0xc0, 0xc9, 0xc0, 0xc4, 0xd6, 0xc0,
                    0xf9, 0xc7, 0xcc, 0xcb, 0xf9, 0xca, 0xc1, 0xc0, 0xd6, 0xd6, 0xc4, 0x8b, 0xd5,
                    0xc1, 0xc7,
                ],
                xor_key: 0xa5,
            },
        ],
    },
];

/// Legitimate or bootstrapper-style Roblox launchers — these are NOT cheat
/// tools per Roblox's own policy (https://devforum.roblox.com/t/3640609).
/// Their presence is recorded for context but should not raise verdict
/// severity on its own. Use exact-ish project tokens only; never add generic
/// words such as "strap", "launcher", "bolt", "wave", etc.
pub static KNOWN_BOOTSTRAPPER_PROCESS_NAMES: &[&str] = &[
    "bloxstrap",
    "fishstrap",
    "froststrap",
    "bubblestrap",
    "lunastrap",
    "luczystrap",
    "appleblox",
    "chevstrap",
    "droidblox",
    "lucem",
    "lution",
    "velostrap",
    "homiestrap",
    "bloxstrap-plus",
    "bloxstrapplus",
    "bloxstrapplusplus",
    "novastrap",
    "funkstrap",
    "sharkstrap",
    "neostrap",
    "nightstrap",
    "aquastrap",
    "veloxstrap",
    "supertrap",
    "johnstrap",
    "femboystrap",
    "gothstrap",
    "polystrap",
    "wolftrap",
    "voltstrap",
    "edustrap",
    "starstrap",
    "snowfallstrap",
    "vistrap",
    "betterblox",
    "limestrap",
    "aesthstrap",
    "kurostrap",
    "lumistrap",
    "baconstrap",
    "urbanstrap",
    "purplestrap",
    "sunstrap",
    "segualstrap",
    "bozstrap",
    "abyssion",
    "hoodtrap",
    "laserstrap",
    "slowstrap",
    "griffinstrap",
    "hyperstrap",
    "pulsex",
    "nullstrap",
    "hellstrap",
    "dapblox",
    "foxstrap",
    "redstrap",
    "namanstrap",
    "drstrap",
    "abethos",
    "singularity",
    "primestraps",
    "darkstrap",
];

/// Directory names created by Bloxstrap-family bootstrappers — informational
/// only. This includes public clones and one explicit "Homiestrap" watch-name:
/// no public repo/download was verified for it, but an exact directory match
/// is useful low-risk context if a private/off-GitHub build exists.
pub static KNOWN_BOOTSTRAPPER_DIRS: &[&str] = &[
    // Major/publicly-verifiable projects.
    "Bloxstrap",
    "Fishstrap",
    "Froststrap",
    "Bubblestrap",
    "Lunastrap",
    "Luczystrap",
    "AppleBlox",
    "Chevstrap",
    "DroidBlox",
    "lucem",
    "Lution",
    "VeloStrap",
    "Velostrap",
    "Homiestrap",
    // Public direct/second-level Bloxstrap-family clones observed in the
    // May 2026 research pass. Exact directory-name matches only.
    "Bloxstrap-Plus",
    "BloxstrapPlus",
    "BloxStrapPlusPlus",
    "Novastrap",
    "Funkstrap",
    "Sharkstrap",
    "Neostrap",
    "Nightstrap",
    "AquaStrap",
    "Veloxstrap",
    "SuperTrap",
    "JOHNstrap",
    "FemboyStrap",
    "gothstrap",
    "Polystrap",
    "PolyStrap",
    "7blox",
    "Wolftrap",
    "VoltStrap",
    "edustrap",
    "StarStrap",
    "Snowfallstrap",
    "LuczyStrap",
    "Vistrap",
    "Betterblox",
    "Limestrap",
    "Aesthstrap",
    "Kurostrap",
    "Lumistrap",
    "Baconstrap",
    "Urbanstrap",
    "Orbit-Launcher",
    "Orbit Launcher",
    "Purplestrap",
    "Sunstrap",
    "Segualstrap",
    "Bozstrap",
    "Simple-Client",
    "Abyssion",
    "Hoodtrap",
    "LaserStrap",
    "Slowstrap",
    "GriffinStrap",
    "HyperStrap",
    "PulseX",
    "Nullstrap",
    "Hellstrap",
    "Dapblox",
    "FoxStrap",
    "FoxStrapV2",
    "Redstrap",
    "Namanstrap",
    "Drstrap",
    "Abethos",
    "Singularity",
    "Primestraps",
    "Darkstrap",
];

/// Exact executable filenames for bootstrapper-family launchers/installers.
/// Informational only; these are not fed into Prefetch Suspicious matching.
pub static KNOWN_BOOTSTRAPPER_FILENAMES: &[&str] = &[
    "Bloxstrap.exe",
    "Fishstrap.exe",
    "Froststrap.exe",
    "Bubblestrap.exe",
    "Lunastrap.exe",
    "Luczystrap.exe",
    "AppleBlox.exe",
    "Chevstrap.exe",
    "DroidBlox.exe",
    "lucem.exe",
    "Lution.exe",
    "VeloStrap.exe",
    "Velostrap.exe",
    "Homiestrap.exe",
    "Bloxstrap-Plus.exe",
    "BloxstrapPlus.exe",
    "BloxStrapPlusPlus.exe",
    "Novastrap.exe",
    "Funkstrap.exe",
    "Sharkstrap.exe",
    "Neostrap.exe",
    "Nightstrap.exe",
    "AquaStrap.exe",
    "Veloxstrap.exe",
    "SuperTrap.exe",
    "JOHNstrap.exe",
    "FemboyStrap.exe",
    "gothstrap.exe",
    "Polystrap.exe",
    "PolyStrap.exe",
    "7blox.exe",
    "Wolftrap.exe",
    "VoltStrap.exe",
    "edustrap.exe",
    "StarStrap.exe",
    "Snowfallstrap.exe",
    "Vistrap.exe",
    "Betterblox.exe",
    "Limestrap.exe",
    "Aesthstrap.exe",
    "Kurostrap.exe",
    "Lumistrap.exe",
    "Baconstrap.exe",
    "Urbanstrap.exe",
    "Orbit-Launcher.exe",
    "Orbit Launcher.exe",
    "Purplestrap.exe",
    "Sunstrap.exe",
    "Segualstrap.exe",
    "Bozstrap.exe",
    "Simple-Client.exe",
    "Abyssion.exe",
    "Hoodtrap.exe",
    "LaserStrap.exe",
    "Slowstrap.exe",
    "GriffinStrap.exe",
    "HyperStrap.exe",
    "PulseX.exe",
    "Nullstrap.exe",
    "Hellstrap.exe",
    "Dapblox.exe",
    "FoxStrap.exe",
    "FoxStrapV2.exe",
    "Redstrap.exe",
    "Namanstrap.exe",
    "Drstrap.exe",
    "Abethos.exe",
    "Singularity.exe",
    "Primestraps.exe",
    "Darkstrap.exe",
];

/// Windows Bloxstrap-family config roots. The first string is the display
/// name, the second is the exact directory name under LOCALAPPDATA/APPDATA.
pub static WINDOWS_BOOTSTRAPPER_CONFIG_DIRS: &[(&str, &str)] = &[
    ("Bloxstrap", "Bloxstrap"),
    ("Fishstrap", "Fishstrap"),
    ("Froststrap", "Froststrap"),
    ("Bubblestrap", "Bubblestrap"),
    ("Lunastrap", "Lunastrap"),
    ("Luczystrap", "Luczystrap"),
    ("Homiestrap", "Homiestrap"),
    ("Voidstrap", "Voidstrap"),
    ("Novastrap", "Novastrap"),
    ("VeloStrap", "VeloStrap"),
    ("Velostrap", "Velostrap"),
];
