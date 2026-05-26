/// The 18 officially allowed FFlags from Roblox's September 29, 2025
/// announcement (https://devforum.roblox.com/t/3966569).
///
/// Cross-checked against the LeventGameing/allowlist community mirror.
/// LAST_VERIFIED: 2026-04-20. If you change anything here, update that
/// date and re-pull from the source.
pub static ALLOWED_FLAGS: &[&str] = &[
    // Geometry / CSG LOD (4 flags) — these use the DFInt prefix; the
    // earlier draft of this file had FInt, which would have allowed the
    // wrong flag name and silently flagged the real one.
    "DFIntCSGLevelOfDetailSwitchingDistance",
    "DFIntCSGLevelOfDetailSwitchingDistanceL12",
    "DFIntCSGLevelOfDetailSwitchingDistanceL23",
    "DFIntCSGLevelOfDetailSwitchingDistanceL34",
    // Rendering (13 flags)
    "DFFlagTextureQualityOverrideEnabled",
    "DFIntTextureQualityOverride",
    "FIntDebugForceMSAASamples",
    "DFFlagDisableDPIScale",
    "FFlagDebugSkyGray",
    "DFFlagDebugPauseVoxelizer",
    "FFlagDebugGraphicsPreferD3D11",
    "FFlagDebugGraphicsPreferVulkan",
    "FFlagDebugGraphicsPreferOpenGL",
    "DFIntDebugFRMQualityLevelOverride",
    "FIntFRMMinGrassDistance",
    "FIntFRMMaxGrassDistance",
    "FIntGrassMovementReducedMotionFactor",
    // UI / Misc (1 flag)
    "FFlagHandleAltEnterFullscreenManually",
];

/// Check if a given flag name is in the official allowlist.
pub fn is_allowed_flag(flag_name: &str) -> bool {
    ALLOWED_FLAGS.iter().any(|&f| f == flag_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_size_matches_official_announcement() {
        assert_eq!(
            ALLOWED_FLAGS.len(),
            18,
            "Roblox's September 2025 allowlist published 18 flags; if Roblox \
             updates the list, change this assertion intentionally and bump \
             the LAST_VERIFIED date in the doc comment."
        );
    }

    #[test]
    fn csg_lod_flags_use_dfint_prefix() {
        // The earlier draft used FInt — wrong prefix means real CSG flag
        // settings escape the allowlist short-circuit and get flagged.
        assert!(is_allowed_flag("DFIntCSGLevelOfDetailSwitchingDistance"));
        assert!(!is_allowed_flag("FIntCSGLevelOfDetailSwitchingDistance"));
    }

    #[test]
    fn known_real_flag_names_are_allowed() {
        for name in [
            "DFFlagTextureQualityOverrideEnabled",
            "FIntDebugForceMSAASamples",
            "FFlagDebugGraphicsPreferOpenGL",
            "FIntGrassMovementReducedMotionFactor",
            "FFlagHandleAltEnterFullscreenManually",
        ] {
            assert!(is_allowed_flag(name), "{} must be allowed", name);
        }
    }
}
