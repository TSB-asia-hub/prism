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

/// Memory-scan baseline: flag names whose mere presence in Roblox process
/// memory is known-not-interesting and should be suppressed from findings.
///
/// Roblox loads its entire FFlag registry (~20k names) into heap at startup.
/// The mere presence of any of these names as a string in heap is therefore
/// evidence of nothing — Roblox itself put them there. This list covers
/// Roblox-shipped A/B rollout, telemetry, UI modernization, and rendering
/// rollout flags that would otherwise fire on every vanilla client.
///
/// Only the memory scanner consults this list. If any of these names appear
/// in a local ClientAppSettings.json or bootstrapper config with a non-
/// default value, the client_settings scanner still flags them at full
/// severity — actively writing the value is a real override regardless of
/// how common the name is in heap.
///
/// DFIntS2PhysicsSenderRate is deliberately NOT on this list (see the test
/// `canonical_desync_flag_stays_at_full_severity`): it is the canonical
/// memory-only desync override and must retain its Flagged severity.
///
/// v0.5.2 note: the memory scanner no longer consults this list because
/// the name-matching emission was retired (see the findings_from_table
/// docstring in scanners/memory_scanner.rs). The list is retained so
/// future scanners that DO want a known-benign baseline can reuse it,
/// and so the pin tests below keep documenting which names Roblox
/// itself ships.
#[allow(dead_code)]
pub static MEMORY_BASELINE_FLAGS: &[&str] = &[
    // ---- Chrome in-game menu rollout (shipped default on modern clients) ----
    "FFlagEnableInGameMenuChromeABTest2",
    "FFlagEnableInGameMenuChromeABTest4",
    "FFlagEnableIngameMenuChrome",
    "FFlagEnableInGameMenuSongbirdABTest",
    "FFlagEnableChromePinnedChat",
    // ---- Beta badges / cosmetic UI A-B (no gameplay effect) ----
    "FFlagVoiceBetaBadge",
    "FFlagTopBarUseNewBadge",
    "FFlagEnableBetaBadgeLearnMore",
    "FFlagBetaBadgeLearnMoreLinkFormview",
    "FFlagControlBetaBadgeWithGuac",
    "FFlagCoreGuiTypeSelfViewPresent",
    // ---- Roblox-side network rollout toggles (server-controlled) ----
    "FFlagOptimizeNetwork",
    "FFlagOptimizeNetworkRouting",
    "FFlagOptimizeNetworkTransport",
    "FFlagOptimizeServerTickRate",
    // ---- Shipped FPS-cap feature (not an uncap) ----
    "FFlagGameBasicSettingsFramerateCap",
    "FFlagGameBasicSettingsFramerateCap5",
    "FFlagTaskSchedulerLimitTargetFpsTo2402",
    // ---- Shipped rendering feature flags (not cheats on their own) ----
    "FFlagGlobalWindRendering",
    "FFlagGlobalWindActivated",
    "FFlagRenderFixFog",
    "FFlagRenderFixGrassPrepass",
    "FFlagUnifiedLightingBetaFeature",
    "FFlagRenderUnifiedLighting6",
    "FFlagFastGPULightCulling3",
    "FFlagNewLightAttenuation",
    "FFlagRenderNoLowFrmBloom",
    // ---- Bug-fix toggles named "Fix*" (not disable-fix toggles) ----
    "FFlagCommitToGraphicsQualityFix",
    "FFlagFixGraphicsQuality",
    // ---- Built-in user-facing features (Shift-F5 FPS, quick launch, …) ----
    "FFlagDebugDisplayFPS",
    "FFlagEnableQuickGameLaunch",
    "FFlagEnableCommandAutocomplete",
    "FFlagEnableBubbleChatFromChatService",
    // ---- Shipped GUI-hide accessibility API ----
    "FFlagUserShowGuiHideToggles",
    "FFlagGuiHidingApiSupport2",
    "DFIntCanHideGuiGroupId",
    // ---- Server-controlled reconnect kill-switches (client value ignored) ----
    "FFlagReconnectDisabled",
    "FStringReconnectDisabledReason",
    // ---- UIBlox theming (Lua app chrome) ----
    "FFlagLuaAppUseUIBloxColorPalettes1",
    "FFlagUIBloxUseNewThemeColorPalettes",
    // ---- Engine-internal render threading assertions ----
    "FFlagDebugCheckRenderThreading",
    "FFlagRenderDebugCheckThreading2",
    "FFlagRenderCheckThreading",
    "FFlagDebugRenderingSetDeterministic",
    // ---- Ad service toggle (privacy choice, not a cheat) ----
    "FFlagAdServiceEnabled",
    // ---- Telemetry / logging verbosity ----
    "FLogNetwork",
    // ---- Engine-internal debug overlays (developer tools, not ESP) ----
    "FFlagDebugDisplayUnthemedInstances",
    "FFlagDebugLightGridShowChunks",
    "FFlagTrackerLodControllerDebugUI",
    // ---- Internal migration/patching scaffolding ----
    "FFlagDataModelPatcherForceLocal",
    "FFlagRefactorPlayerConnect",
    "FFlagDebugLocalRccServerConnection",
    // ---- Animation system corrections ----
    "FFlagQuaternionPoseCorrection",
    "FFlagRigScaleShouldAffectAnimations",
    // ---- Reporting flow rollout ----
    "FFlagEnableReportAbuseMenuRoactABTest2",
];

/// Historically held "ambiguous" TSB-community flag names that fired
/// Suspicious in memory. v0.5.1 retired the soft-findings concept: the
/// memory scanner cannot distinguish "Roblox's runtime loaded this name
/// into its registry" from "an injector wrote this override" at the NAME
/// level (only VALUES would differ, and the memory scanner does not
/// capture adjacent values). Every entry that used to live here now lives
/// in MEMORY_BASELINE_FLAGS and is silenced from the memory scan.
///
/// ClientSettings scanning remains the authoritative path: if a user
/// actually writes an override into ClientAppSettings.json or a
/// bootstrapper config, the client_settings scanner flags the value at
/// full CRITICAL/HIGH/MEDIUM severity.
///
/// The canonical memory-only exception is `DFIntS2PhysicsSenderRate`,
/// which stays off both lists so the memory scanner can still catch the
/// classic desync injector family that writes directly via
/// WriteProcessMemory. See the pin test below.
#[allow(dead_code)]
pub static MEMORY_SOFT_FINDINGS: &[&str] = &[];

/// True if this flag name is an ambiguous TSB-community memory finding
/// whose severity should be capped at Suspicious when seen in memory.
/// Retained for the retirement pin test — the memory scanner itself no
/// longer consults this list, see the value-proximity gate in
/// `scanners::memory_scanner::findings_from_table`.
#[allow(dead_code)]
pub fn is_memory_soft_finding(flag_name: &str) -> bool {
    MEMORY_SOFT_FINDINGS.iter().any(|&f| f == flag_name)
}

/// True if this flag name is a memory-scanner baseline — i.e. its presence
/// in process memory is not on its own suspicious. Retained for tests and
/// future reuse; the memory scanner itself no longer consults this list
/// (v0.5.2 retired the flag-name emission path).
#[allow(dead_code)]
pub fn is_memory_baseline_flag(flag_name: &str) -> bool {
    MEMORY_BASELINE_FLAGS.iter().any(|&f| f == flag_name)
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
    fn memory_baseline_covers_known_roblox_shipped_names() {
        // The baseline silences flag names Roblox itself loads into process
        // heap via its runtime flag registry. Without these entries the
        // memory scanner would fire Suspicious/Flagged findings on every
        // vanilla client that has the registry resident (which is every
        // live client, per memory_scanner.rs:582-588). Pin the canonical
        // samples so a cleanup cannot accidentally re-empty the list.
        assert!(is_memory_baseline_flag("FFlagAdServiceEnabled"));
        assert!(is_memory_baseline_flag("FFlagTopBarUseNewBadge"));
        assert!(is_memory_baseline_flag(
            "FFlagEnableInGameMenuChromeABTest4"
        ));
        assert!(is_memory_baseline_flag("FFlagUnifiedLightingBetaFeature"));
        assert!(is_memory_baseline_flag(
            "FFlagGameBasicSettingsFramerateCap5"
        ));
        assert!(is_memory_baseline_flag("FLogNetwork"));
        assert!(is_memory_baseline_flag("FFlagRenderFixFog"));
        assert!(is_memory_baseline_flag("FFlagDebugDisplayFPS"));
    }

    #[test]
    fn memory_soft_findings_is_retired() {
        // The soft-findings concept was retired in v0.5.1 because the
        // memory scanner cannot distinguish runtime-registry presence from
        // injector presence at the name level. Baseline silences; the
        // canonical desync flag remains off both lists.
        assert!(MEMORY_SOFT_FINDINGS.is_empty());
    }

    #[test]
    fn engine_default_names_are_not_blanket_silenced() {
        // v0.5.2 reverses the v0.5.1 blanket silence on physics/engine
        // names: the memory scanner now requires value-proximity evidence
        // before emitting, which kills the FP without dropping the ability
        // to detect real memory-only injections. Keep these names OFF the
        // baseline so a value-carrying override still surfaces.
        for &name in [
            "DFIntBulletContactBreakOrthogonalThresholdPercent",
            "DFIntMinimalSimRadiusBuffer",
            "FFlagSimAdaptiveTimesteppingDefault2",
            "FIntCameraFarZPlane",
        ]
        .iter()
        {
            assert!(
                !is_memory_baseline_flag(name),
                "{} must be detectable (with value) — not on baseline",
                name
            );
        }
    }

    #[test]
    fn canonical_desync_flag_stays_at_full_severity() {
        // Non-negotiable: DFIntS2PhysicsSenderRate is the #1 desync /
        // fake-lag override. It must never be silenced (baseline) AND
        // must not be downgraded to Suspicious (soft findings) — keep it
        // out of both lists so memory-only injectors (LornoFix class) are
        // still surfaced at Flagged severity.
        assert!(!MEMORY_BASELINE_FLAGS.contains(&"DFIntS2PhysicsSenderRate"));
        assert!(!is_memory_soft_finding("DFIntS2PhysicsSenderRate"));
    }

    #[test]
    fn memory_soft_findings_do_not_leak_into_official_allowlist() {
        // Never overlap: a flag on Roblox's official allowlist is not a
        // finding at all, so it should never also appear in the soft
        // list.
        for &soft in MEMORY_SOFT_FINDINGS {
            assert!(
                !is_allowed_flag(soft),
                "{} is on Roblox's official allowlist; remove from MEMORY_SOFT_FINDINGS",
                soft
            );
        }
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
