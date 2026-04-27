use crate::models::ScanVerdict;

// =============================================================================
// CRITICAL FLAGS: Desync / Physics / Replication manipulation
// These flags give direct competitive advantage through physics desync,
// teleportation, invisibility, noclip, or simulation radius abuse.
// Sources: Roblox DevForum bug reports, pixelyloaf abusive flags,
// alexbomb6666/rblxflags, fantaize.net desync analysis, community repos.
// =============================================================================
pub static CRITICAL_FLAGS: &[&str] = &[
    // ---- Physics sender rate manipulation (desync / fake-lag) ----
    // Controls how often physics data is sent to server. Value 1 = freeze
    // server-side position; -30 = lock to origin (invisible).
    "DFIntS2PhysicsSenderRate",
    // Typo variant that also appears in community configs
    "DFIntS2PhysicSenderRate",
    // Bandwidth cap for physics replication; 1 = starve server of updates
    "DFIntPhysicsSenderMaxBandwidthBps",
    // Scaling factor for physics sender bandwidth
    "DFIntPhysicsSenderMaxBandwidthBpsScaling",
    // Data sender rate; -1 = block all data replication
    "DFIntDataSenderRate",
    // Touch sender bandwidth; -1 = block touch replication
    "DFIntTouchSenderMaxBandwidthBps",
    // ---- Simulation radius expansion (network ownership theft) ----
    // Expanding sim radius lets client claim ownership of remote parts
    "DFIntMinClientSimulationRadius",
    "DFIntMinimalSimRadiusBuffer",
    "DFIntMaxClientSimulationRadius",
    // Prevent sim radius from shrinking back
    "DFFlagDebugPhysicsSenderDoesNotShrinkSimRadius",
    // Force custom sim radius
    "FFlagDebugUseCustomSimRadius",
    // ---- NextGen Replicator / Aurora desync (invisibility exploit) ----
    // Toggling these breaks character replication on other clients
    "NextGenReplicatorEnabledWrite4",
    "NextGenReplicatorEnabledRead",
    // Large replicator variants used in desync chains
    "LargeReplicatorEnabled9",
    "LargeReplicatorSerializeWrite4",
    "LargeReplicatorSerializeRead3",
    "LargeReplicatorWrite5",
    "LargeReplicatorRead5",
    // Replicator-related network manipulation
    "DFIntReplicatorClusterPacketLimit",
    "DFIntReplicatorWritePacketLimit",
    // ---- Replicator animation track limit (animation desync) ----
    // -1 = disable animation replication; others see no movement
    "DFIntReplicatorAnimationTrackLimitPerAnimator",
    // ---- Game network PV header manipulation (invisibility) ----
    // High exponent zeros out position/velocity headers
    "DFIntGameNetPVHeaderTranslationZeroCutoffExponent",
    "DFIntGameNetPVHeaderLinearVelocityZeroCutoffExponent",
    "DFIntGameNetPVHeaderRotationalVelocityZeroCutoffExponent",
    // ---- Noclip / collision bypass ----
    // Shrinks assembly collision extents; negative = pass through walls
    "DFIntAssemblyExtentsExpansionStudHundredth",
    // Limits broad-phase collision pair count; low value = noclip
    "DFIntSimBroadPhasePairCountMax",
    // Primal solver manipulation for noclip/physics bypass
    "FFlagDebugSimDefaultPrimalSolver",
    "DFIntDebugSimPrimalStiffness",
    "DFIntMaximumFreefallMoveTimeInTenths",
    // ---- Physics engine gravity / force manipulation ----
    // Extreme values cause flying, super-jump, moon gravity
    "DFIntSimAdaptiveHumanoidPDControllerSubstepMultiplier",
    "DFIntSolidFloorPercentForceApplication",
    "DFIntNonSolidFloorPercentForceApplication",
    "DFIntNewRunningBaseGravityReductionFactorHundredth",
    "DFIntMaxAltitudePDStickHipHeightPercent",
    "DFIntMaximumUnstickForceInGs",
    "DFIntUnstickForceAttackInTenths",
    "DFIntPhysicsDecompForceUpgradeVersion",
    // ---- Simulation timestep manipulation ----
    "FFlagSimAdaptiveTimesteppingDefault2",
    "DFFlagSimHumanoidTimestepModelUpdate",
    "DFIntSimExplicitlyCappedTimestepMultiplier",
    "DFIntMaxTimestepMultiplierAcceleration",
    "DFIntMaxTimestepMultiplierBuoyancy",
    "DFIntMaxTimestepMultiplierConstraint",
    "DFIntTimestepArbiterVelocityCriteriaThresholdTwoDt",
    "DFIntTimestepArbiterHumanoidTurningVelThreshold",
    "DFIntTimestepArbiterOmegaThou",
    // ---- Primal solver gravity / flight exploits ----
    "DFIntDebugSimPrimalLineSearch",
    "DFIntDebugSimPrimalPreconditioner",
    "DFIntDebugSimPrimalNewtonIts",
    "DFIntDebugSimPrimalWarmstartVelocity",
    "DFIntDebugSimPrimalWarmstartForce",
    "FFlagDebugSimPrimalGSLump",
    "FIntDebugSimPrimalGSLumpAlpha",
    // ---- Bullet / contact threshold manipulation ----
    "DFIntBulletContactBreakOrthogonalThresholdPercent",
    "DFIntBulletContactBreakThresholdPercent",
    // ---- Tool desync ----
    "DFIntSimBlockLargeLocalToolWeldManipulationsThreshold",
    // ---- Hip height / animation exploits ----
    "DFIntHipHeightClamp",
    "FFlagRemapAnimationR6ToR15Rig",
    "DFFlagAnimatorPostProcessIK",
    // ---- Physics throttle bypass ----
    "DFIntPhysicsImprovedCyclicExecutiveThrottleThresholdTenth",
    "DFFlagPhysicsSkipNonRealTimeHumanoidForceCalc2",
    // ---- Game network local space manipulation ----
    "DFIntGameNetLocalSpaceMaxSendIndex",
    // ---- Parallel dynamics manipulation ----
    // -1 = invisibility through broken cluster batching
    "FIntParallelDynamicPartsFastClusterBatchSize",
    // ---- Raycast distance manipulation ----
    // Very low = break hit detection; very high = server-side advantage
    "DFIntRaycastMaxDistance",
    // ---- World step / missed step manipulation ----
    "DFIntMaxMissedWorldStepsRemembered",
    "DFIntWorldStepMax",
    "DFIntDebugDefaultTargetWorldStepsPerFrame",
    // ---- Data packet / bandwidth manipulation ----
    "DFIntMaxDataPacketPerSend",
    "DFIntServerMaxBandwidth",
    "DFIntAngularVelocityLimit",
    // ---- Max active animation tracks (animation freeze) ----
    "DFIntMaxActiveAnimationTracks",
    "FFlagProcessAnimationLooped",
    // ---- Interpolation manipulation (desync-adjacent) ----
    "DFIntInterpolationFrameVelocityThresholdMillionth",
    "DFIntInterpolationFrameRotVelocityThresholdMillionth",
    "DFIntInterpolationFramePositionThresholdMillionth",
    "DFIntCheckPVDifferencesForInterpolationMinVelThresholdStudsPerSecHundredth",
    "DFIntCheckPVDifferencesForInterpolationMinRotVelThresholdRadsPerSecHundredth",
    "DFIntCheckPVCachedVelThresholdPercent",
    "DFIntCheckPVCachedRotVelThresholdPercent",
    "DFIntCheckPVLinearVelocityIntegrateVsDeltaPositionThresholdPercent",
    "DFIntGameNetDontSendRedundantNumTimes",
    "DFIntGameNetDontSendRedundantDeltaPositionMillionth",
    // ---- Replication focus / NOU manipulation ----
    "DFIntReplicationFocusNouExtentsSizeCutoffForPauseStuds",
    "DFIntSimOwnedNOUCountThresholdMillionth",
    "DFIntStreamJobNOUVolumeCap",
    "DFIntStreamJobNOUVolumeLengthCap",
    // ---- Max acceptable update delay (desync window) ----
    "DFIntMaxAcceptableUpdateDelay",
    // ---- Debug send distance manipulation ----
    "DFIntDebugSendDistInSteps",
    // ---- Solver state replication ----
    "DFFlagSolverStateReplicatedOnly2",
    // ---- Failsafe humanoid (bypass safety checks) ----
    "FFlagFailsafeHumanoid_3",
    // ---- Server connection manipulation ----
    "FFlagDebugLocalRccServerConnection",
    "FFlagRefactorPlayerConnect",
];

// =============================================================================
// HIGH FLAGS: Visual / rendering advantages
// Wallhacks, ESP, x-ray, fog removal, camera manipulation, GUI hiding,
// entity highlighting, and texture stripping that provide visual advantage.
// =============================================================================
pub static HIGH_FLAGS: &[&str] = &[
    // ---- Wallhack / ESP via debug drawing ----
    // Draws outlines around every part and humanoid (wallhack)
    "DFFlagDebugDrawBroadPhaseAABBs",
    // Draws outlines around every body part (ESP through walls)
    "DFFlagDebugDrawBvhNodes",
    // Skeleton rendering through walls (ESP)
    "DFFlagAnimatorDrawSkeletonAttachments",
    "DFFlagAnimatorDrawSkeletonAll",
    "DFIntAnimatorDrawSkeletonScalePercent",
    // Debug draw master enable
    "DFFlagDebugDrawEnable",
    // Humanoid debug rendering (shows collision info through walls)
    "FFlagDebugHumanoidRendering",
    // Highlight outlines (can be abused for ESP on mobile)
    "FFlagHighlightOutlinesOnMobile",
    // ---- X-ray / fog / see-through ----
    // Far Z plane = 1 creates x-ray camera (see through terrain/parts)
    "FIntCameraFarZPlane",
    // Restrict GC distance = 1 makes most geometry invisible
    "DFIntDebugRestrictGCDistance",
    // ---- Camera manipulation (zoom/FOV advantage) ----
    // Extreme zoom distance gives sniper-like view in close-quarters games
    "FIntCameraMaxZoomDistance",
    "FIntMaxCameraMaxZoomDistance",
    // ---- Animation LOD manipulation (see players at all distances) ----
    // 0 = animations always render at full detail regardless of distance
    "DFIntAnimationLodFacsDistanceMin",
    "DFIntAnimationLodFacsDistanceMax",
    "DFIntAnimationLodFacsVisibilityDenominator",
    // ---- Texture removal / stripping (see through surfaces) ----
    // (DFFlagTextureQualityOverrideEnabled and DFIntTextureQualityOverride
    // are on Roblox's official allowlist — see flag_allowlist.rs — so they
    // can never trigger here. Removed from this tier to keep the catalog
    // honest; if tournament policy needs to override Roblox's allowlist,
    // delete the corresponding entry from flag_allowlist.rs first.)
    // Skip mip levels (reduce textures to near-invisible)
    "FIntDebugTextureManagerSkipMips",
    // Remove part textures entirely
    "FStringPartTexturePackTable2022",
    "FStringPartTexturePackTablePre2022",
    // Remove terrain textures (see through terrain)
    "FStringTerrainMaterialTable2022",
    "FStringTerrainMaterialTablePre2022",
    // Texture compositor; 0 = no texture compositing
    "DFIntTextureCompositorActiveJobs",
    "DFIntPerformanceControlTextureQualityBestUtility",
    "FIntTextureCompositorLowResFactor",
    // Terrain slice size manipulation
    "FIntTerrainArraySliceSize",
    // ---- Shadow / lighting removal (see in dark areas) ----
    // 0 = no shadows, full visibility in dark areas
    "FIntRenderShadowIntensity",
    // Disable shadow map culling (also strips shadows)
    "DFIntCullFactorPixelThresholdShadowMapHighQuality",
    "DFIntCullFactorPixelThresholdShadowMapLowQuality",
    // Shadow bias manipulation
    "FIntRenderShadowmapBias",
    // CSG voxelizer fade radius; 0 = no baked shadow fade
    "FIntCSGVoxelizerFadeRadius",
    // ---- Force lighting technology (reduce visual clutter) ----
    "DFFlagDebugRenderForceTechnologyVoxel",
    "FFlagDebugForceFutureIsBrightPhase2",
    "FFlagDebugForceFutureIsBrightPhase3",
    // (FFlagRenderUnifiedLighting6 and FFlagUnifiedLightingBetaFeature are
    // Roblox-shipped unified-lighting rollout gates; see MEMORY_BASELINE_FLAGS.
    // They are present in vanilla client memory on every run and setting
    // them in ClientAppSettings does not confer competitive advantage. Do
    // not re-add without a documented cheat-value for the suspicious DB.)

    // ---- Post-processing removal ----
    "FFlagDisablePostFx",
    // (FFlagGlobalWindRendering / FFlagGlobalWindActivated are shipped
    // Roblox Global Wind feature toggles; FFlagRenderFixFog is a bug-fix
    // toggle, not a fog-removal cheat. All three moved to baseline.)

    // ---- GUI hiding for competitive advantage ----
    // (FFlagUserShowGuiHideToggles / FFlagGuiHidingApiSupport2 /
    // DFIntCanHideGuiGroupId are the shipped Roblox GUI-hide accessibility
    // API — moved to MEMORY_BASELINE_FLAGS. Force-hiding HUD via debug
    // flags is still a real knob, so the following two stay.)
    // Dont render screen GUI (hide all UI overlays)
    "FFlagDebugDontRenderScreenGui",
    "FFlagDebugDontRenderUI",
    // ---- Roughness manipulation (shiny avatars = easier to spot) ----
    "DFIntRenderClampRoughnessMax",
    // ---- Interpolation visualizer (network position debug overlay) ----
    "DFFlagDebugEnableInterpolationVisualizer",
    // ---- Debug display overlays ----
    "FFlagDebugDisplayUnthemedInstances",
    "FFlagDebugLightGridShowChunks",
    "FFlagTrackerLodControllerDebugUI",
    // ---- Particle / sky / visual stripping ----
    // (FFlagDebugSkyGray and DFFlagDebugPauseVoxelizer are on Roblox's
    // allowlist; removed here to avoid the dead-entry confusion.)
    "FFlagDebugDeterministicParticles",
    // ---- SSAO manipulation ----
    "FFlagDebugSSAOForce",
    "FIntSSAOMipLevels",
    // ---- Grass stripping beyond allowlist values ----
    // (FIntFRMMinGrassDistance, FIntFRMMaxGrassDistance, and
    // FIntGrassMovementReducedMotionFactor are on Roblox's allowlist —
    // removed from this tier. FIntRenderGrassDetailStrands and
    // FIntRenderGrassHeightScaler are NOT on the allowlist and stay.)
    "FIntRenderGrassDetailStrands",
    "FIntRenderGrassHeightScaler",
    // ---- Viewport manipulation ----
    "FIntViewportFrameMaxSize",
    // ---- Refactor mesh materials (strip materials) ----
    "FFlagMSRefactor5",
    // ---- Chat / voice chat manipulation for advantage ----
    "FFlagDebugForceChatDisabled",
    "DFIntMaxLoadableAudioChannelCount",
    "DFIntVoiceChatRollOffMinDistance",
    "DFIntVoiceChatRollOffMaxDistance",
    "DFIntVoiceChatVolumeThousandths",
    "DFIntAvatarFaceChatHeadRollLimitDegrees",
    "FFlagDebugDefaultChannelStartMuted",
    // ---- Scroll wheel delta (exploit zoom speed) ----
    "FIntScrollWheelDeltaAmount",
    // ---- Remote event size limit manipulation ----
    "DFIntRemoteEventSingleInvocationSizeLimit",
    // ---- Disconnect / reconnect manipulation ----
    "DFFlagDebugDisableTimeoutDisconnect",
    // (FFlagReconnectDisabled / FStringReconnectDisabledReason are
    // Roblox-side kill-switches; client-local values are ignored by the
    // server. Moved to MEMORY_BASELINE_FLAGS.)

    // (FFlagDataModelPatcherForceLocal is an internal migration toggle,
    // not a cheat vector — moved to MEMORY_BASELINE_FLAGS.)
];

// =============================================================================
// MEDIUM FLAGS: Moderate advantage
// FPS uncapping, telemetry disabling, network optimization, rendering
// performance flags that also reduce visual clutter, UI manipulation.
// =============================================================================
pub static MEDIUM_FLAGS: &[&str] = &[
    // ---- FPS uncapping / task scheduler manipulation ----
    // The numeric `DFIntTaskSchedulerTargetFps` and refresh-rate bounds
    // remain suspicious because user-chosen values drive the behavior.
    // The shipped feature-gate bools (`FFlagTaskSchedulerLimitTargetFpsTo2402`,
    // `FFlagGameBasicSettingsFramerateCap*`) are Roblox's own rollout
    // toggles — presence in heap is expected; moved to MEMORY_BASELINE_FLAGS.
    "DFIntTaskSchedulerTargetFps",
    "FIntTargetRefreshRate",
    "FIntRefreshRateLowerBound",
    // ---- Telemetry disabling (hides client modifications) ----
    "FFlagDebugDisableTelemetryEphemeralCounter",
    "FFlagDebugDisableTelemetryEphemeralStat",
    "FFlagDebugDisableTelemetryEventIngest",
    "FFlagDebugDisableTelemetryPoint",
    "FFlagDebugDisableTelemetryV2Counter",
    "FFlagDebugDisableTelemetryV2Event",
    "FFlagDebugDisableTelemetryV2Stat",
    // (FFlagAdServiceEnabled is a privacy/preference toggle that Bloxstrap
    // ships disabled by default — no competitive-advantage. Moved to
    // MEMORY_BASELINE_FLAGS.)

    // ---- Network optimization (potential desync at extreme values) ----
    // FFlagOptimize* boolean rollouts are Roblox-side staged rollouts;
    // client value is advisory. Numeric tuning stays suspicious.
    "DFIntConnectionMTUSize",
    "DFIntNetworkLatencyTolerance",
    "DFIntNetworkPrediction",
    "DFIntRakNetResendRttMultiple",
    "DFIntRakNetResendTimeoutMS",
    "DFIntRakNetResendBufferArrayLength",
    "DFIntRaknetBandwidthPingSendEveryXSeconds",
    "DFIntRakNetLoopMs",
    "DFIntServerPhysicsUpdateRate",
    "DFIntServerTickRate",
    "FLogNetwork",
    // ---- Graphics quality override ----
    // (DFIntDebugFRMQualityLevelOverride is on Roblox's allowlist —
    // removed. `FFlagCommitToGraphicsQualityFix` and `FFlagFixGraphicsQuality`
    // are "Fix*" bug-fix toggles — shipped true by default — moved to
    // MEMORY_BASELINE_FLAGS.)
    "FIntRomarkStartWithGraphicQualityLevel",
    // ---- Light update frequency reduction ----
    "FIntRenderLocalLightUpdatesMax",
    "FIntRenderLocalLightUpdatesMin",
    "FIntRenderLocalLightFadeInMs",
    // (FFlagNewLightAttenuation is a Roblox rendering-rollout bool; moved
    // to MEMORY_BASELINE_FLAGS. No meaningful competitive advantage from
    // either state.)

    // ---- CSG LOD switching ----
    // (The four DFIntCSGLevelOfDetailSwitchingDistance* flags are on
    // Roblox's allowlist — removed. CSGv2LodsToGenerate is not.)
    "DFIntCSGv2LodsToGenerate",
    // ---- Frame buffer manipulation ----
    "DFIntMaxFrameBufferSize",
    // ---- MSAA manipulation ----
    // (FIntDebugForceMSAASamples is allowlisted — removed.)

    // ---- Threading manipulation ----
    "FIntRuntimeMaxNumOfThreads",
    "FIntTaskSchedulerThreadMin",
    // (Render-threading assertion toggles were engine-internal correctness
    // checks that slowed rendering if anything — moved to MEMORY_BASELINE_FLAGS.)

    // ---- DPI scale manipulation ----
    // (DFFlagDisableDPIScale is allowlisted — removed.)

    // ---- UI manipulation ----
    // (Chrome / in-game menu / bubble-chat / self-view / BETA-badge
    // rollouts are all Roblox-shipped UI A/B flags — moved to
    // MEMORY_BASELINE_FLAGS. Keep numeric padding/blur knobs only.)
    "FIntFontSizePadding",
    "FIntRobloxGuiBlurIntensity",
    // ---- Report abuse menu manipulation ----
    "FStringReportAbuseMenuRoactForcedUserIds",
    "FFlagEnableReportAbuseMenuRoact2",
    "FFlagEnableReportAbuseMenuLayerOnV3",
    // (FFlagDebugDisplayFPS is the Shift-F5 built-in overlay — user-facing
    // documented feature, not a cheat — moved to MEMORY_BASELINE_FLAGS.)

    // ---- Debug flag state display ----
    "FStringDebugShowFlagState",
    // ---- DFIntDebugSimPhysicsSteppingMethodOverride ----
    "DFIntDebugSimPhysicsSteppingMethodOverride",
    // ---- Render distance culling ----
    "FFlagRenderTestEnableDistanceCulling",
    "DFFlagDebugSkipMeshVoxelizer",
    // ---- Sound physics velocity ----
    "FFlagSoundsUsePhysicalVelocity",
    // ---- Shadow atlas manipulation ----
    "FIntRenderMaxShadowAtlasUsageBeforeDownscale",
    // ---- Voice chat configuration ----
    "DFIntVoiceChatMaxRecordedDataDeliveryIntervalMs",
    // ---- Modernization forced user IDs ----
    "FStringInGameMenuModernizationStickyBarForcedUserIds",
    // ---- Order66 (misc debug flag) ----
    "DFFlagOrder66",
    // (Quaternion/RigScale animation-system corrections are Roblox-side
    // migration fixes; moved to MEMORY_BASELINE_FLAGS.)

    // ---- Avatar chat visualization ----
    "FFlagDebugAvatarChatVisualization",
    // (FFlagFastGPULightCulling3 is a staged rendering-perf rollout; moved
    // to MEMORY_BASELINE_FLAGS.)

    // ---- Deferred lighting disable ----
    "FFlagDebugDisableDeferredLighting",
    // (UIBlox theming and the low-FRM bloom fade are cosmetic Roblox
    // rollouts; moved to MEMORY_BASELINE_FLAGS.)

    // ---- Vis bug checks (can affect rendering) ----
    "DFFlagUseVisBugChecks",
    "FFlagEnableVisBugChecks27",
    "FFlagVisBugChecksThreadYield",
    "FIntEnableVisBugChecksHundredthPercent27",
    // (Quick-launch, chat /command autocomplete, and grass render fix are
    // shipped feature gates with no competitive effect; moved to
    // MEMORY_BASELINE_FLAGS.)

    // ---- Camera input type manipulation ----
    "FFlagUserCameraControlLastInputTypeUpdate",
    // ---- Debug heap dump ----
    "FFlagDebugLuaHeapDump",
];

// =============================================================================
// LOW FLAGS: Benign / cosmetic but non-allowlisted
// Graphics API preferences, minor rendering tweaks, quality-of-life flags.
// These are unlikely to give competitive advantage but are still non-allowlisted.
// =============================================================================
pub static LOW_FLAGS: &[&str] = &[
    // ---- Graphics API preferences (beyond allowlisted set) ----
    // (FFlagDebugGraphicsPreferD3D11 / PreferOpenGL / PreferVulkan are
    // allowlisted — removed. The remaining entries are non-allowlisted
    // graphics-API tweaks.)
    "FFlagDebugGraphicsDisableDirect3D11",
    "FFlagDebugGraphicsPreferD3D11FL10",
    "FFlagDebugGraphicsPreferMetal",
    "FFlagGraphicsEnableD3D10Compute",
    "FFlagDebugGraphicsDisableVulkan",
    "FFlagDebugGraphicsDisableVulkan11",
    "FFlagRenderVulkanFixMinimizeWindow",
    // (FFlagHandleAltEnterFullscreenManually and FFlagGrassReducedMotion
    // were previously listed here for "completeness" but are allowlisted /
    // don't exist as real flag names — removed to keep the catalog honest.
    // The real allowlisted reduced-motion flag is the int
    // `FIntGrassMovementReducedMotionFactor`, which lives in flag_allowlist.)

    // ---- Compression ----
    "DFFlagEnableRequestAsyncCompression",
];

/// Get the severity verdict for a given flag name.
///
/// Returns:
/// - `Flagged` for CRITICAL flags (physics desync, replication manipulation,
///   noclip, simulation radius abuse, gravity exploits).
/// - `Suspicious` for HIGH flags (wallhack, ESP, x-ray, camera abuse,
///   texture stripping, GUI hiding) and MEDIUM flags (FPS uncapping,
///   telemetry disabling, network optimisation, UI manipulation).
/// - `Clean` for LOW flags (benign cosmetic / graphics API preferences)
///   and any flag not in our database.
pub fn get_flag_severity(flag_name: &str) -> ScanVerdict {
    if CRITICAL_FLAGS.iter().any(|&f| f == flag_name) {
        return ScanVerdict::Flagged;
    }
    if HIGH_FLAGS.iter().any(|&f| f == flag_name) {
        return ScanVerdict::Suspicious;
    }
    if MEDIUM_FLAGS.iter().any(|&f| f == flag_name) {
        return ScanVerdict::Suspicious;
    }
    // LOW flags are benign; return Clean.
    ScanVerdict::Clean
}

/// Return a human-readable category label for a flag, or None if unknown.
pub fn get_flag_category(flag_name: &str) -> Option<&'static str> {
    if CRITICAL_FLAGS.iter().any(|&f| f == flag_name) {
        return Some("CRITICAL");
    }
    if HIGH_FLAGS.iter().any(|&f| f == flag_name) {
        return Some("HIGH");
    }
    if MEDIUM_FLAGS.iter().any(|&f| f == flag_name) {
        return Some("MEDIUM");
    }
    if LOW_FLAGS.iter().any(|&f| f == flag_name) {
        return Some("LOW");
    }
    None
}

/// Return a brief description of why a flag is suspicious.
pub fn get_flag_description(flag_name: &str) -> Option<&'static str> {
    match flag_name {
        // === CRITICAL: Physics / Desync ===
        "DFIntS2PhysicsSenderRate" => Some("Physics sender rate: controls how often physics data reaches the server. Documented exploit value 1 (updates dropped to once/sec) causes server-side desync."),
        "DFIntS2PhysicSenderRate" => Some("Typo variant of physics sender rate; same desync effect."),
        "DFIntPhysicsSenderMaxBandwidthBps" => Some("Caps physics replication bandwidth. Value 1 starves server of position updates."),
        "DFIntPhysicsSenderMaxBandwidthBpsScaling" => Some("Scaling factor for physics sender bandwidth; 0 disables scaling."),
        "DFIntDataSenderRate" => Some("Controls data replication rate. Value -1 blocks all data replication."),
        "DFIntTouchSenderMaxBandwidthBps" => Some("Touch event bandwidth cap. Value -1 blocks touch replication."),
        "DFIntMinClientSimulationRadius" => Some("Minimum client simulation radius. Value 2147000000 claims ownership of all objects."),
        "DFIntMinimalSimRadiusBuffer" => Some("Simulation radius buffer. Extreme values expand network ownership."),
        "DFIntMaxClientSimulationRadius" => Some("Maximum client simulation radius. Value 2147000000 for total map control."),
        "DFFlagDebugPhysicsSenderDoesNotShrinkSimRadius" => Some("Prevents simulation radius from shrinking after expansion."),
        "FFlagDebugUseCustomSimRadius" => Some("Forces custom simulation radius, bypassing server limits."),
        "NextGenReplicatorEnabledWrite4" => Some("NextGen replicator toggle. Rapid toggling causes invisibility desync."),
        "DFIntReplicatorAnimationTrackLimitPerAnimator" => Some("Animation track replication limit. Value -1 hides all animations from other players."),
        "DFIntGameNetPVHeaderTranslationZeroCutoffExponent" => Some("Position header zero cutoff. Value 10 zeros out position data, causing invisibility."),
        "DFIntAssemblyExtentsExpansionStudHundredth" => Some("Assembly collision extents. Value -50 shrinks hitbox, enabling noclip."),
        "DFIntSimBroadPhasePairCountMax" => Some("Broad-phase collision pair limit. Low values disable collision detection (noclip)."),
        "FFlagDebugSimDefaultPrimalSolver" => Some("Enables primal solver. Combined with stiffness=0, enables noclip/flying."),
        "DFIntSimAdaptiveHumanoidPDControllerSubstepMultiplier" => Some("PD controller substep multiplier. Value -999999 causes extreme gravity manipulation."),
        "DFIntSolidFloorPercentForceApplication" => Some("Solid floor force. Value -1000 causes character to fly/phase through floors."),
        "DFIntNonSolidFloorPercentForceApplication" => Some("Non-solid floor force. Value -5000 causes extreme floor phasing."),
        "FFlagSimAdaptiveTimesteppingDefault2" => Some("Adaptive timestepping. Enables jump height/gravity exploit chain."),
        "DFFlagSimHumanoidTimestepModelUpdate" => Some("Humanoid timestep model update. Part of gravity manipulation chain."),
        "DFIntHipHeightClamp" => Some("Hip height clamp. Value -48 moves character below ground."),
        "FFlagRemapAnimationR6ToR15Rig" => Some("R6 to R15 animation remap. Causes visual desync in animation display."),
        "FIntParallelDynamicPartsFastClusterBatchSize" => Some("Cluster batch size. Value -1 causes invisibility through broken batching."),
        "DFIntRaycastMaxDistance" => Some("Raycast max distance. Value 3 breaks hit detection systems."),
        "DFIntMaxMissedWorldStepsRemembered" => Some("Missed world steps buffer. Value 1000 extends desync window."),
        "DFIntSimBlockLargeLocalToolWeldManipulationsThreshold" => Some("Tool weld threshold. Value -1 enables tool desync exploit."),
        "DFIntMaxActiveAnimationTracks" => Some("Max active animation tracks. Value 0 freezes all animations."),
        "DFIntDebugSimPrimalLineSearch" => Some("Primal solver line search. Various values cause gravity/flight exploits."),
        "DFIntDebugSimPrimalStiffness" => Some("Primal solver stiffness. Value 0 disables physics constraints (noclip)."),

        // === HIGH: Visual Advantage ===
        "DFFlagDebugDrawBroadPhaseAABBs" => Some("Draws outlines around every part/humanoid. Functions as wallhack."),
        "DFFlagDebugDrawBvhNodes" => Some("Draws outlines around body parts. Functions as ESP through walls."),
        "DFFlagAnimatorDrawSkeletonAttachments" => Some("Renders skeleton attachments visible through walls (ESP)."),
        "DFFlagAnimatorDrawSkeletonAll" => Some("Renders full skeleton on all avatars through walls (ESP)."),
        "FFlagDebugHumanoidRendering" => Some("Shows humanoid collision debug info through walls."),
        "FIntCameraFarZPlane" => Some("Camera far Z plane. Value 1 creates x-ray vision effect."),
        "FIntCameraMaxZoomDistance" => Some("Camera max zoom. Value 9999+ gives extreme zoom-out advantage."),
        "DFIntDebugRestrictGCDistance" => Some("Garbage collection distance. Value 1 makes most geometry invisible."),
        "DFIntAnimationLodFacsDistanceMin" => Some("Animation LOD min distance. Value 0 renders all player animations at max detail."),
        "DFIntAnimationLodFacsDistanceMax" => Some("Animation LOD max distance. Value 0 forces full animation detail at all distances."),
        "FIntRenderShadowIntensity" => Some("Shadow intensity. Value 0 removes all shadows for visibility in dark areas."),
        "FFlagDisablePostFx" => Some("Disables post-processing effects. Removes fog, bloom, and visual obstruction."),
        "FFlagDebugDontRenderScreenGui" => Some("Hides all screen GUIs. Can remove game UI for cleaner competitive view."),
        "DFIntRenderClampRoughnessMax" => Some("Roughness clamp. Extreme negative values make avatars extremely shiny/visible."),
        "DFFlagDebugEnableInterpolationVisualizer" => Some("Shows network position debug overlay. Reveals player interpolation data."),

        // === MEDIUM ===
        "DFIntTaskSchedulerTargetFps" => Some("FPS target. Values like 9999 or 2147483647 uncap framerate."),
        "FFlagDebugDisableTelemetryEphemeralCounter" => Some("Disables telemetry counter. Hides client modification from Roblox analytics."),
        "FFlagAdServiceEnabled" => Some("Ad service toggle. Set to false to disable ads."),
        "DFIntConnectionMTUSize" => Some("Network MTU size. Non-default values affect packet fragmentation."),

        _ => None,
    }
}
