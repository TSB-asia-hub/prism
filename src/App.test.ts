import { describe, expect, it, vi } from "vitest";
import type { ScanFinding } from "./types";
import {
  emptyProgress,
  findingKey,
  formatBytes,
  groupByVerdict,
  hasTauriRuntime,
  importBadgeTitle,
  parseFFlagOverride,
  parseFindingDetails,
  partitionFFlagOverrides,
  relativeTime,
  shortTime,
  truncate,
} from "./App";

function finding(
  verdict: ScanFinding["verdict"],
  overrides: Partial<ScanFinding> = {},
): ScanFinding {
  return {
    module: "memory",
    verdict,
    description: `${verdict} finding`,
    details: null,
    timestamp: "2026-05-06T12:34:56.000Z",
    ...overrides,
  };
}

describe("App UI helpers", () => {
  it("builds pending progress entries for every backend scanner", () => {
    expect(emptyProgress()).toEqual({
      process_scanner: { state: "pending" },
      file_scanner: { state: "pending" },
      client_settings_scanner: { state: "pending" },
      prefetch_scanner: { state: "pending" },
      memory_scanner: { state: "pending" },
    });
  });

  it("detects Tauri only from the injected runtime marker", () => {
    expect(hasTauriRuntime()).toBe(false);

    vi.stubGlobal("window", { __TAURI_INTERNALS__: {} });
    expect(hasTauriRuntime()).toBe(true);
    vi.unstubAllGlobals();
  });

  it("uses details in finding keys so same-tick findings stay distinct", () => {
    const base = finding("Suspicious", {
      description: "same",
      details: "Path: C:\\one",
    });

    expect(findingKey(base)).not.toBe(
      findingKey({ ...base, details: "Path: C:\\two" }),
    );
  });

  it("groups already-sorted findings without reordering them", () => {
    const flagged = finding("Flagged", { description: "first" });
    const suspiciousA = finding("Suspicious", { description: "second" });
    const suspiciousB = finding("Suspicious", { description: "third" });
    const clean = finding("Clean", { description: "fourth" });

    expect(groupByVerdict([flagged, suspiciousA, suspiciousB, clean])).toEqual([
      { verdict: "Flagged", items: [flagged] },
      { verdict: "Suspicious", items: [suspiciousA, suspiciousB] },
      { verdict: "Clean", items: [clean] },
    ]);
  });

  it("parses pipe-separated detail fields and preserves freeform leftovers", () => {
    expect(
      parseFindingDetails("Flag: DFFlagDebug | Value: true | raw tail"),
    ).toEqual({
      fields: [
        { label: "Flag", value: "DFFlagDebug" },
        { label: "Value", value: "true" },
      ],
      freeform: "raw tail",
    });
  });

  it("preserves multiline grouped finding values", () => {
    expect(
      parseFindingDetails(
        "PID: 1848 | Exact curated matches: 2 total\n- A=1\n- B=2 | Detection: live",
      ),
    ).toEqual({
      fields: [
        { label: "PID", value: "1848" },
        { label: "Exact curated matches", value: "2 total\n- A=1\n- B=2" },
        { label: "Detection", value: "live" },
      ],
      freeform: null,
    });
  });

  it("splits comma detail fields only at capitalized key boundaries", () => {
    expect(
      parseFindingDetails("Path: C:\\Roblox, Player\\Client.exe, Hash: abc123"),
    ).toEqual({
      fields: [
        { label: "Path", value: "C:\\Roblox, Player\\Client.exe" },
        { label: "Hash", value: "abc123" },
      ],
      freeform: null,
    });
  });

  it("does not treat loose prose as key-value details", () => {
    expect(parseFindingDetails("contains WriteProcessMemory: but no field")).toEqual({
      fields: [],
      freeform: "contains WriteProcessMemory: but no field",
    });
  });

  it("formats byte counts across scanner progress units", () => {
    expect(formatBytes(1023)).toBe("1023 B");
    expect(formatBytes(1024)).toBe("1 KiB");
    expect(formatBytes(1024 * 1024)).toBe("1.0 MiB");
    expect(formatBytes(1024 * 1024 * 1024)).toBe("1.00 GiB");
  });

  it("formats import badge titles with signature and staleness state", () => {
    expect(
      importBadgeTitle({
        signatureValid: true,
        ageSeconds: 90,
        stale: false,
        sourcePath: "/tmp/report.json",
      }),
    ).toBe("signature OK · 2m old\n/tmp/report.json");

    expect(
      importBadgeTitle({
        signatureValid: false,
        ageSeconds: 7200,
        stale: true,
        sourcePath: "/tmp/old.json",
      }),
    ).toBe(
      "signature INVALID · 2h old (exceeds 30m freshness window)\n/tmp/old.json",
    );
  });

  it("truncates long labels and leaves short labels intact", () => {
    expect(truncate("abcdef", 6)).toBe("abcdef");
    expect(truncate("abcdef", 4)).toBe("abcd…");
  });

  it("formats relative times at UI thresholds", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-06T12:00:00.000Z"));

    expect(relativeTime(new Date("2026-05-06T11:59:58.000Z"))).toBe("just now");
    expect(relativeTime(new Date("2026-05-06T11:59:30.000Z"))).toBe("30s ago");
    expect(relativeTime(new Date("2026-05-06T11:30:00.000Z"))).toBe("30m ago");
    expect(relativeTime(new Date("2026-05-06T09:00:00.000Z"))).toBe("3h ago");

    vi.useRealTimers();
  });

  it("renders short times without throwing for valid ISO timestamps", () => {
    expect(shortTime("2026-05-06T12:34:56.000Z")).toMatch(/\d{2}:\d{2}/);
  });
});

describe("FFlag override grouping", () => {
  it("parses a live registry override finding with default-from-details", () => {
    const f: ScanFinding = {
      module: "memory_scanner",
      verdict: "Flagged",
      description:
        'Critical live FastFlag registry override: "DFIntS2PhysicsSenderRate" = -30',
      details:
        "PID: 1234 | Singleton: 0xABC via heap | Registry entry: 0xDEF | Value address: 0x111 | Default: 15 | Detection: resolved Roblox FastFlag hash table",
      timestamp: "2026-05-06T12:34:56.000Z",
    };
    expect(parseFFlagOverride(f)).toEqual({
      flagName: "DFIntS2PhysicsSenderRate",
      injectedValue: "-30",
      defaultValue: "15",
      verdict: "Flagged",
      kind: "live-registry",
      sourceKey: findingKey(f),
    });
  });

  it("parses a baseline-deviation finding with inline (default: X)", () => {
    const f: ScanFinding = {
      module: "memory_scanner",
      verdict: "Suspicious",
      description:
        'Live FastFlag deviates from baseline: "DFIntRaycastMaxDistance" = 3 (default: 15000)',
      details:
        "PID: 1234 | Registry node: 0x1 | Flag string: 0x2 | Registry entry: 0x3 | Value address: 0x4 | Node candidates: bucket=2 | Default: 15000 | Note: very low values break hit detection",
      timestamp: "2026-05-06T12:34:56.000Z",
    };
    const parsed = parseFFlagOverride(f)!;
    expect(parsed.flagName).toBe("DFIntRaycastMaxDistance");
    expect(parsed.injectedValue).toBe("3");
    expect(parsed.defaultValue).toBe("15000");
    expect(parsed.kind).toBe("baseline-deviation");
  });

  it("parses a heap-context injection-evidence finding for a bool override", () => {
    const f: ScanFinding = {
      module: "memory_scanner",
      verdict: "Suspicious",
      description:
        'Suspicious runtime FFlag injection evidence: "DFFlagAnimatorDrawSkeletonAll" = true',
      details:
        "Address: 0x100 | Encoding: ascii | Occurrences: 4 | Category: HIGH | Default: false | Renders skeleton ESP",
      timestamp: "2026-05-06T12:34:56.000Z",
    };
    const parsed = parseFFlagOverride(f)!;
    expect(parsed.flagName).toBe("DFFlagAnimatorDrawSkeletonAll");
    expect(parsed.injectedValue).toBe("true");
    expect(parsed.defaultValue).toBe("false");
    expect(parsed.kind).toBe("injection-context");
  });

  it("parses a value-match finding without a known default", () => {
    const f: ScanFinding = {
      module: "memory_scanner",
      verdict: "Suspicious",
      description:
        'Suspicious runtime FFlag value match: "DFIntCullFactorPixelThresholdMainViewHighQuality" = 2147483647',
      details:
        "Address: 0x200 | Encoding: ascii | Occurrences: 1 | Category: HIGH | Detection: parsed value matches a curated injector cheat-value rule",
      timestamp: "2026-05-06T12:34:56.000Z",
    };
    const parsed = parseFFlagOverride(f)!;
    expect(parsed.flagName).toBe(
      "DFIntCullFactorPixelThresholdMainViewHighQuality",
    );
    expect(parsed.injectedValue).toBe("2147483647");
    expect(parsed.defaultValue).toBeNull();
    expect(parsed.kind).toBe("value-match");
  });

  it("ignores non-memory_scanner findings", () => {
    const f: ScanFinding = {
      module: "file_scanner",
      verdict: "Flagged",
      description:
        'Critical live FastFlag registry override: "DFIntS2PhysicsSenderRate" = -30',
      details: null,
      timestamp: "2026-05-06T12:34:56.000Z",
    };
    expect(parseFFlagOverride(f)).toBeNull();
  });

  it("ignores Clean findings (those are the aggregate summary lines)", () => {
    const f: ScanFinding = {
      module: "memory_scanner",
      verdict: "Clean",
      description:
        '12 non-allowlisted FFlag-shaped identifiers observed in Roblox heap.',
      details: "Unique names: 12 | Total occurrences: 480",
      timestamp: "2026-05-06T12:34:56.000Z",
    };
    expect(parseFFlagOverride(f)).toBeNull();
  });

  it("ignores memory_scanner findings whose description does not match the prefix table", () => {
    // Module load / coverage findings must NEVER get absorbed into the
    // override card — they are unrelated runtime evidence and the user
    // needs to see them as their own row.
    const f: ScanFinding = {
      module: "memory_scanner",
      verdict: "Flagged",
      description: 'Untrusted module loaded into Roblox: "evil.dll"',
      details: "Path: C:\\Temp\\evil.dll, PID: 1234",
      timestamp: "2026-05-06T12:34:56.000Z",
    };
    expect(parseFFlagOverride(f)).toBeNull();
  });

  it("partitions multiple overrides, dedupes by (name, injected_value), keeps the strongest verdict", () => {
    // Two findings emit for the same (flag, injected value) — one from the
    // live registry (Flagged, no Default in details) and one from the value-
    // match path (Suspicious, no default). The aggregated entry must keep
    // the Flagged verdict and the live-registry kind, since that's the
    // stronger evidence.
    const liveFlag: ScanFinding = {
      module: "memory_scanner",
      verdict: "Flagged",
      description:
        'Critical live FastFlag registry override: "DFIntS2PhysicsSenderRate" = -30',
      details: "PID: 1 | Singleton: 0x0 via heap | Registry entry: 0x0 | Value address: 0x0 | Default: 15 | Detection: live",
      timestamp: "2026-05-06T12:34:56.000Z",
    };
    const valueMatch: ScanFinding = {
      module: "memory_scanner",
      verdict: "Suspicious",
      description:
        'Suspicious runtime FFlag value match: "DFIntS2PhysicsSenderRate" = -30',
      details: "Address: 0x100 | Encoding: ascii | Occurrences: 2 | Category: CRITICAL",
      timestamp: "2026-05-06T12:34:57.000Z",
    };
    const unrelated: ScanFinding = {
      module: "process_scanner",
      verdict: "Suspicious",
      description: "Known cheat tool process running",
      details: "name=odessa.exe",
      timestamp: "2026-05-06T12:34:58.000Z",
    };

    const { overrides, sourceKeys, rest } = partitionFFlagOverrides([
      liveFlag,
      valueMatch,
      unrelated,
    ]);
    expect(overrides.length).toBe(1);
    expect(overrides[0]).toMatchObject({
      flagName: "DFIntS2PhysicsSenderRate",
      injectedValue: "-30",
      defaultValue: "15",
      verdict: "Flagged",
      kind: "live-registry",
    });
    expect(sourceKeys.size).toBe(2);
    expect(rest).toEqual([unrelated]);
  });

  it("keeps distinct entries for the same flag at different injected values", () => {
    const f1: ScanFinding = {
      module: "memory_scanner",
      verdict: "Flagged",
      description:
        'Critical live FastFlag registry override: "DFIntS2PhysicsSenderRate" = -30',
      details: "Default: 15",
      timestamp: "2026-05-06T12:34:56.000Z",
    };
    const f2: ScanFinding = {
      module: "memory_scanner",
      verdict: "Suspicious",
      description:
        'Suspicious runtime FFlag value match: "DFIntS2PhysicsSenderRate" = 3',
      details: "Address: 0x100",
      timestamp: "2026-05-06T12:34:57.000Z",
    };
    const { overrides } = partitionFFlagOverrides([f1, f2]);
    expect(overrides.length).toBe(2);
    // Sorted by (verdict desc, name asc) — Flagged comes first.
    expect(overrides[0].injectedValue).toBe("-30");
    expect(overrides[1].injectedValue).toBe("3");
  });

  it("returns empty overrides and untouched rest when no FFlag overrides present", () => {
    const f: ScanFinding = {
      module: "file_scanner",
      verdict: "Flagged",
      description: "Cheat tool installed",
      details: "Path: C:\\Tools\\cheats\\fflag_injector.exe",
      timestamp: "2026-05-06T12:34:56.000Z",
    };
    const { overrides, sourceKeys, rest } = partitionFFlagOverrides([f]);
    expect(overrides).toEqual([]);
    expect(sourceKeys.size).toBe(0);
    expect(rest).toEqual([f]);
  });

  it("handles description-only baseline deviation without a Default details field", () => {
    // The runtime_flag_baseline_finding emission path uses inline `(default: X)`
    // in the description AND now also adds Default: to details. This test
    // covers a scenario where details parsing might fail but the inline form
    // still works.
    const f: ScanFinding = {
      module: "memory_scanner",
      verdict: "Suspicious",
      description:
        'Live FastFlag deviates from baseline: "FIntCameraFarZPlane" = 1 (default: 100000)',
      details: null,
      timestamp: "2026-05-06T12:34:56.000Z",
    };
    const parsed = parseFFlagOverride(f)!;
    expect(parsed.injectedValue).toBe("1");
    expect(parsed.defaultValue).toBe("100000");
  });

  it("does NOT mis-split a quoted injected string that incidentally contains ' (default: '", () => {
    // Mega-review pin: extract_adjacent_value_ascii returns heap-extracted
    // quoted strings verbatim — they can legitimately contain ' (default: '
    // as content. The previous parser used unconditional lastIndexOf and
    // would truncate the value + synthesize a fake strikethrough. After
    // the fix, inline-default extraction is scoped to baseline-deviation.
    const f: ScanFinding = {
      module: "memory_scanner",
      verdict: "Suspicious",
      description:
        'Suspicious runtime FFlag injection evidence: "FStringSomeFlag" = "this is a (default: configuration)"',
      details:
        "Address: 0x100 | Encoding: ascii | Occurrences: 1 | Category: HIGH",
      timestamp: "2026-05-06T12:34:56.000Z",
    };
    const parsed = parseFFlagOverride(f)!;
    expect(parsed.injectedValue).toBe(
      '"this is a (default: configuration)"',
    );
    expect(parsed.defaultValue).toBeNull();
  });

  it("scopes inline (default: X) extraction to baseline-deviation kind only", () => {
    // Sanity: a baseline-deviation finding that *does* end with (default: X)
    // still parses correctly (the trailing anchor protects the legitimate case).
    const f: ScanFinding = {
      module: "memory_scanner",
      verdict: "Suspicious",
      description:
        'Live FastFlag deviates from baseline: "FIntCameraFarZPlane" = 1 (default: 100000)',
      details: null,
      timestamp: "2026-05-06T12:34:56.000Z",
    };
    const parsed = parseFFlagOverride(f)!;
    expect(parsed.injectedValue).toBe("1");
    expect(parsed.defaultValue).toBe("100000");
  });

  it("sourceKey upgrades to the winning finding when merge upgrades verdict", () => {
    // Mega-review fix: when a Flagged live-registry finding merges over a
    // Suspicious value-match finding for the same (flag, value), the
    // surviving sourceKey must belong to the Flagged one. This honours
    // the documented contract: sourceKey locates the surviving rendered
    // entry, not the first-seen one.
    const weak: ScanFinding = {
      module: "memory_scanner",
      verdict: "Suspicious",
      description:
        'Suspicious runtime FFlag value match: "DFIntS2PhysicsSenderRate" = -30',
      details: "Address: 0x100 | Encoding: ascii | Occurrences: 1 | Category: CRITICAL",
      timestamp: "2026-05-06T12:34:56.000Z",
    };
    const strong: ScanFinding = {
      module: "memory_scanner",
      verdict: "Flagged",
      description:
        'Critical live FastFlag registry override: "DFIntS2PhysicsSenderRate" = -30',
      details:
        "PID: 1 | Singleton: 0x0 via heap | Registry entry: 0x0 | Value address: 0x0 | Default: 15 | Detection: live",
      timestamp: "2026-05-06T12:34:57.000Z",
    };
    const { overrides } = partitionFFlagOverrides([weak, strong]);
    expect(overrides).toHaveLength(1);
    expect(overrides[0].verdict).toBe("Flagged");
    expect(overrides[0].kind).toBe("live-registry");
    expect(overrides[0].sourceKey).toBe(findingKey(strong));
  });

  it("sourceKey preserves first-seen identity when merge does not upgrade", () => {
    // Symmetric case: if the first finding is already the strongest, the
    // sourceKey stays put.
    const strong: ScanFinding = {
      module: "memory_scanner",
      verdict: "Flagged",
      description:
        'Critical live FastFlag registry override: "DFIntS2PhysicsSenderRate" = -30',
      details: "Default: 15",
      timestamp: "2026-05-06T12:34:56.000Z",
    };
    const weak: ScanFinding = {
      module: "memory_scanner",
      verdict: "Suspicious",
      description:
        'Suspicious runtime FFlag value match: "DFIntS2PhysicsSenderRate" = -30',
      details: "Address: 0x100",
      timestamp: "2026-05-06T12:34:57.000Z",
    };
    const { overrides } = partitionFFlagOverrides([strong, weak]);
    expect(overrides).toHaveLength(1);
    expect(overrides[0].sourceKey).toBe(findingKey(strong));
  });
});
