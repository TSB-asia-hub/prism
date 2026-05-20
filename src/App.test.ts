import { describe, expect, it, vi } from "vitest";
import type { ScanFinding } from "./types";
import {
  emptyProgress,
  findingKey,
  formatBytes,
  groupByVerdict,
  hasTauriRuntime,
  importBadgeTitle,
  parseFindingDetails,
  parseMemoryFlagEvidence,
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

  it("parses the v0.10.0 aggregated bare-key bridge summary", () => {
    // Lock in compatibility with the format `inspect_generic_singleton_overrides`
    // emits as of v0.10.0: a single Flagged finding whose details contain
    // a multi-line `Detected flags: \n- Name = Value` list plus a per-flag
    // context annotation field. The frontend's `.memory-flags` accordion
    // depends on this shape parsing into the per-row flag list.
    const result = parseMemoryFlagEvidence(
      finding("Flagged", {
        module: "memory_scanner",
        description: "Live FastFlag registry injection: 3 flag(s) detected",
        details:
          "PID: 7156 | Singleton candidates: 1 | FFlag-shaped entries walked: 27377 | Entries inspected: 13297 | Source breakdown: cheat-rule 1 / baseline 1 / tracker 1 | Detected flags: \n- DFIntS2PhysicsSenderRate = 30\n- DFIntMaxDataPacketPerSend = 100000\n- DFIntRaknetBandwidthInfluxHundredthsPercentageV2 = 10000\n | Per-flag context: DFIntS2PhysicsSenderRate (vanilla 15, via baseline); DFIntMaxDataPacketPerSend (vanilla vanilla, via cheat-rule); DFIntRaknetBandwidthInfluxHundredthsPercentageV2 (vanilla 100, via tracker) | Detection: walked the Roblox FastFlag hash table via the bare-key bucket walk",
      }),
    );

    expect(result).not.toBeNull();
    expect(result!.flags).toEqual([
      { name: "DFIntS2PhysicsSenderRate", value: "30" },
      { name: "DFIntMaxDataPacketPerSend", value: "100000" },
      {
        name: "DFIntRaknetBandwidthInfluxHundredthsPercentageV2",
        value: "10000",
      },
    ]);
    expect(result!.detection).toContain("bare-key bucket walk");
  });

  it("extracts memory scanner flags from grouped detected-flag details", () => {
    const result = parseMemoryFlagEvidence(
      finding("Flagged", {
        module: "memory_scanner",
        description: "Critical live Roblox runtime-variable overrides",
        details:
          "Detected flags: 2 total\n- DFIntS2PhysicsSenderRate=1\n- DFFlagAssemblyExtentsExpansionStudHundredth=-50 | Detection: live memory",
      }),
    );

    expect(result).toEqual({
      flags: [
        { name: "DFIntS2PhysicsSenderRate", value: "1" },
        { name: "DFFlagAssemblyExtentsExpansionStudHundredth", value: "-50" },
      ],
      detection: "live memory",
    });
  });

  it("cleans legacy memory matches by dropping addresses and defaults", () => {
    const result = parseMemoryFlagEvidence(
      finding("Flagged", {
        module: "memory_scanner",
        description: "Critical live Roblox runtime-variable overrides",
        details:
          "PID: 1848 | Matches: DFIntA=9999 @0x7FF, DFIntB=1 (file default 15) @0x800 | Detection: cache",
      }),
    );

    expect(result).toEqual({
      flags: [
        { name: "DFIntA", value: "9999" },
        { name: "DFIntB", value: "1" },
      ],
      detection: "cache",
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
