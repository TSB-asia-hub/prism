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
