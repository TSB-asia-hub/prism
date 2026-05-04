import { Component, type KeyboardEvent as ReactKeyboardEvent, ReactNode, memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { save as showSaveDialog } from "@tauri-apps/plugin-dialog";
import type { ScanFinding, ScanReport, ScanVerdict } from "./types";

// Version is wired in at build time from package.json by Vite's __APP_VERSION__
// define (see vite.config.ts); fall back to "?" if the define is missing.
declare const __APP_VERSION__: string;
const APP_VERSION =
  typeof __APP_VERSION__ !== "undefined" ? __APP_VERSION__ : "?";

type Phase = "idle" | "scanning" | "complete";
type Filter = "all" | "flagged" | "suspicious" | "inconclusive" | "clean";

// Display metadata for each scanner. The `id` is the stable identifier the
// backend uses in `scan-progress` events — keep in sync with SCANNER_IDS
// in src-tauri/src/scanners/mod.rs.
const SCANNERS: { id: string; label: string }[] = [
  { id: "process_scanner", label: "processes" },
  { id: "file_scanner", label: "file system" },
  { id: "client_settings_scanner", label: "client settings" },
  { id: "prefetch_scanner", label: "prefetch cache" },
  { id: "memory_scanner", label: "memory regions" },
];

type ScannerState = "pending" | "running" | "done" | "errored";

type ScannerProgress = {
  state: ScannerState;
  findings?: number;
  // memory_scanner only: bytes scanned so far during the walk
  bytesScanned?: number;
  regionsScanned?: number;
  errorMessage?: string;
};

type ProgressMap = Record<string, ScannerProgress>;

type ScanProgressEvent =
  | { kind: "started"; scanner: string }
  | { kind: "done"; scanner: string; findings: number }
  | {
    kind: "heartbeat";
    scanner: string;
    regions_scanned: number;
    bytes_scanned: number;
  }
  | { kind: "errored"; scanner: string; message: string };

function emptyProgress(): ProgressMap {
  return Object.fromEntries(
    SCANNERS.map((s) => [s.id, { state: "pending" as const }]),
  );
}

type Toast = { msg: string; kind: "info" | "success" | "error" };

// Tauri v2 injects its invoke bridge at window.__TAURI_INTERNALS__. If this
// is missing, the app is running in a plain browser (e.g. `npm run dev`
// opened at http://localhost:1420) rather than the Tauri webview, and
// `invoke` would throw "Cannot read properties of undefined".
function hasTauriRuntime(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof (window as unknown as { __TAURI_INTERNALS__?: unknown })
      .__TAURI_INTERNALS__ !== "undefined"
  );
}

// Stable per-finding identity so open-state and React keys track the
// finding itself, not its position in the filtered list. Includes the
// `details` field so two findings with identical module+timestamp+description
// (which can happen on batch scans hitting Utc::now() in the same tick)
// still get distinct keys when their details differ.
function findingKey(f: ScanFinding): string {
  return `${f.module}|${f.timestamp}|${f.description}|${f.details ?? ""}`;
}

function AppInner() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [report, setReport] = useState<ScanReport | null>(null);
  const [progress, setProgress] = useState<ProgressMap>(() => emptyProgress());
  const [filter, setFilter] = useState<Filter>("all");
  const [openKey, setOpenKey] = useState<string | null>(null);
  const [toast, setToast] = useState<Toast | null>(null);
  const [tauriReady, setTauriReady] = useState<boolean>(() => hasTauriRuntime());
  const [exportInFlight, setExportInFlight] = useState(false);
  const scanInFlight = useRef(false);

  // The Tauri runtime is injected synchronously in the real webview, but if
  // the first render raced the injection (some loader orderings), re-check
  // on mount. We only set true — never back to false.
  useEffect(() => {
    if (tauriReady) return;
    if (hasTauriRuntime()) setTauriReady(true);
  }, [tauriReady]);

  // Subscribe to scan-progress events while a scan is running. Each event
  // mutates the per-scanner state map. Unsubscribe when the phase leaves
  // "scanning" so stale events from a previous scan can't bleed into a new
  // one.
  useEffect(() => {
    if (phase !== "scanning") return;
    if (!hasTauriRuntime()) return;
    let unlisten: UnlistenFn | null = null;
    let cancelled = false;
    listen<ScanProgressEvent>("scan-progress", (event) => {
      const payload = event.payload;
      setProgress((prev) => {
        const current = prev[payload.scanner] ?? { state: "pending" };
        switch (payload.kind) {
          case "started":
            return { ...prev, [payload.scanner]: { ...current, state: "running" } };
          case "done":
            return {
              ...prev,
              [payload.scanner]: {
                ...current,
                state: "done",
                findings: payload.findings,
              },
            };
          case "heartbeat":
            return {
              ...prev,
              [payload.scanner]: {
                ...current,
                state: "running",
                regionsScanned: payload.regions_scanned,
                bytesScanned: payload.bytes_scanned,
              },
            };
          case "errored":
            return {
              ...prev,
              [payload.scanner]: {
                ...current,
                state: "errored",
                errorMessage: payload.message,
              },
            };
        }
      });
    }).then((fn) => {
      if (cancelled) {
        fn();
      } else {
        unlisten = fn;
      }
    });
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, [phase]);

  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => setToast(null), 3000);
    return () => clearTimeout(id);
  }, [toast]);

  // Clear the open row whenever the filter changes, so a stale selection
  // never surfaces on a different finding.
  useEffect(() => {
    setOpenKey(null);
  }, [filter]);

  const runScan = useCallback(async () => {
    if (scanInFlight.current) return;
    if (!hasTauriRuntime()) {
      setToast({
        msg: "Tauri runtime not detected — launch the app with `npm run tauri dev` or the installed .app, not `npm run dev`.",
        kind: "error",
      });
      return;
    }
    scanInFlight.current = true;
    setPhase("scanning");
    setReport(null);
    setOpenKey(null);
    setFilter("all");
    setProgress(emptyProgress());
    try {
      const result = await invoke<ScanReport>("run_scan");
      setReport(result);
      setPhase("complete");
    } catch (err) {
      setToast({ msg: `Scan failed: ${String(err)}`, kind: "error" });
      setPhase("idle");
    } finally {
      scanInFlight.current = false;
    }
  }, []);

  const exportReport = useCallback(async () => {
    if (!report || exportInFlight) return;
    if (!hasTauriRuntime()) {
      setToast({ msg: "Tauri runtime not detected — cannot export.", kind: "error" });
      return;
    }
    setExportInFlight(true);
    try {
      // Prompt for the destination first via the OS Save-As dialog so the
      // user can pick any directory + filename. Default the suggested name
      // to the legacy timestamped pattern. `save` returns null when the
      // user cancels, in which case we silently abort without surfacing an
      // error toast.
      const ts = new Date(report.timestamp)
        .toISOString()
        .replace(/[-:]/g, "")
        .replace(/\..+/, "")
        .replace("T", "_");
      const chosenPath = await showSaveDialog({
        title: "Save scan report",
        defaultPath: `FlagCheck_Report_${ts}.json`,
        filters: [{ name: "JSON report", extensions: ["json"] }],
      });
      if (!chosenPath) {
        setExportInFlight(false);
        return;
      }
      // The backend re-runs scanners and signs in-memory; we deliberately
      // do NOT pass the on-screen report here. This means the saved file
      // reflects the current machine state at export time, not whatever
      // (potentially tampered) report the webview is holding.
      const path = await invoke<string>("save_report", { path: chosenPath });
      setToast({ msg: `Report saved → ${path}`, kind: "success" });
    } catch (err) {
      setToast({ msg: `Export failed: ${String(err)}`, kind: "error" });
    } finally {
      setExportInFlight(false);
    }
  }, [report, exportInFlight]);

  const counts = useMemo(() => {
    if (!report)
      return { clean: 0, inconclusive: 0, suspicious: 0, flagged: 0, total: 0 };
    return report.findings.reduce(
      (acc, f) => {
        if (f.verdict === "Clean") acc.clean++;
        else if (f.verdict === "Inconclusive") acc.inconclusive++;
        else if (f.verdict === "Suspicious") acc.suspicious++;
        else if (f.verdict === "Flagged") acc.flagged++;
        // Silently ignore unknown verdict strings rather than bucketing
        // them into `flagged` — a counts chip showing "01" with no
        // matching row would confuse operators.
        acc.total++;
        return acc;
      },
      { clean: 0, inconclusive: 0, suspicious: 0, flagged: 0, total: 0 },
    );
  }, [report]);

  const ordered = useMemo(() => {
    if (!report) return [];
    const rank: Record<ScanVerdict, number> = {
      Flagged: 0,
      Suspicious: 1,
      Inconclusive: 2,
      Clean: 3,
    };
    const sorted = [...report.findings].sort(
      (a, b) => rank[a.verdict] - rank[b.verdict],
    );
    if (filter === "all") return sorted;
    return sorted.filter((f) => f.verdict.toLowerCase() === filter);
  }, [report, filter]);

  return (
    <div className="app">
      {!tauriReady && (
        <div className="toast toast--error" style={{ position: "static", margin: "12px 16px 0" }}>
          Tauri runtime not detected. Launch the installed app or run{" "}
          <code>npm run tauri dev</code> — the plain Vite dev server can't reach the backend.
        </div>
      )}
      <Toolbar
        phase={phase}
        report={report}
        onScan={runScan}
        onExport={exportReport}
        disabled={!tauriReady}
        exportInFlight={exportInFlight}
      />
      <Summary
        phase={phase}
        report={report}
        counts={counts}
        progress={progress}
      />
      <Workarea
        phase={phase}
        findings={ordered}
        filter={filter}
        onFilter={setFilter}
        openKey={openKey}
        onToggle={(k) => setOpenKey((prev) => (prev === k ? null : k))}
        onScan={runScan}
        counts={counts}
      />
      <StatusBar phase={phase} report={report} />
      {toast && <div className={`toast toast--${toast.kind}`}>{toast.msg}</div>}
    </div>
  );
}

/* ——————————————————————————————————————————————————————————— */

function Toolbar({
  phase,
  report,
  onScan,
  onExport,
  disabled = false,
  exportInFlight = false,
}: {
  phase: Phase;
  report: ScanReport | null;
  onScan: () => void;
  onExport: () => void;
  disabled?: boolean;
  exportInFlight?: boolean;
}) {
  const lastScan =
    phase === "scanning"
      ? "in progress…"
      : report
        ? relativeTime(new Date(report.timestamp))
        : "never";

  const os = report?.os_info ?? "—";
  const machine = report?.machine_id ?? "—";

  return (
    <header className="toolbar">
      <div className="toolbar__left">
        <div className="brand">
          <span className="brand__logo" />
          <span>Echo</span>
          <span className="brand__sub">/ Integrity</span>
        </div>
        <div className="toolbar__divider" />
        <div className="toolbar__meta">
          <div className="toolbar__meta-cell">
            <span className="toolbar__meta-label">OS</span>
            <span className="toolbar__meta-value">{os}</span>
          </div>
          <div className="toolbar__meta-cell">
            <span className="toolbar__meta-label">Machine</span>
            <span className="toolbar__meta-value">{truncate(machine, 14)}</span>
          </div>
          <div className="toolbar__meta-cell">
            <span className="toolbar__meta-label">Last</span>
            <span className="toolbar__meta-value">{lastScan}</span>
          </div>
        </div>
      </div>
      <div className="toolbar__right">
        {phase === "complete" && report && (
          <button
            className="btn btn--ghost"
            onClick={onExport}
            disabled={disabled || exportInFlight}
          >
            {exportInFlight ? "Saving…" : "Export"}
          </button>
        )}
        <button
          className="btn btn--primary"
          onClick={onScan}
          disabled={phase === "scanning" || disabled}
        >
          {phase === "scanning" ? (
            <>
              <span className="btn__spinner" />
              Scanning
            </>
          ) : phase === "complete" ? (
            "Rescan"
          ) : (
            "Run scan"
          )}
        </button>
      </div>
    </header>
  );
}

/* ——————————————————————————————————————————————————————————— */

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

function Summary({
  phase,
  report,
  counts,
  progress,
}: {
  phase: Phase;
  report: ScanReport | null;
  counts: {
    clean: number;
    inconclusive: number;
    suspicious: number;
    flagged: number;
    total: number;
  };
  progress: ProgressMap;
}) {
  const completedCount = SCANNERS.filter(
    (s) => progress[s.id]?.state === "done" || progress[s.id]?.state === "errored",
  ).length;
  const modifier =
    phase === "scanning"
      ? "summary--scanning"
      : phase === "complete" && report?.overall_verdict === "Clean"
        ? "summary--clean"
        : phase === "complete" && report?.overall_verdict === "Inconclusive"
          ? "summary--inconclusive"
          : phase === "complete" && report?.overall_verdict === "Suspicious"
            ? "summary--warn"
            : phase === "complete" && report?.overall_verdict === "Flagged"
              ? "summary--danger"
              : "";

  const verdictLabel =
    phase === "idle"
      ? "—"
      : phase === "scanning"
        ? "Scanning"
        : report?.overall_verdict ?? "—";

  return (
    <div className={`summary ${modifier}`}>
      <div className="summary__cell">
        <span className="summary__label">Verdict</span>
        <div className="summary__verdict">
          <span className="summary__dot" />
          <span>{verdictLabel}</span>
        </div>
      </div>

      <div className="summary__cell summary__cell--divider">
        <span className="summary__label">
          {phase === "scanning" ? "Probing" : "Findings"}
        </span>
        {phase === "scanning" ? (
          <div className="summary__progress">
            <div className="summary__bar">
              <div
                className="summary__bar-fill"
                style={{
                  width: `${Math.min(100, (completedCount / SCANNERS.length) * 100)}%`,
                }}
              />
            </div>
            <ul className="summary__scanners">
              {SCANNERS.map((s) => {
                const p = progress[s.id];
                const state = p?.state ?? "pending";
                const mem =
                  s.id === "memory_scanner" && state === "running" && p?.bytesScanned
                    ? ` ${formatBytes(p.bytesScanned)} / ${p.regionsScanned ?? 0} regions`
                    : "";
                const count =
                  state === "done" && typeof p?.findings === "number"
                    ? ` ${p.findings}`
                    : "";
                return (
                  <li
                    key={s.id}
                    className={`summary__scanner summary__scanner--${state}`}
                    title={p?.errorMessage ?? ""}
                  >
                    <span className="summary__scanner-mark" aria-hidden>
                      {state === "done"
                        ? "✓"
                        : state === "errored"
                          ? "✕"
                          : state === "running"
                            ? "·"
                            : " "}
                    </span>
                    <span className="summary__scanner-label">{s.label}</span>
                    <span className="summary__scanner-meta">
                      {state === "done"
                        ? count
                        : state === "running"
                          ? mem || "…"
                          : state === "errored"
                            ? "error"
                            : ""}
                    </span>
                  </li>
                );
              })}
            </ul>
          </div>
        ) : (
          <div className="summary__counts">
            <span
              className={
                "summary__count summary__count--danger" +
                (counts.flagged === 0 ? " summary__count--zero" : "")
              }
            >
              <span className="summary__count-num">
                {String(counts.flagged).padStart(2, "0")}
              </span>
              <span className="summary__count-label">flag</span>
            </span>
            <span
              className={
                "summary__count summary__count--warn" +
                (counts.suspicious === 0 ? " summary__count--zero" : "")
              }
            >
              <span className="summary__count-num">
                {String(counts.suspicious).padStart(2, "0")}
              </span>
              <span className="summary__count-label">susp</span>
            </span>
            <span
              className={
                "summary__count summary__count--inconclusive" +
                (counts.inconclusive === 0 ? " summary__count--zero" : "")
              }
            >
              <span className="summary__count-num">
                {String(counts.inconclusive).padStart(2, "0")}
              </span>
              <span className="summary__count-label">incl</span>
            </span>
            <span
              className={
                "summary__count summary__count--clean" +
                (counts.clean === 0 ? " summary__count--zero" : "")
              }
            >
              <span className="summary__count-num">
                {String(counts.clean).padStart(2, "0")}
              </span>
              <span className="summary__count-label">clean</span>
            </span>
          </div>
        )}
      </div>

      <div className="summary__cell">
        <span className="summary__label">Scan</span>
        {report ? (
          <>
            <span className="summary__scanid">
              {truncate(report.scan_id, 18)}
            </span>
            <span className="summary__sub">
              HMAC {truncate(report.hmac_signature, 10)}
            </span>
          </>
        ) : (
          <>
            <span className="summary__scanid">—</span>
            <span className="summary__sub">no report yet</span>
          </>
        )}
      </div>
    </div>
  );
}

/* ——————————————————————————————————————————————————————————— */

function Workarea({
  phase,
  findings,
  filter,
  onFilter,
  openKey,
  onToggle,
  onScan,
  counts,
}: {
  phase: Phase;
  findings: ScanFinding[];
  filter: Filter;
  onFilter: (f: Filter) => void;
  openKey: string | null;
  onToggle: (key: string) => void;
  onScan: () => void;
  counts: {
    clean: number;
    inconclusive: number;
    suspicious: number;
    flagged: number;
    total: number;
  };
}) {
  const chips: { key: Filter; label: string; modifier: string; count: number }[] = [
    { key: "all", label: "All", modifier: "", count: counts.total },
    { key: "flagged", label: "Flag", modifier: "filter-chip--danger", count: counts.flagged },
    { key: "suspicious", label: "Susp", modifier: "filter-chip--warn", count: counts.suspicious },
    {
      key: "inconclusive",
      label: "Incl",
      modifier: "filter-chip--inconclusive",
      count: counts.inconclusive,
    },
    { key: "clean", label: "Clean", modifier: "filter-chip--clean", count: counts.clean },
  ];

  const showChrome = phase === "complete" && counts.total > 0;

  return (
    <div className="work">
      {showChrome && (
        <div className="filters">
          <span className="filters__label">Filter</span>
          {chips.map((c) => (
            <button
              key={c.key}
              type="button"
              aria-pressed={filter === c.key}
              className={`filter-chip ${c.modifier} ${filter === c.key ? "filter-chip--active" : ""}`}
              onClick={() => onFilter(c.key)}
            >
              {c.modifier && <span className="filter-chip__dot" />}
              {c.label}
              <span style={{ color: "var(--text-muted)", marginLeft: 2 }}>
                {c.count}
              </span>
            </button>
          ))}
        </div>
      )}
      {showChrome && (
        <div className="table-head">
          <span />
          <span>Module</span>
          <span>Description</span>
          <span>Verdict</span>
          <span>Time</span>
          <span />
        </div>
      )}

      {phase === "idle" && (
        <div className="empty">
          <span className="empty__title">No scan yet</span>
          <button className="btn btn--ghost" onClick={onScan}>
            Run scan
          </button>
          <span className="empty__hint">
            Inspects processes · files · settings · prefetch · memory
          </span>
        </div>
      )}

      {phase === "scanning" && (
        <div className="empty">
          <span className="empty__title">Inspecting surfaces…</span>
          <span className="empty__hint">Results will populate shortly</span>
        </div>
      )}

      {phase === "complete" && findings.length === 0 && (
        <div className="empty">
          <span className="empty__title">
            {filter === "all" ? "No findings" : `No ${filter} findings`}
          </span>
          {filter !== "all" && (
            <button className="btn btn--ghost" onClick={() => onFilter("all")}>
              Show all
            </button>
          )}
        </div>
      )}

      {phase === "complete" &&
        findings.map((f) => {
          const key = findingKey(f);
          return (
            <FindingRow
              key={key}
              rowKey={key}
              finding={f}
              open={openKey === key}
              onToggle={onToggle}
            />
          );
        })}
    </div>
  );
}

/* ——————————————————————————————————————————————————————————— */

// Memoized so clicking one row to expand it does not force a re-render of
// every other row in the list. With the memory scanner now emitting
// findings for large Roblox processes, finding counts can spike into the
// hundreds — without this memo the main thread stalls long enough that
// buttons stop responding.
type FindingRowProps = {
  rowKey: string;
  finding: ScanFinding;
  open: boolean;
  onToggle: (key: string) => void;
};

const FindingRow = memo(function FindingRow({
  rowKey,
  finding: f,
  open,
  onToggle,
}: FindingRowProps) {
  const cls = `row row--${f.verdict.toLowerCase()} ${open ? "row--open" : ""}`;
  // Verdict glyph supplements color so colorblind users still see severity.
  const glyph =
    f.verdict === "Flagged"
      ? "✕"
      : f.verdict === "Suspicious"
        ? "▲"
        : f.verdict === "Inconclusive"
          ? "?"
          : "•";
  // Tooltip on the verdict cell: explain that Suspicious is operator-review,
  // not auto-accusation — the value-match heap path is capped here so a
  // curated-rule misclassification can never directly cost a player.
  const verdictTitle =
    f.verdict === "Suspicious"
      ? "Suspicious — evidence requires operator review. Will not auto-accuse a player; tournament action requires staff confirmation."
      : f.verdict === "Flagged"
        ? "Flagged — high-confidence evidence (injector markers + curated cheat value, or equivalent multi-signal corroboration)."
        : f.verdict === "Inconclusive"
          ? "Inconclusive — scanner could not run on this platform or coverage was insufficient."
          : "Clean — no evidence of abuse on this path.";
  const handleClick = useCallback(() => onToggle(rowKey), [onToggle, rowKey]);
  const handleKey = useCallback(
    (e: ReactKeyboardEvent) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        onToggle(rowKey);
      }
    },
    [onToggle, rowKey],
  );
  return (
    <div
      className={cls}
      role="button"
      tabIndex={0}
      aria-expanded={open}
      aria-label={`${f.verdict} finding from ${f.module}: ${f.description}. Press Enter to ${open ? "collapse" : "expand"}.`}
      onClick={handleClick}
      onKeyDown={handleKey}
    >
      <span className="row__bar" aria-hidden="true" />
      <span className="row__module">{f.module}</span>
      <span className="row__desc">{f.description}</span>
      <span className="row__verdict" title={verdictTitle}>
        <span aria-hidden="true">{glyph}</span> {f.verdict.toLowerCase()}
      </span>
      <span className="row__time">{shortTime(f.timestamp)}</span>
      <span className="row__caret" aria-hidden="true">›</span>
      <div className="row__details">
        <div className="row__details-inner">
          {/* Only render the inner content when open. The outer
              .row__details box is kept unconditionally so the CSS
              max-height transition still has something to animate. */}
          {open ? <FindingDetails details={f.details} /> : null}
        </div>
      </div>
    </div>
  );
});

/* ——————————————————————————————————————————————————————————— */

// Parse a finding's `details` string into a list of {label, value} pairs so
// the UI can render them as a clean two-column grid instead of a single
// `Key: foo | Key: bar | Key: baz` line. Backend scanners use either ` | `
// (memory_scanner) or `, ` (file_scanner) as the separator between KV
// segments — for the comma form we only split when the next segment looks
// like a `Capitalized-key:` so commas inside paths or notes don't shred
// values. Anything that doesn't parse as KV is rendered as a freeform note.
type DetailField = { label: string; value: string };

function parseFindingDetails(details: string): {
  fields: DetailField[];
  freeform: string | null;
} {
  const trimmed = details.trim();
  if (!trimmed) return { fields: [], freeform: null };

  const segments = trimmed.includes(" | ")
    ? trimmed.split(" | ")
    : trimmed.split(/, (?=[A-Z][\w .-]*?:\s)/);

  const fields: DetailField[] = [];
  const leftovers: string[] = [];
  for (const raw of segments) {
    const seg = raw.trim();
    if (!seg) continue;
    const colon = seg.indexOf(":");
    if (colon <= 0 || colon > 40) {
      leftovers.push(seg);
      continue;
    }
    const label = seg.slice(0, colon).trim();
    const value = seg.slice(colon + 1).trim();
    if (!label || !value || /\s/.test(label) && !/^[A-Z][\w .-]*$/.test(label)) {
      leftovers.push(seg);
      continue;
    }
    fields.push({ label, value });
  }
  return {
    fields,
    freeform: leftovers.length ? leftovers.join(" · ") : null,
  };
}

function FindingDetails({ details }: { details: string | null }) {
  const parsed = useMemo(
    () => (details ? parseFindingDetails(details) : null),
    [details],
  );
  if (!details || !parsed) {
    return <span className="row__details-empty">No additional details.</span>;
  }
  if (parsed.fields.length === 0) {
    return <span className="row__details-freeform">{details}</span>;
  }
  return (
    <>
      <dl className="row__details-grid">
        {parsed.fields.map((f, i) => (
          <div className="row__details-row" key={`${f.label}-${i}`}>
            <dt className="row__details-key">{f.label}</dt>
            <dd className="row__details-value">{f.value}</dd>
          </div>
        ))}
      </dl>
      {parsed.freeform && (
        <p className="row__details-freeform">{parsed.freeform}</p>
      )}
    </>
  );
}

/* ——————————————————————————————————————————————————————————— */

function StatusBar({
  phase,
  report,
}: {
  phase: Phase;
  report: ScanReport | null;
}) {
  const state =
    phase === "idle"
      ? "Idle"
      : phase === "scanning"
        ? "Inspecting"
        : report?.overall_verdict ?? "Done";

  const dotCls =
    phase === "scanning"
      ? "statusbar__dot statusbar__dot--warn"
      : phase === "complete" && report?.overall_verdict === "Flagged"
        ? "statusbar__dot statusbar__dot--flag"
        : phase === "complete" && report?.overall_verdict === "Suspicious"
          ? "statusbar__dot statusbar__dot--susp"
          : phase === "complete" && report?.overall_verdict === "Inconclusive"
            ? "statusbar__dot statusbar__dot--inconclusive"
            : phase === "complete"
              ? "statusbar__dot statusbar__dot--live"
              : "statusbar__dot";

  return (
    <footer className="statusbar">
      <div className="statusbar__group">
        <span>
          <span className={dotCls} />
          {state}
        </span>
        <span className="statusbar__sep">·</span>
        <span>TSBCC v{APP_VERSION}</span>
      </div>
      <div className="statusbar__group">
        <span>Local only</span>
        <span className="statusbar__sep">·</span>
        <span>HMAC-SHA256</span>
      </div>
    </footer>
  );
}

/* ——————————————————————————————————————————————————————————— */

/* ——————————————————————————————————————————————————————————— */

class ErrorBoundary extends Component<
  { children: ReactNode },
  { error: Error | null }
> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: { componentStack?: string | null }) {
    // eslint-disable-next-line no-console
    console.error("UI error boundary caught:", error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="empty" style={{ padding: "32px 16px" }}>
          <span className="empty__title">Something broke in the UI</span>
          <span className="empty__hint">
            {this.state.error.message || "Unknown error"}
          </span>
          <button
            className="btn btn--ghost"
            onClick={() => {
              this.setState({ error: null });
              if (typeof window !== "undefined") window.location.reload();
            }}
          >
            Reload
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

export default function App() {
  return (
    <ErrorBoundary>
      <AppInner />
    </ErrorBoundary>
  );
}

/* ——————————————————————————————————————————————————————————— */

function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.slice(0, n) + "…";
}

function shortTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function relativeTime(d: Date): string {
  const diff = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diff < 5) return "just now";
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return d.toLocaleDateString();
}
