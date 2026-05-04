# TSBCC FFlag Scanner

A cross-platform desktop tool for detecting FFlag abuse in competitive Roblox tournaments. Built with Rust + Tauri and React + TypeScript.

Tournament players run this scanner before matches. Staff review the generated report to verify the player's system is clean — similar to how Echo works for Minecraft screenshares, but purpose-built for Roblox FFlag detection.

![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS-lightgrey)
![Built with](https://img.shields.io/badge/built%20with-Tauri%20v2-orange)

---

## Why this exists

Roblox's September 2025 FFlag allowlist (the "18 official flags") restricts which Fast Flags players can override via `ClientAppSettings.json`, but determined players bypass it using memory injectors and offset-based tools that write FFlag values directly into Roblox's heap at runtime. Modified Fast Flags remain a major integrity threat for competitive Roblox — desync, physics manipulation, visual exploits, and animation hiding all stem from FFlag abuse.

The Strongest Battlegrounds competitive scene currently lacks a dedicated FFlag screening tool. This is one.

---

## What it scans

### Process Scanner
Enumerates all running processes and flags known cheat / injection tools — Voidstrap, the major 2026 Roblox executors (Wave, Solara, Hydrogen, Krampus, Fluxus, Krnl, …), plus generic memory-inspection tooling (Cheat Engine, x64dbg, ProcessHacker / SystemInformer, ReClass, HxD, Extreme Injector). If Roblox is running alongside a flagged tool, severity is elevated.

Legitimate Roblox launchers (Bloxstrap, Fishstrap, AppleBlox) are reported as **informational only** — per Roblox's own automated-action policy they are not cheat indicators.

### File Scanner
Searches the filesystem for tool artifacts in common locations (Downloads, Desktop, AppData, Application Support). Detects known tool directories and executables by name. Each path is reported at most once even when multiple search roots overlap.

### Client Settings Scanner
Parses Roblox's `ClientAppSettings.json` and bootstrapper configs:
- **Windows:** `%LocalAppData%\Roblox\Versions\*\ClientSettings\` plus Bloxstrap / Voidstrap / Fishstrap modification directories, plus the FFlagToolkit injector config under `%AppData%`.
- **macOS:** `/Applications/Roblox.app/Contents/MacOS/ClientSettings/ClientAppSettings.json` (the bundle-internal path used by the native client) plus `~/Library/Roblox/ClientSettings/` as a fallback, and AppleBlox configs / profiles.

Every detected FFlag is classified against:
- **Allowlist** — the 18 officially-permitted flags from Roblox's Sept 29, 2025 announcement (https://devforum.roblox.com/t/3966569). A `ClientAppSettings.json` containing only allowlisted flags produces a Clean finding, not Suspicious.
- **Critical / High / Medium / Low tiers** — non-allowlisted flags categorized by exploit potential (desync, visual advantage, etc.).
- **Unknown** — flag-shaped overrides not in the database, emitted as Clean informational entries so staff can review them without turning an outdated local database into a warning by itself.

### Prefetch Scanner (Windows)
Reads `C:\Windows\Prefetch\*.pf` to detect execution history of known tools — catches players who uninstall tools before running the scanner.

### Memory Scanner (Windows)
Reads Roblox's process memory to detect runtime FFlag injections that bypass the file-based allowlist:
- Uses `OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)`, `VirtualQueryEx`, and `ReadProcessMemory` against committed non-image regions.
- Skips `MEM_IMAGE` regions to avoid false positives from FFlag string literals living in the unmodified `.text` segment.
- Refuses to scan a Roblox-named process whose executable path is outside a trusted Roblox install root (closes the decoy attack: dropping a renamed empty binary called `RobloxPlayerBeta.exe` no longer redirects the scan to it).
- Trusted UWP roots are scoped to the `ROBLOXCORPORATION.` package family, not the entire `WindowsApps` / `Packages` store.

The macOS memory path is intentionally **not implemented** in this build. Detection on macOS relies on the file/process/prefetch/client-settings scanners only.

---

## What this scanner does NOT detect (be honest)

- **Cheats that patch FFlag *values* after the string literal has been freed** — if the integer is modified in memory but no name string remains, the memory scanner has nothing to match.
- **VM / second-machine setups** — the scanner only sees the machine it's running on.
- **Compromised allowlisted-flag values** — Roblox permits the 18 allowlisted flags to be set; the scanner does not check whether their *values* are abusive.
- **Hyperion-mediated obfuscation** — Hyperion (Byfron) on Windows is user-mode and does not block third-party `ReadProcessMemory` against `RobloxPlayerBeta.exe` (per Roblox staff statement, https://devforum.roblox.com/t/4510318), but it does encrypt the `.text` section. The scanner skips `MEM_IMAGE` so this doesn't cause false negatives — but if a future Hyperion update kernel-blocks RPM, the Windows memory path will return nothing useful.

---

## Trust model

Each scan generates a JSON report:
- **HMAC-SHA256 signed** with a per-build random key generated by `build.rs` and burned into the binary.
- **Machine ID** — SHA256 of the platform machine identifier (macOS `IOPlatformUUID` via absolute-path `/usr/sbin/ioreg`; Windows `MachineGuid` via absolute-path `reg.exe`). The lookup binaries are absolute-pathed so a player can't shadow them via `$PATH`.
- **256-bit scan_id** derived from four independent OS-RNG seeds, hashed with SHA-256.
- **Timestamped** — `validate_report` rejects reports older than 30 minutes (with a 2-minute future-clock-skew tolerance).
- **Three-tier verdict:** `Clean` / `Suspicious` / `Flagged`.

### Verdict tiers

- **`Clean`** — no evidence of FFlag abuse on any scanner path.
- **`Suspicious`** — evidence consistent with abuse, but the signal alone is not strong enough to auto-accuse. Requires operator review before any tournament action. The heap string-scan value-match path is **deliberately capped at Suspicious** — it can never auto-Flag — so that a future curated-rule misclassification, a rare vanilla heap coincidence, or any other low-confidence signal cannot directly cost a player their entry.
- **`Flagged`** — high-confidence evidence: injector tool markers within the proximity window of a known-suspicious flag, a live FastFlag registry override carrying a curated cheat value, or equivalent multi-signal corroboration. Tournaments may treat this as ship-blocking.

Reports are saved (or to the location chosen via the Save-As dialog) as `Prism_Report_{timestamp}.json`.

### Limits of the current trust model

- **The HMAC key lives in the binary.** A player who reverse-engineers their copy can forge reports verifiable against THAT build. Per-build randomization makes forgery non-portable across releases, but it is not a replacement for server-side validation. For high-stakes tournaments, the validation step should happen on a TSBCC-controlled server using a server-side key.
- **The machine ID is editable** by an admin user (Windows registry) or a privileged macOS user. Treat machine_id as a soft fingerprint, not an attestation.
- **`save_report` re-runs scanners in the backend** rather than trusting whatever the webview displays — so a tampered frontend can't get a forged report signed and saved. A player would have to patch the binary itself, which is detectable by checksumming the released build.

If you need stronger guarantees: distribute scanner builds with code-signed installers (signed Windows MSI, notarized macOS DMG) and have staff verify the binary checksum before trusting any report it produces.

---

## Building from source

### Prerequisites
- [Rust](https://rustup.rs/) (1.78+)
- [Node.js](https://nodejs.org/) (22 LTS recommended)
- Platform-specific Tauri dependencies: [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)

### Development
```bash
npm install
npm run tauri dev
```

### Production build
```bash
npm run tauri build
```

**macOS output:**
```
src-tauri/target/release/bundle/macos/TSBCC FFlag Scanner.app
src-tauri/target/release/bundle/dmg/TSBCC FFlag Scanner_<version>_aarch64.dmg
```

**Windows output:**
```
src-tauri/target/release/bundle/msi/TSBCC FFlag Scanner_<version>_x64.msi
src-tauri/target/release/bundle/nsis/TSBCC FFlag Scanner_<version>_x64-setup.exe
```

CI publishes one portable Windows scanner `.exe` (no installer) plus macOS Intel and Apple Silicon `.dmg`s on every `v*` tag.

---

## Project structure

```
prism/
├── src/                          # React + TypeScript frontend
│   ├── App.tsx                   # Main app + ErrorBoundary
│   ├── main.tsx                  # React root
│   ├── styles.css
│   └── types.ts
├── src-tauri/
│   ├── src/
│   │   ├── lib.rs                # Tauri app entry point
│   │   ├── commands.rs           # run_scan, save_report, validate_report
│   │   ├── models/
│   │   │   ├── scan_result.rs    # ScanVerdict, ScanFinding
│   │   │   └── scan_report.rs    # ScanReport with HMAC signing & freshness
│   │   ├── scanners/
│   │   │   ├── mod.rs            # Dispatches scanners via spawn_blocking
│   │   │   ├── process_scanner.rs
│   │   │   ├── file_scanner.rs
│   │   │   ├── client_settings_scanner.rs
│   │   │   ├── prefetch_scanner.rs
│   │   │   └── memory_scanner.rs
│   │   ├── reports/
│   │   │   └── report_generator.rs
│   │   └── data/
│   │       ├── known_tools.rs    # Cheat tool / executor signatures
│   │       ├── flag_allowlist.rs # The 18 official Roblox allowed flags
│   │       └── suspicious_flags.rs
│   ├── build.rs                  # Generates per-build HMAC key
│   ├── capabilities/default.json # Tauri v2 capability manifest
│   └── Cargo.toml
├── .github/workflows/release.yml # Test job + Windows / macOS builds
├── package.json
└── vite.config.ts
```

---

## Known limitations

- **Memory-only FFlag changes are invisible if the integer is patched without a residual string** — see "What this scanner does NOT detect" above.
- **Players can use VMs or alt machines** to bypass PC scanning entirely.
- **Tool signature lists require ongoing maintenance** as new bypass tools emerge. The 2026 executor list (Wave / Solara / Hydrogen / etc.) was current at last verify; check `src-tauri/src/data/known_tools.rs` for the canonical set and update as the ecosystem changes.
- **The HMAC key is in the binary.** Per-build randomization helps but does not eliminate the fundamental client-side-key problem; for high-stakes use, validate reports server-side.

These are the same fundamental limitations any client-side scanner faces. The tool raises the bar significantly for casual cheaters while acknowledging that determined actors require additional measures (manual screenshare, server-side detection, etc.).

---

## License

MIT
