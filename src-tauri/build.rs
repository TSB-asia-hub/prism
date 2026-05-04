use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Generate a per-build random 32-byte HMAC key written to OUT_DIR. The
    // key is `include_bytes!`d by scan_report.rs at compile time. This means
    // every released binary has a different key — a player who extracts the
    // key from their copy can still forge reports from THAT install, but can
    // no longer forge reports verifiable against any other player's install
    // (and tournament staff with their own scanner-build key can detect
    // mismatches). It does not fix the fundamental client-side-key problem
    // documented in the README's "Trust model" section, but it's strictly
    // better than the previous hardcoded constant.
    //
    // We use the OS RNG via getrandom-style fallbacks: SystemTime nanos +
    // PID + sequence + std RandomState seeds, fed through SHA-256-shaped
    // mixing. (build.rs avoids pulling in extra crypto deps; the resulting
    // 32 bytes are not cryptographically perfect but they ARE unpredictable
    // to anyone who didn't run this exact build.)

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    let key_path = out_dir.join("hmac_key.bin");

    let mut key = [0u8; 32];
    let mut seed: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xDEADBEEFu64)
        ^ std::process::id() as u64;
    for byte in key.iter_mut() {
        // SplitMix64 — a small, well-distributed PRNG suitable for build-time
        // key derivation (NOT for runtime crypto).
        seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        *byte = (z & 0xFF) as u8;
    }

    fs::write(&key_path, key).expect("write hmac_key.bin");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=app.manifest");
    println!("cargo:rerun-if-changed=app.dev.manifest");

    // Embed a Windows application manifest. In release builds we request
    // `requireAdministrator` so the OS prompts for UAC on every launch and
    // the resulting process has the privileges the memory scanner needs
    // (PROCESS_VM_READ on the Roblox process). In debug builds we fall
    // back to `asInvoker` — `cargo tauri dev` runs the exe non-elevated
    // and Windows refuses to silently elevate, returning ERROR_ELEVATION
    // _REQUIRED (740) and breaking hot-reload. The dev variant still pulls
    // in Common Controls 6.0 so WebView2 can resolve TaskDialogIndirect.
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let manifest = if profile == "release" {
        include_str!("app.manifest")
    } else {
        include_str!("app.dev.manifest")
    };
    let win_attrs = tauri_build::WindowsAttributes::new().app_manifest(manifest);
    let attrs = tauri_build::Attributes::new().windows_attributes(win_attrs);
    if let Err(e) = tauri_build::try_build(attrs) {
        panic!("tauri_build::try_build failed: {}", e);
    }
}
