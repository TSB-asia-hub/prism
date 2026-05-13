// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(feature = "ui")]
fn main() {
    prism_lib::run()
}

#[cfg(not(feature = "ui"))]
fn main() {
    eprintln!("prism: ui feature is disabled; run a tools/* binary instead.");
}
