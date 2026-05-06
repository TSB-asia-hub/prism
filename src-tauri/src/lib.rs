mod commands;
pub mod data;
pub mod models;
mod reports;
mod scanners;
mod util;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        // Shared cancellation flag for run_scan / cancel_scan. Stored in
        // state so the cancel command and run_scan see the same Arc.
        .manage(scanners::progress::CancelToken::new())
        .invoke_handler(tauri::generate_handler![
            commands::run_scan,
            commands::save_report,
            commands::validate_report,
            commands::import_report,
            commands::open_finding_folder,
            commands::cancel_scan,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
