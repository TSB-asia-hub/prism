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
        .invoke_handler(tauri::generate_handler![
            commands::run_scan,
            commands::save_report,
            commands::validate_report,
            commands::import_report,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
