mod proxy;

use proxy::{ProxyConfig, ProxyState, ProxyStats};
use std::sync::Arc;
use tauri::State;

type AppState = Arc<ProxyState>;

#[tauri::command]
async fn connect(state: State<'_, AppState>, config: ProxyConfig) -> Result<String, String> {
    state
        .connect(config)
        .await
        .map_err(|e| e.to_string())?;
    Ok("connected".into())
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<String, String> {
    state
        .disconnect()
        .await
        .map_err(|e| e.to_string())?;
    Ok("disconnected".into())
}

#[tauri::command]
async fn get_stats(state: State<'_, AppState>) -> Result<ProxyStats, String> {
    Ok(state.get_stats().await)
}

#[tauri::command]
async fn get_profiles(state: State<'_, AppState>) -> Result<Vec<ProxyConfig>, String> {
    Ok(state.get_profiles().await)
}

#[tauri::command]
async fn save_profile(state: State<'_, AppState>, profile: ProxyConfig) -> Result<(), String> {
    state
        .save_profile(profile)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn delete_profile(state: State<'_, AppState>, name: String) -> Result<(), String> {
    state
        .delete_profile(&name)
        .await
        .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state = Arc::new(ProxyState::new());

    tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::default().build())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            connect,
            disconnect,
            get_stats,
            get_profiles,
            save_profile,
            delete_profile,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
