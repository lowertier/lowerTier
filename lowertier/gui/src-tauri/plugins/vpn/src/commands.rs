use tauri::{AppHandle, Runtime, command};

use crate::{LowertierVpnExt, models::Request};

#[command]
pub(crate) async fn execute<R: Runtime>(
    app: AppHandle<R>,
    action: String,
    payload: String,
) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        app.lowertier_vpn()
            .execute(Request { action, payload })
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}
