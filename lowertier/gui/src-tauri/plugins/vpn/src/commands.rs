use tauri::{AppHandle, Runtime, command};

use crate::{LowertierVpnExt, models::Request};

#[command]
pub(crate) async fn execute<R: Runtime>(
    app: AppHandle<R>,
    action: String,
    payload: serde_json::Value,
) -> Result<serde_json::Value, String> {
    app.lowertier_vpn()
        .execute(Request { action, payload })
        .await
        .map_err(|error| error.to_string())
}
