use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::*;

pub fn init<R: Runtime, C: DeserializeOwned>(
  app: &AppHandle<R>,
  _api: PluginApi<R, C>,
) -> crate::Result<LowertierVpn<R>> {
  Ok(LowertierVpn(app.clone()))
}

/// Access to the lowertier-vpn APIs.
pub struct LowertierVpn<R: Runtime>(AppHandle<R>);

impl<R: Runtime> LowertierVpn<R> {
  pub fn execute(&self, _payload: Request) -> crate::Result<serde_json::Value> {
    let _ = &self.0;
    Err(std::io::Error::new(
      std::io::ErrorKind::Unsupported,
      "Native VPN control requires the iOS app.",
    ).into())
  }
}
