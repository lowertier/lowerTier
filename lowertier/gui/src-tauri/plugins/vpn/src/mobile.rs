use serde::de::DeserializeOwned;
use tauri::{
  plugin::{PluginApi, PluginHandle},
  AppHandle, Runtime,
};

use crate::models::*;

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_lowertier_vpn);

// initializes the Kotlin or Swift plugin classes
pub fn init<R: Runtime, C: DeserializeOwned>(
  _app: &AppHandle<R>,
  api: PluginApi<R, C>,
) -> crate::Result<LowertierVpn<R>> {
  #[cfg(target_os = "ios")]
  let handle = api.register_ios_plugin(init_plugin_lowertier_vpn)?;
  Ok(LowertierVpn(handle))
}

/// Access to the lowertier-vpn APIs.
pub struct LowertierVpn<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> LowertierVpn<R> {
  pub fn execute(&self, payload: Request) -> crate::Result<serde_json::Value> {
    self
      .0
      .run_mobile_plugin("execute", payload)
      .map_err(Into::into)
  }
}
