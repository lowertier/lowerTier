use tauri::{
  plugin::{Builder, TauriPlugin},
  Manager, Runtime,
};

pub use models::*;

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

mod commands;
mod error;
mod models;

pub use error::{Error, Result};

#[cfg(desktop)]
use desktop::LowertierVpn;
#[cfg(mobile)]
use mobile::LowertierVpn;

/// Extensions to [`tauri::App`], [`tauri::AppHandle`] and [`tauri::Window`] to access the lowertier-vpn APIs.
pub trait LowertierVpnExt<R: Runtime> {
  fn lowertier_vpn(&self) -> &LowertierVpn<R>;
}

impl<R: Runtime, T: Manager<R>> crate::LowertierVpnExt<R> for T {
  fn lowertier_vpn(&self) -> &LowertierVpn<R> {
    self.state::<LowertierVpn<R>>().inner()
  }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
  Builder::new("lowertier-vpn")
    .invoke_handler(tauri::generate_handler![commands::execute])
    .setup(|app, api| {
      #[cfg(mobile)]
      let lowertier_vpn = mobile::init(app, api)?;
      #[cfg(desktop)]
      let lowertier_vpn = desktop::init(app, api)?;
      app.manage(lowertier_vpn);
      Ok(())
    })
    .build()
}
