use super::super::{
    args::{ServiceArgs, ServiceCommand},
    client::Response,
    error::{CliError, Result},
};
use crate::service_manager::{Service, ServiceInstallOptions, ServiceStatus};

pub fn execute(args: &ServiceArgs) -> Result<Response> {
    let run = || -> anyhow::Result<Response> {
        let service = Service::new(args.name.clone())?;
        let status = match &args.command {
            ServiceCommand::Install(install) => {
                let program = match &install.core_path {
                    Some(path) => path.clone(),
                    None => std::env::current_exe()?.with_file_name(if cfg!(windows) {
                        "lowertier-core.exe"
                    } else {
                        "lowertier-core"
                    }),
                }
                .canonicalize()?;
                let directory = install
                    .service_work_dir
                    .clone()
                    .unwrap_or_else(|| {
                        if cfg!(windows) {
                            program.parent().unwrap().to_path_buf()
                        } else {
                            std::env::temp_dir()
                        }
                    })
                    .canonicalize()?;
                anyhow::ensure!(
                    directory.is_dir(),
                    "The service work directory must be a directory."
                );
                service.install(&ServiceInstallOptions {
                    program,
                    args: install.core_args.clone(),
                    work_directory: directory,
                    disable_autostart: install.disable_autostart.unwrap_or(false),
                    description: Some(install.description.clone()),
                    display_name: install.display_name.clone(),
                    disable_restart_on_failure: install.disable_restart_on_failure.unwrap_or(false),
                })?;
                "installed"
            }
            ServiceCommand::Uninstall => {
                service.uninstall()?;
                "not_installed"
            }
            ServiceCommand::Start => {
                service.start()?;
                "running"
            }
            ServiceCommand::Stop => {
                service.stop()?;
                "stopped"
            }
            ServiceCommand::Status => match service.status()? {
                ServiceStatus::Running => "running",
                ServiceStatus::Stopped(_) => "stopped",
                ServiceStatus::NotInstalled => "not_installed",
            },
        };
        Ok(Response::Service {
            name: args.name.clone(),
            status: status.into(),
        })
    };
    run().map_err(|error| {
        let code = if error
            .chain()
            .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
            .any(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
        {
            "permission_denied"
        } else {
            "internal"
        };
        CliError::new(code, "The local service operation failed.", "service")
    })
}
