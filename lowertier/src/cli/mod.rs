pub mod args;
pub(crate) mod client;
pub(crate) mod commands;
pub(crate) mod error;
mod remote;
pub(crate) mod render;

use args::{Arguments, Command, ConfigCommand, GuiArgs, Output, PageArgs};
use clap::Parser;
use client::{Client, Response};
use error::{CliError, Result};
use std::process::ExitCode;

fn output_from_args(args: &[std::ffi::OsString]) -> Output {
    for (index, arg) in args.iter().enumerate().skip(1) {
        if arg == "--output=json"
            || arg == "-ojson"
            || arg == "-o=json"
            || (arg == "--output" || arg == "-o")
                && args.get(index + 1).is_some_and(|value| value == "json")
        {
            return Output::Json;
        }
    }
    Output::Table
}

/// Entry point of the `lowertier` binary.
pub async fn main() -> ExitCode {
    let raw = std::env::args_os().collect::<Vec<_>>();
    let request_id = uuid::Uuid::new_v4().to_string();
    let args = match Arguments::try_parse_from(&raw) {
        Ok(args) => args,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp
                    | clap::error::ErrorKind::DisplayVersion
                    | clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            ) =>
        {
            let code = match error.kind() {
                clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => 2,
                _ => 0,
            };
            return match render::help(&error, output_from_args(&raw), &request_id) {
                Ok(()) => ExitCode::from(code),
                Err(_) => ExitCode::FAILURE,
            };
        }
        Err(error) => {
            let output = output_from_args(&raw);
            // Parser context can contain supplied secrets. Keep JSON errors generic.
            let failure = CliError::new(
                "invalid_argument",
                "The command arguments are invalid. Use --help.",
                "arguments",
            );
            if output == Output::Json {
                let _ = render::write_error(output, &request_id, "", &failure);
            } else {
                render::clap_message(&error);
            }
            return ExitCode::from(2);
        }
    };
    if let Command::Run(run) = args.command {
        return crate::core::run(crate::core::RunOptions {
            config_files: run.config,
            config_dir: run.config_dir,
            sets: run.sets,
            daemon: run.daemon,
            log_level: run.log_level,
        })
        .await;
    }
    ExitCode::from(dispatch(&args, &request_id).await)
}

fn local_text(text: String) -> Result<Response> {
    Ok(Response::Text { text })
}

async fn local(args: &Arguments) -> Result<Response> {
    let invalid =
        |error: anyhow::Error| CliError::new("invalid_argument", format!("{error:#}"), "");
    match &args.command {
        Command::Init(init) => {
            let join = init
                .join
                .as_deref()
                .map(crate::common::join_code::JoinCode::decode)
                .transpose()
                .map_err(invalid)?;
            let joining = join.as_ref().map(|join| join.network.clone());
            let written = crate::core::init(&crate::core::InitOptions {
                output: init.file.clone(),
                network: init.network.clone(),
                listen_port: init.listen,
                peers: init.peers.clone(),
                tun_mode: init.tun.clone(),
                ipv4: init.ipv4.clone(),
                join,
                force: init.force,
            })
            .map_err(invalid)?;
            let files = written
                .iter()
                .map(|path| format!("  {}\n", path.display()))
                .collect::<String>();
            let share = match joining {
                Some(network) => format!("The node joins network {network:?} when it starts."),
                None => "Share the network name and the secret file with peers. Keep the .key \
                         file private."
                    .into(),
            };
            local_text(format!(
                "Wrote\n{files}\nStart the node:\n  lowertier run -c {}\n\n{share}\n",
                init.file.display()
            ))
        }
        Command::Check(check) => {
            let files = crate::core::check(&check.config, &check.sets)
                .await
                .map_err(invalid)?;
            local_text(files.iter().map(|file| format!("ok  {file}\n")).collect())
        }
        Command::Nodes => Ok(Response::Nodes {
            nodes: crate::common::runtime_registry::live_records(),
        }),
        Command::Config {
            command: ConfigCommand::Explain { path },
        } => local_text(crate::common::config_schema::explain(path.as_deref()).map_err(invalid)?),
        Command::Service(service) => commands::service::execute(service),
        _ => unreachable!("not a local command"),
    }
}

#[cfg(feature = "gui")]
async fn gui_serve(args: &Arguments, gui: &GuiArgs) -> Result<()> {
    crate::gui::serve(args, gui).await
}

#[cfg(not(feature = "gui"))]
async fn gui_serve(_: &Arguments, _: &GuiArgs) -> Result<()> {
    Err(CliError::new(
        "invalid_argument",
        "This build has no GUI. Rebuild with the gui feature.",
        "gui",
    ))
}

async fn dispatch(args: &Arguments, request_id: &str) -> u8 {
    if let Command::Ssh {
        target,
        tty,
        command,
    } = &args.command
    {
        return match remote::ssh(args, request_id, target, *tty, command).await {
            Ok(code) => code,
            Err(error) => {
                let code = error.exit_code();
                let _ = render::write_error(args.output, request_id, "", &error);
                code
            }
        };
    }
    if let Command::Completion { shell } = &args.command {
        return match render::completion(shell, args.output, request_id) {
            Ok(()) => 0,
            Err(_) => 1,
        };
    }
    if args.command.local() {
        return finish(args, request_id, "", local(args).await);
    }
    if let Command::Gui(gui) = &args.command {
        return match gui_serve(args, gui).await {
            Ok(()) => 0,
            Err(error) => {
                let _ = render::write_error(args.output, request_id, "", &error);
                error.exit_code()
            }
        };
    }
    if let Command::Doctor = args.command {
        let (response, failed) = commands::doctor::execute(args).await;
        let code = finish(args, request_id, "", Ok(response));
        return if failed { 7 } else { code };
    }
    let mut client = match Client::connect(args, request_id.to_owned()).await {
        Ok(client) => client,
        Err(error) => {
            return finish(
                args,
                request_id,
                args.instance.as_deref().unwrap_or(""),
                Err(error),
            );
        }
    };
    if args.verbose > 0 {
        render::diagnostic(&format!(
            "portal {} ({}); instance {}; token {}",
            client.target.portal,
            client.target.name.as_deref().unwrap_or("unnamed"),
            client.meta.instance_id,
            client.target.token_file.display()
        ));
    }
    if let Command::Top(top) = &args.command {
        return match crate::tui::run(client, std::time::Duration::from_millis(top.interval)).await {
            Ok(()) => 0,
            Err(error) => {
                let _ = render::write_error(args.output, request_id, "", &error);
                error.exit_code()
            }
        };
    }
    let streaming = matches!(
        args.command,
        Command::Stats { watch: true, .. } | Command::Logs { follow: true, .. }
    );
    if streaming {
        let result = tokio::select! {
            result = stream(args, &mut client) => result,
            result = tokio::signal::ctrl_c() => result.map_err(|_| CliError::new("internal", "Cannot receive the interrupt signal.", "")),
        };
        match result {
            Ok(()) => 0,
            Err(error) => finish(
                args,
                &client.meta.request_id,
                &client.meta.instance_id,
                Err(error),
            ),
        }
    } else {
        finish(
            args,
            request_id,
            &client.meta.instance_id,
            commands::execute(&client, &args.command).await,
        )
    }
}

fn finish(args: &Arguments, request_id: &str, instance_id: &str, result: Result<Response>) -> u8 {
    match result {
        Ok(response) => {
            match render::write_response(args.output, request_id, instance_id, &response) {
                Ok(()) => 0,
                Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => 0,
                Err(_) => 1,
            }
        }
        Err(error) => {
            let _ = render::write_error(args.output, request_id, instance_id, &error);
            error.exit_code()
        }
    }
}

async fn stream(args: &Arguments, client: &mut Client) -> Result<()> {
    let logs = matches!(args.command, Command::Logs { .. });
    let resource = if logs { "logs" } else { "stats" };
    let mut cursor = commands::stats::wait(client, resource, String::new())
        .await?
        .cursor;
    let mut page = match &args.command {
        Command::Logs { page, .. } => PageArgs {
            limit: page.limit,
            page_token: page.page_token.clone(),
        },
        _ => PageArgs::default(),
    };
    // Follow from the newest lines unless a cursor was given.
    let mut first = logs && page.page_token.is_empty();
    loop {
        client.meta.request_id = uuid::Uuid::new_v4().to_string();
        let (response, more) = if first {
            first = false;
            let entries = commands::log::tail(client, page.limit).await?;
            page.page_token = entries.next_page_token.clone();
            (Response::from(entries), false)
        } else if logs {
            let entries = commands::log::read(client, &page).await?;
            let more = entries.logs.len() == page.limit as usize;
            page.page_token = entries.next_page_token.clone();
            (Response::from(entries), more)
        } else {
            (commands::execute(client, &args.command).await?, false)
        };
        if let Err(error) = render::write_response(
            args.output,
            &client.meta.request_id,
            &client.meta.instance_id,
            &response,
        ) {
            if error.kind() == std::io::ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(CliError::new(
                "internal",
                "Cannot write the command output.",
                "",
            ));
        }
        if more {
            continue;
        }
        loop {
            let change = commands::stats::wait(client, resource, cursor).await?;
            cursor = change.cursor;
            if change.reset {
                page.page_token.clear();
            }
            if change.reset || !change.changed.is_empty() {
                break;
            }
        }
    }
}
