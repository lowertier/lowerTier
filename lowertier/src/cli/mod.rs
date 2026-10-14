pub mod args;
mod client;
mod commands;
mod error;
mod render;

use args::{Arguments, Command, LogCommand, Output, PageArgs, StatsCommand};
use clap::Parser;
use client::{Client, Response};
use error::{CliError, Result};

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

pub async fn run() -> u8 {
    let raw = std::env::args_os().collect::<Vec<_>>();
    let request_id = uuid::Uuid::new_v4().to_string();
    let args = match Arguments::try_parse_from(&raw) {
        Ok(args) => args,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            return match render::help(&error, output_from_args(&raw), &request_id) {
                Ok(()) => 0,
                Err(_) => 1,
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
            return 2;
        }
    };
    if let Command::Completion { shell } = &args.command {
        return match render::completion(shell, args.output, &request_id) {
            Ok(()) => 0,
            Err(_) => 1,
        };
    }
    if let Command::Service(service) = &args.command {
        return finish(&args, &request_id, "", commands::service::execute(service));
    }
    let mut client = match Client::connect(&args, request_id.clone()).await {
        Ok(client) => client,
        Err(error) => {
            return finish(
                &args,
                &request_id,
                args.instance.as_deref().unwrap_or(""),
                Err(error),
            );
        }
    };
    if args.verbose > 0 {
        render::diagnostic(&format!(
            "Control API v1 portal: {}; instance: {}",
            args.rpc_portal, client.meta.instance_id
        ));
    }
    let streaming = matches!(
        args.command,
        Command::Stats {
            command: StatsCommand::Watch { .. }
        } | Command::Log {
            command: LogCommand::Follow(_)
        }
    );
    if streaming {
        let result = tokio::select! {
            result = stream(&args, &mut client) => result,
            result = tokio::signal::ctrl_c() => result.map_err(|_| CliError::new("internal", "Cannot receive the interrupt signal.", "")),
        };
        match result {
            Ok(()) => 0,
            Err(error) => finish(
                &args,
                &client.meta.request_id,
                &client.meta.instance_id,
                Err(error),
            ),
        }
    } else {
        finish(
            &args,
            &request_id,
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
    let resource = if matches!(args.command, Command::Log { .. }) {
        "logs"
    } else {
        "stats"
    };
    let mut cursor = commands::stats::wait(client, resource, String::new())
        .await?
        .cursor;
    let mut page = match &args.command {
        Command::Log {
            command: LogCommand::Follow(page),
        } => PageArgs {
            limit: page.limit,
            page_token: page.page_token.clone(),
        },
        _ => PageArgs::default(),
    };
    loop {
        client.meta.request_id = uuid::Uuid::new_v4().to_string();
        let (response, more) = if resource == "logs" {
            let logs = commands::log::read(client, &page).await?;
            let more = logs.logs.len() == page.limit as usize;
            page.page_token = logs.next_page_token.clone();
            (Response::from(logs), more)
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
