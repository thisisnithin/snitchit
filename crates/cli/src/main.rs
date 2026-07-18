//! `snitchit` — the thin binary: parse args, dispatch, render.
//!
//! All the substance lives in `snitchit-core` and `snitchit-collectors`; this
//! crate only wires clap subcommands to them and renders `log`/`verify`/`view`
//! output.

use std::process::ExitCode;

use anyhow::Result;
use clap::{CommandFactory, Parser};

use crate::cli::{Cli, Command};

mod cli;
mod commands;

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(e) => {
            eprintln!("snitchit: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn real_main() -> Result<i32> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Log(args)) => {
            let path = commands::resolve_session(args.session.as_deref())?;
            commands::log::log(&path)?;
            Ok(0)
        }
        Some(Command::Verify(args)) => {
            let path = commands::resolve_session(args.session.as_deref())?;
            let ok = commands::verify::verify(&path)?;
            Ok(i32::from(!ok))
        }
        Some(Command::View(args)) => {
            let path = commands::resolve_session(args.session.as_deref())?;
            commands::view::view(&path, &args)?;
            Ok(0)
        }
        Some(Command::Install(args)) => {
            commands::install::install(&args)?;
            Ok(0)
        }
        Some(Command::Uninstall(args)) => {
            commands::install::uninstall(&args)?;
            Ok(0)
        }
        Some(Command::Hook { agent }) => {
            // Observe-only: whatever happens, exit 0 so we never block the agent
            // (exit 2 would deny the tool; any non-zero surfaces an error to it).
            commands::hook::run(&agent);
            Ok(0)
        }
        None => {
            if cli.wrapped.is_empty() {
                Cli::command().print_help()?;
                println!();
                Ok(0)
            } else {
                commands::run::run(&cli.wrapped)
            }
        }
    }
}
