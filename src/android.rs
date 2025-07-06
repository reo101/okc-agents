use eyre::{bail, Context, Result};
use std::env;
use tokio::process::Command;

pub const AM_ENV: &str = "AM";
const DEFAULT_AM_COMMAND: &str = "am";

pub fn am_command() -> String {
    env::var(AM_ENV).unwrap_or_else(|_| DEFAULT_AM_COMMAND.to_string())
}

pub async fn run_am_broadcast(command: &mut Command) -> Result<()> {
    let status = command
        .status()
        .await
        .context("Failed to execute 'am broadcast' command")?;

    if status.success() {
        Ok(())
    } else {
        bail!("'am broadcast' command failed with status: {status}")
    }
}
