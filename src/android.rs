use eyre::{Context, Result, bail};
use std::env;
use std::sync::OnceLock;
use tokio::process::Command;

pub const AM_ENV: &str = "AM";
pub const SSH_PROXY_RECEIVER: &str = "org.ddosolitary.okcagent/.SshProxyReceiver";
pub const GPG_PROXY_RECEIVER: &str = "org.ddosolitary.okcagent/.GpgProxyReceiver";
pub const EXTRA_SSH_PROTO_VER: &str = "org.ddosolitary.okcagent.extra.SSH_PROTO_VER";
pub const EXTRA_GPG_PROTO_VER: &str = "org.ddosolitary.okcagent.extra.GPG_PROTO_VER";
pub const EXTRA_PROXY_PORT: &str = "org.ddosolitary.okcagent.extra.PROXY_PORT";
pub const EXTRA_GPG_ARGS: &str = "org.ddosolitary.okcagent.extra.GPG_ARGS";

const DEFAULT_AM_COMMAND: &str = "am";
static AM_COMMAND: OnceLock<String> = OnceLock::new();

pub fn am_command() -> &'static str {
    AM_COMMAND
        .get_or_init(|| env::var(AM_ENV).unwrap_or_else(|_| DEFAULT_AM_COMMAND.to_string()))
        .as_str()
}

pub fn broadcast_command(receiver: &str) -> Command {
    let mut command = Command::new(am_command());
    command.arg("broadcast").arg("-n").arg(receiver);
    command
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
