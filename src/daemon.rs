use crate::cli::{print_kill_vars, KillArgs, AGENT_PID_ENV};
use eyre::{Context, Result};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::env;
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;

pub const DAEMONIZE_ENV: &str = "_OKC_AGENT_DAEMONIZE";

/// Handles the logic for the generic `kill` command.
pub async fn kill_agent_command(args: KillArgs) -> Result<()> {
    let pid_str = env::var(AGENT_PID_ENV).with_context(|| {
        format!(
            "Agent not running? Environment variable {} is not set.",
            AGENT_PID_ENV
        )
    })?;

    let pid = pid_str
        .parse::<i32>()
        .with_context(|| format!("Failed to parse PID from {}: '{}'", AGENT_PID_ENV, pid_str))?;

    kill(Pid::from_raw(pid), Signal::SIGTERM)
        .with_context(|| format!("Failed to send SIGTERM to agent process with PID {}", pid))?;

    print_kill_vars(pid, &args);
    Ok(())
}

/// Spawns the current executable as a detached daemon process.
pub async fn spawn_daemon(socket_path: &Path) -> Result<u32> {
    let current_exe = env::current_exe().context("Could not find current executable path")?;

    let child = Command::new(current_exe)
        .env(DAEMONIZE_ENV, "1")
        .env(crate::cli::AUTH_SOCK_ENV, socket_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("Failed to spawn daemon process")?;

    Ok(child.id().unwrap_or(0))
}
