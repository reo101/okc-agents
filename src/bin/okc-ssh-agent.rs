use clap::{Parser, Subcommand};
use eyre::{Context, Result, bail};
use okc_agents::android::{broadcast_command, run_am_broadcast};
use okc_agents::cli::{self, HasShellArgs, KillArgs, ShellArgs};
use okc_agents::daemon;
use okc_agents::logging::init_tracing;
use std::env;
use std::future;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io;
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::process::Command;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::oneshot;
use tracing::{error, info, warn};

const SSH_PROTO_VER: u32 = 0;
const SSH_APP_RECEIVER: &str = "org.ddosolitary.okcagent/.SshProxyReceiver";

// --- Main Application Entry Point ---

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    // If daemonized, run the server. Otherwise, handle CLI commands.
    if env::var(daemon::DAEMONIZE_ENV).is_ok() {
        return run_ssh_server_from_env(future::pending()).await;
    }

    let cli = Cli::parse();
    match cli.command {
        Commands::Start(args) => start_ssh_command(args).await?,
        Commands::Kill(args) => daemon::kill_agent_command(args).await?,
    }

    Ok(())
}

// --- Specific Business Logic for SSH Agent ---

async fn run_ssh_server_from_env<F>(shutdown: F) -> Result<()>
where
    F: future::Future<Output = ()>,
{
    let socket_path_str = env::var(cli::AUTH_SOCK_ENV)
        .context("Expected SSH_AUTH_SOCK to be set in daemonized process")?;
    let socket_path = PathBuf::from(socket_path_str);
    run_ssh_server(socket_path, shutdown).await
}

async fn run_ssh_server<F>(socket_path: PathBuf, shutdown: F) -> Result<()>
where
    F: future::Future<Output = ()>,
{
    tokio::pin!(shutdown);

    match tokio::fs::remove_file(&socket_path).await {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!("Failed to remove stale socket at {}", socket_path.display())
            });
        }
    }

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("Daemon could not bind to socket at {:?}", &socket_path))?;

    info!(
        version = env!("CARGO_PKG_VERSION"),
        socket = %socket_path.display(),
        "okc-ssh-agent daemon started"
    );

    let mut sig_term = signal(SignalKind::terminate())?;
    let mut sig_int = signal(SignalKind::interrupt())?;
    let counter = AtomicU64::new(0);

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => { info!("Received shutdown request, stopping SSH server."); break; }
            _ = sig_term.recv() => { info!("Received SIGTERM, shutting down."); break; }
            _ = sig_int.recv() => { info!("Received SIGINT, shutting down."); break; }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _)) => {
                        let connection_id = counter.fetch_add(1, Ordering::Relaxed);
                        tokio::spawn(async move {
                            if let Err(error) = handle_ssh_connection(stream, connection_id).await {
                                error!(connection_id, error = ?error, "SSH connection failed");
                            }
                        });
                    }
                    Err(error) => warn!(error = %error, "Failed to accept incoming SSH connection"),
                }
            }
        }
    }

    match tokio::fs::remove_file(&socket_path).await {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            warn!(path = %socket_path.display(), error = %error, "Failed to delete socket file");
        }
    }
    Ok(())
}

async fn handle_ssh_connection(mut client_stream: UnixStream, connection_id: u64) -> Result<()> {
    info!(connection_id, "Handling new SSH client connection");

    let app_listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = app_listener.local_addr()?.port();
    info!(connection_id, port, "Listening for app callback connection");

    let mut broadcast = broadcast_command(SSH_APP_RECEIVER);
    broadcast
        .arg("--ei")
        .arg("org.ddosolitary.okcagent.extra.SSH_PROTO_VER")
        .arg(SSH_PROTO_VER.to_string())
        .arg("--ei")
        .arg("org.ddosolitary.okcagent.extra.PROXY_PORT")
        .arg(port.to_string());

    run_am_broadcast(&mut broadcast).await?;

    let (mut app_stream, _) = tokio::time::timeout(Duration::from_secs(10), app_listener.accept())
        .await
        .context("Timed out waiting for app to connect")??;

    info!(connection_id, remote_addr = ?app_stream.peer_addr(), "App connected, proxying traffic");

    let (client_to_app, app_to_client) =
        io::copy_bidirectional(&mut client_stream, &mut app_stream)
            .await
            .context("Data proxying failed")?;
    info!(
        connection_id,
        client_to_app, app_to_client, "SSH proxy session finished"
    );
    Ok(())
}

async fn start_ssh_command(args: StartArgs) -> Result<()> {
    let is_foreground = args.foreground || args.debug || !args.cmd.is_empty();

    let temp_dir = tempfile::Builder::new()
        .prefix("okc-agent-")
        .tempdir_in(env::var_os("TMPDIR").unwrap_or_else(|| "/tmp".into()))
        .context("Failed to create temporary directory for agent socket")?;

    let socket_path = match args.addr {
        Some(ref path) => path.clone(),
        None => temp_dir.path().join("agent.sock"),
    };

    if is_foreground {
        cli::print_shell_exports(&socket_path, std::process::id(), &args);

        if !args.cmd.is_empty() {
            let mut child_cmd = Command::new(&args.cmd[0]);
            child_cmd
                .args(&args.cmd[1..])
                .env(cli::AUTH_SOCK_ENV, &socket_path)
                .env(cli::AGENT_PID_ENV, std::process::id().to_string());

            let mut child_process = child_cmd.spawn().context("Failed to spawn command")?;
            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            let mut server_task = tokio::spawn(run_ssh_server(socket_path.clone(), async move {
                let _ = shutdown_rx.await;
            }));

            tokio::select! {
                server_result = &mut server_task => {
                    let server_result = server_result.context("SSH server task panicked")?;
                    let _ = child_process.kill().await;
                    let _ = child_process.wait().await;
                    server_result.context("SSH server exited while child command was still running")?;
                    bail!("SSH server exited before child command finished")
                }
                status = child_process.wait() => {
                    let status = status.context("Failed to wait for child process")?;
                    info!(%status, "Child command finished");
                }
            }

            let _ = shutdown_tx.send(());
            server_task
                .await
                .context("SSH server task panicked during shutdown")??;
        } else {
            run_ssh_server(socket_path, future::pending()).await?;
        }
    } else {
        let pid = daemon::spawn_daemon(&socket_path).await?;
        info!(pid, "Agent daemon started");
        cli::print_shell_exports(&socket_path, pid, &args);
        let _persisted_socket_dir = temp_dir.keep(); // Daemon cleans up the socket when it exits.
    }

    Ok(())
}

// --- CLI Structure for SSH Agent ---

#[derive(Parser, Debug)]
#[command(author, version, about = "An SSH agent for OpenConnect via Termux")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Starts the agent
    #[command(visible_alias = "s")]
    Start(StartArgs),
    /// Kills a running agent
    #[command(visible_alias = "k")]
    Kill(KillArgs),
}

#[derive(Parser, Debug)]
pub struct StartArgs {
    #[command(flatten)]
    shell: ShellArgs,
    /// Bind the agent to a specific UNIX-domain socket path.
    #[arg(short, long, value_name = "BIND_ADDRESS")]
    addr: Option<PathBuf>,
    /// Run the agent in the foreground.
    #[arg(short = 'D', long)]
    foreground: bool,
    /// Run in debug mode (implies foreground).
    #[arg(short, long)]
    debug: bool,
    /// If a command is given, it is executed as a subprocess of the agent.
    #[arg(last = true)]
    cmd: Vec<String>,
}

impl HasShellArgs for StartArgs {
    fn shell_args(&self) -> &ShellArgs {
        &self.shell
    }
}
