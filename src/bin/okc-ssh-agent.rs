use clap::{Parser, Subcommand};
use eyre::{bail, Context, Result};
use futures_util::future;
use okc_agents::cli::{self, HasShellArgs, KillArgs, ShellArgs};
use okc_agents::daemon;
use slog::{error, info, o, warn, Drain, Logger};
use std::env;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::process::Command;
use tokio::signal::unix::{signal, SignalKind};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt;

const SSH_PROTO_VER: u32 = 0;
const SSH_APP_RECEIVER: &str = "org.ddosolitary.okcagent/.SshProxyReceiver";

// --- Main Application Entry Point ---

#[tokio::main]
async fn main() -> Result<()> {
    // Setup logger.
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = Logger::root(drain, o!());

    // If daemonized, run the server. Otherwise, handle CLI commands.
    if env::var(daemon::DAEMONIZE_ENV).is_ok() {
        return run_ssh_server(log).await;
    }

    let cli = Cli::parse();
    match cli.command {
        Commands::Start(args) => start_ssh_command(args, log).await?,
        Commands::Kill(args) => daemon::kill_agent_command(args).await?,
    }

    Ok(())
}

// --- Specific Business Logic for SSH Agent ---

async fn run_ssh_server(log: Logger) -> Result<()> {
    let socket_path_str = env::var(cli::AUTH_SOCK_ENV)
        .context("Expected SSH_AUTH_SOCK to be set in daemonized process")?;
    let socket_path = PathBuf::from(socket_path_str);

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("Daemon could not bind to socket at {:?}", &socket_path))?;

    info!(log, "okc-ssh-agent daemon started"; "version" => env!("CARGO_PKG_VERSION"), "socket" => socket_path.display());

    let mut sig_term = signal(SignalKind::terminate())?;
    let mut sig_int = signal(SignalKind::interrupt())?;
    let counter = AtomicU64::new(0);

    loop {
        tokio::select! {
            biased;
            _ = sig_term.recv() => { info!(log, "Received SIGTERM, shutting down."); break; }
            _ = sig_int.recv() => { info!(log, "Received SIGINT, shutting down."); break; }
            accept_result = listener.accept() => {
                if let Ok((stream, _)) = accept_result {
                    let conn_log = log.new(o!("id" => counter.fetch_add(1, Ordering::Relaxed)));
                    tokio::spawn(async move {
                        if let Err(e) = handle_ssh_connection(stream, conn_log.clone()).await {
                            error!(conn_log, "Connection failed: {:?}", e);
                        }
                    });
                }
            }
        }
    }

    tokio::fs::remove_file(&socket_path)
        .await
        .unwrap_or_else(|e| warn!(log, "Failed to delete socket file"; "path" => socket_path.display(), "error" => %e));
    Ok(())
}

async fn handle_ssh_connection(mut client_stream: UnixStream, log: Logger) -> Result<()> {
    info!(log, "Handling new SSH client connection");
    let (mut crx, mut ctx) = client_stream.split();

    let app_listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = app_listener.local_addr()?.port();
    info!(log, "Listening for app on TCP port {}", port);

    // TODO: deduplicate
    let am_command = std::env::var("AM").unwrap_or_else(|_| "am".to_string());

    let status = Command::new(am_command)
        .arg("broadcast")
        .arg("-n")
        .arg(SSH_APP_RECEIVER)
        .arg("--ei")
        .arg("org.ddosolitary.okcagent.extra.SSH_PROTO_VER")
        .arg(SSH_PROTO_VER.to_string())
        .arg("--ei")
        .arg("org.ddosolitary.okcagent.extra.PROXY_PORT")
        .arg(port.to_string())
        .status()
        .await
        .context("Failed to execute 'am broadcast' command")?;

    if !status.success() {
        bail!("'am broadcast' command failed with status: {}", status);
    }

    let mut app_stream = match tokio::time::timeout(
        Duration::from_secs(10),
        TcpListenerStream::new(app_listener).next(),
    )
    .await
    {
        Ok(Some(Ok(stream))) => stream,
        _ => bail!("Timed out waiting for app to connect"),
    };

    info!(log, "App connected, proxying data"; "remote_addr" => ?app_stream.peer_addr());
    let (mut arx, mut atx) = app_stream.split();

    let (r1, r2) = future::join(copy_data(&mut crx, &mut atx), copy_data(&mut arx, &mut ctx)).await;
    r1.and(r2).context("Data proxying failed")
}

async fn copy_data<R, W>(reader: &mut R, writer: &mut W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    io::copy(reader, writer).await?;
    writer.shutdown().await?;
    Ok(())
}

async fn start_ssh_command(args: StartArgs, log: Logger) -> Result<()> {
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
        env::set_var(cli::AUTH_SOCK_ENV, &socket_path);
        cli::print_shell_exports(&socket_path, std::process::id(), &args);

        if !args.cmd.is_empty() {
            let mut child_cmd = Command::new(&args.cmd[0]);
            child_cmd.args(&args.cmd[1..]).envs(env::vars());

            let server_task = tokio::spawn(run_ssh_server(log.clone()));
            let mut child_process = child_cmd.spawn().context("Failed to spawn command")?;

            tokio::select! {
                res = server_task => error!(log, "Server exited unexpectedly: {:?}", res),
                status = child_process.wait() => info!(log, "Child command finished"; "status" => %status.unwrap()),
            }
        } else {
            run_ssh_server(log).await?;
        }
    } else {
        let pid = daemon::spawn_daemon(&socket_path).await?;
        info!(log, "Agent daemon started"; "pid" => pid);
        cli::print_shell_exports(&socket_path, pid, &args);
        let _ = temp_dir.keep(); // Leak the temp dir, daemon will clean it up.
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
