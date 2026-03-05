use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Parser;
use eyre::{Context, ContextCompat, Result, bail};
use okc_agents::android::{
    EXTRA_GPG_ARGS, EXTRA_GPG_PROTO_VER, EXTRA_PROXY_PORT, GPG_PROXY_RECEIVER, broadcast_command,
    run_am_broadcast,
};
use okc_agents::logging::init_tracing;
use std::time::Duration;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time;
use tracing::{debug, error, info, warn};

const FRAME_CHUNK_SIZE: usize = 4 * 1024;

const GPG_PROTO_VER: i32 = 1;

/// A GPG proxy for forwarding requests to the okc-agent Android app.
///
/// This client mimics a subset of gpg's command-line options and forwards them
/// to the OpenKeychain app for execution.
#[derive(Parser, Debug)]
#[command(author, version)]
struct GpgArgs {
    // Actions
    #[arg(long, short, help = "Make a signature")]
    sign: bool,
    #[arg(
        long,
        visible_alias = "clearsign",
        help = "Make a clear text signature"
    )]
    clear_sign: bool,
    #[arg(long, short = 'b', help = "Make a detached signature")]
    detach_sign: bool,
    #[arg(long, short, help = "Encrypt data")]
    encrypt: bool,
    #[arg(long, short, help = "Decrypt data")]
    decrypt: bool,
    #[arg(long, help = "Verify a signature")]
    verify: bool,

    // Options
    #[arg(long, short = 'a', help = "Create ASCII armored output")]
    armor: bool,
    #[arg(
        long,
        short,
        value_name = "USER-ID",
        help = "Encrypt for USER-ID (can be used multiple times)"
    )]
    recipient: Vec<String>,
    #[arg(long, short = 'o', value_name = "FILE", help = "Write output to FILE")]
    output: Option<String>,
    #[arg(long, help = "Use quiet mode")]
    quiet: bool,
    #[arg(long, help = "Assume \"yes\" on most questions")]
    yes: bool,
    #[arg(long, help = "Assume \"no\" on most questions")]
    no: bool,
    #[arg(long, help = "Don't encrypt to the default key")]
    no_encrypt_to: bool,
    #[arg(long, short = 'v', help = "Use verbose mode")]
    verbose: bool,
    #[arg(long, help = "Display configuration")]
    list_config: bool,
    #[arg(long, help = "Use colon-separated output for listings")]
    with_colons: bool,
    #[arg(
        long,
        value_name = "LEVEL",
        help = "Set the bzip2 compression level (0-9)"
    )]
    bzip2_compress_level: Option<String>,
    #[arg(long, value_name = "FILENAME", help = "Use FILENAME for the signature")]
    set_filename: Option<String>,
    #[arg(
        long,
        value_name = "FD",
        help = "Write status messages to file descriptor FD"
    )]
    status_fd: Option<String>,

    // Positional Arguments
    #[arg(help = "Input files or data for the operation")]
    files: Vec<String>,

    // Ignored/Unsupported options for compatibility
    #[arg(long, short = 'u', value_name = "USER-ID", hide = true)]
    local_user: Option<String>,
    #[arg(long, hide = true)]
    default_key: bool,
    #[arg(long, value_name = "algo", hide = true)]
    compress_algo: Option<String>,
    #[arg(long, hide = true)]
    batch: bool,
    #[arg(long, hide = true)]
    no_batch: bool,
    #[arg(long, value_name = "format", hide = true)]
    keyid_format: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let args = GpgArgs::parse();
    validate_args(&args)?;
    warn_ignored_options(&args);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        protocol = GPG_PROTO_VER,
        "okc-gpg starting"
    );
    if let Err(error) = run_gpg_proxy(args).await {
        error!(error = ?error, "A critical error occurred");
        return Err(error);
    }
    Ok(())
}

fn validate_args(args: &GpgArgs) -> Result<()> {
    let has_action = args.sign
        || args.clear_sign
        || args.detach_sign
        || args.encrypt
        || args.decrypt
        || args.verify
        || args.list_config;
    if !has_action {
        bail!("No action selected. Use one of --sign/--encrypt/--decrypt/--verify/--list-config.");
    }

    if args.list_config
        && (args.sign
            || args.clear_sign
            || args.detach_sign
            || args.encrypt
            || args.decrypt
            || args.verify)
    {
        bail!("--list-config cannot be combined with crypto actions.");
    }

    if args.clear_sign
        && (args.sign || args.detach_sign || args.encrypt || args.decrypt || args.verify)
    {
        bail!("--clear-sign cannot be combined with other crypto actions.");
    }

    if args.detach_sign
        && (args.sign || args.clear_sign || args.encrypt || args.decrypt || args.verify)
    {
        bail!("--detach-sign cannot be combined with other crypto actions.");
    }

    if (args.sign || args.encrypt) && (args.decrypt || args.verify) {
        bail!("Encrypt/sign actions cannot be combined with decrypt/verify actions.");
    }

    Ok(())
}

fn warn_ignored_options(args: &GpgArgs) {
    if args.local_user.is_some() {
        warn!("Option --local-user is ignored by the app");
    }
    if args.default_key {
        warn!("Option --default-key is ignored by the app");
    }
    if args.compress_algo.is_some() {
        warn!("Option --compress-algo is ignored by the app");
    }
    if args.batch {
        warn!("Option --batch is ignored by the app");
    }
    if args.no_batch {
        warn!("Option --no-batch is ignored by the app");
    }
    if args.keyid_format.is_some() {
        warn!("Option --keyid-format is ignored by the app");
    }
}

/// Reconstructs a command-line argument vector from the parsed GpgArgs struct.
/// Based on <https://github.com/DDoSolitary/OkcAgent/blob/817bc018b59f7fbba992e98601f7c72278ce9acd/app/src/main/java/org/ddosolitary/okcagent/gpg/GpgArguments.kt>
fn reconstruct_args(args: &GpgArgs) -> Vec<String> {
    let mut constructed_args = Vec::new();

    // Helper macro to add boolean flags
    macro_rules! add_flag {
        ($field:expr, $name:expr) => {
            if $field {
                constructed_args.push($name.to_string());
            }
        };
    }

    // Helper macro to add options with values
    macro_rules! add_option {
        ($field:expr, $name:expr) => {
            if let Some(value) = $field {
                constructed_args.push($name.to_string());
                constructed_args.push(value.clone());
            }
        };
    }

    // Actions
    add_flag!(args.sign, "--sign");
    add_flag!(args.clear_sign, "--clear-sign");
    add_flag!(args.detach_sign, "--detach-sign");
    add_flag!(args.encrypt, "--encrypt");
    add_flag!(args.decrypt, "--decrypt");
    add_flag!(args.verify, "--verify");

    // Options
    add_flag!(args.armor, "--armor");
    add_flag!(args.quiet, "--quiet");
    add_flag!(args.yes, "--yes");
    add_flag!(args.no, "--no");
    add_flag!(args.no_encrypt_to, "--no-encrypt-to");
    add_flag!(args.verbose, "--verbose");
    add_flag!(args.list_config, "--list-config");
    add_flag!(args.with_colons, "--with-colons");

    // Options with values
    add_option!(&args.output, "--output");
    add_option!(&args.bzip2_compress_level, "--bzip2-compress-level");
    add_option!(&args.set_filename, "--set-filename");
    add_option!(&args.status_fd, "--status-fd");

    // Multi-value option
    for r in &args.recipient {
        constructed_args.push("--recipient".to_string());
        constructed_args.push(r.clone());
    }

    // Positional arguments
    constructed_args.extend(args.files.clone());

    constructed_args
}

#[derive(Debug)]
enum ConnectionType {
    Control,
    Input,
    Output,
}

impl TryFrom<u8> for ConnectionType {
    type Error = eyre::Report;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Control),
            1 => Ok(Self::Input),
            2 => Ok(Self::Output),
            _ => bail!("Invalid connection type received: {value}"),
        }
    }
}

#[derive(Default)]
struct AppConnections {
    control: Option<TcpStream>,
    input: Option<TcpStream>,
    output: Option<TcpStream>,
}

impl AppConnections {
    fn insert(&mut self, kind: ConnectionType, stream: TcpStream) -> Result<()> {
        let (slot, name) = match kind {
            ConnectionType::Control => (&mut self.control, "control"),
            ConnectionType::Input => (&mut self.input, "input"),
            ConnectionType::Output => (&mut self.output, "output"),
        };

        if slot.replace(stream).is_some() {
            bail!("Received duplicate {name} connection");
        }

        Ok(())
    }

    fn into_required(self) -> Result<(TcpStream, TcpStream, TcpStream)> {
        Ok((
            self.control
                .context("Failed to establish control connection")?,
            self.input.context("Failed to establish input connection")?,
            self.output
                .context("Failed to establish output connection")?,
        ))
    }
}

async fn run_gpg_proxy(args: GpgArgs) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    info!(port, "Listening for app connections");

    let mut cmd = broadcast_command(GPG_PROXY_RECEIVER);
    let gpg_args_for_app = reconstruct_args(&args);

    cmd.arg("--ei")
        .arg(EXTRA_GPG_PROTO_VER)
        .arg(GPG_PROTO_VER.to_string())
        .arg("--ei")
        .arg(EXTRA_PROXY_PORT)
        .arg(port.to_string());

    if !gpg_args_for_app.is_empty() {
        let encoded_args = gpg_args_for_app
            .into_iter()
            .map(|s| STANDARD.encode(s))
            .collect::<Vec<_>>()
            .join(",");
        cmd.arg("--esa").arg(EXTRA_GPG_ARGS).arg(encoded_args);
    }

    run_am_broadcast(&mut cmd).await?;
    info!("Broadcast sent. Waiting for connections from the app...");

    let mut connections = AppConnections::default();

    for _ in 0..3 {
        let (mut stream, addr) = time::timeout(Duration::from_secs(15), listener.accept())
            .await
            .context("Timed out waiting for an app connection.")??;

        let kind = ConnectionType::try_from(
            stream
                .read_u8()
                .await
                .context("Failed to read connection type")?,
        )?;
        debug!(from = %addr, ?kind, "Accepted app connection");
        connections.insert(kind, stream)?;
    }

    let (control, input, output) = connections.into_required()?;
    let (exit_code, (), ()) = tokio::try_join!(
        handle_control_connection(control),
        handle_input_connection(input),
        handle_output_connection(output)
    )?;

    info!(exit_code, "All app connections finished");

    if exit_code == 0 {
        Ok(())
    } else {
        bail!("The app reported an error (status code: {})", exit_code)
    }
}

/// Handles the control stream: receives logs/status from the app.
async fn handle_control_connection(mut stream: TcpStream) -> Result<u8> {
    info!("Control connection established");
    loop {
        let msg = read_length_prefixed_str(&mut stream).await?;
        if msg.is_empty() {
            break; // End of messages
        }
        // Log messages received from the app
        match msg.get(..4) {
            Some("[E] ") => error!("[app] {}", &msg[4..]),
            Some("[W] ") => warn!("[app] {}", &msg[4..]),
            _ => info!("[app] {}", msg),
        }
    }
    let status_code = stream
        .read_u8()
        .await
        .context("Failed to read final status code")?;
    debug!("Control connection finished");
    Ok(status_code)
}

/// Handles the input stream: reads from stdin/file and sends to the app.
async fn handle_input_connection(mut stream: TcpStream) -> Result<()> {
    let path = read_length_prefixed_str(&mut stream).await?;
    info!(source = %path, "Input connection established");

    if path == "-" {
        let mut stdin = io::stdin();
        copy_to_length_prefixed(&mut stdin, &mut stream).await?;
    } else {
        let mut file = tokio::fs::File::open(&path)
            .await
            .context("Failed to open input file")?;
        copy_to_length_prefixed(&mut file, &mut stream).await?;
    }
    debug!("Input connection finished");
    Ok(())
}

/// Handles the output stream: receives from the app and writes to stdout/file.
async fn handle_output_connection(mut stream: TcpStream) -> Result<()> {
    let path = read_length_prefixed_str(&mut stream).await?;
    info!(destination = %path, "Output connection established");
    if path == "-" {
        let mut stdout = io::stdout();
        copy_from_length_prefixed(&mut stream, &mut stdout).await?;
    } else {
        let mut file = tokio::fs::File::create(&path)
            .await
            .context("Failed to create output file")?;
        copy_from_length_prefixed(&mut stream, &mut file).await?;
    }
    debug!("Output connection finished");
    Ok(())
}

/// Reads a u16-length-prefixed string from a stream.
async fn read_length_prefixed_str<R: AsyncRead + Unpin>(reader: &mut R) -> Result<String> {
    let len = reader.read_u16().await?;
    if len == 0 {
        return Ok(String::new());
    }
    let mut str_buf = vec![0u8; len as usize];
    reader.read_exact(&mut str_buf).await?;
    Ok(String::from_utf8(str_buf)?)
}

/// Reads from a source and writes to a stream using a u16-length-prefix protocol.
async fn copy_to_length_prefixed<R, W>(source: &mut R, dest: &mut W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; FRAME_CHUNK_SIZE];
    loop {
        let len_read = source.read(&mut buf).await?;
        if len_read == 0 {
            break;
        }
        let len = u16::try_from(len_read).context("Input chunk exceeded frame size")?;
        debug!(bytes = len_read, "Sending framed payload chunk");
        dest.write_u16(len).await?;
        dest.write_all(&buf[..len_read]).await?;
    }
    dest.write_u16(0).await?; // EOF marker
    dest.flush().await?;
    Ok(())
}

/// Reads from a u16-length-prefixed stream and writes the contents to a destination.
async fn copy_from_length_prefixed<R, W>(source: &mut R, dest: &mut W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; u16::MAX as usize];
    loop {
        let len_to_read = source.read_u16().await? as usize;
        if len_to_read == 0 {
            break; // EOF marker
        }
        debug!(bytes = len_to_read, "Receiving framed payload chunk");
        let chunk = &mut buf[..len_to_read];
        source.read_exact(chunk).await?;
        dest.write_all(chunk).await?;
    }
    dest.flush().await?;
    Ok(())
}
