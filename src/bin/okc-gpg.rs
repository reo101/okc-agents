use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{ArgAction, Parser};
use eyre::{bail, Context, Result};
use slog::{debug, error, info, o, warn, Drain, Logger};
use std::time::Duration;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time;

const GPG_PROTO_VER: i32 = 1;
const GPG_APP_RECEIVER: &str = "org.ddosolitary.okcagent/.GpgProxyReceiver";

/// A GPG proxy for forwarding requests to the okc-agent Android app.
///
/// This client mimics a subset of gpg's command-line options and forwards them
/// to the OpenKeychain app for execution.
#[derive(Parser, Debug)]
#[command(author, version)]
struct GpgArgs {
    // Actions
    #[arg(long, short, group = "action", help = "Make a signature")]
    sign: bool,
    #[arg(
        long,
        visible_alias = "clearsign",
        group = "action",
        help = "Make a clear text signature"
    )]
    clear_sign: bool,
    #[arg(
        long,
        short = 'b',
        group = "action",
        help = "Make a detached signature"
    )]
    detach_sign: bool,
    #[arg(long, short, group = "action", help = "Encrypt data")]
    encrypt: bool,
    #[arg(long, short, group = "action", help = "Decrypt data")]
    decrypt: bool,
    #[arg(long, group = "action", help = "Verify a signature")]
    verify: bool,

    // Options
    #[arg(long, short = 'a', help = "Create ASCII armored output")]
    armor: bool,
    #[arg(long, short, value_name = "USER-ID", action = ArgAction::Append, help = "Encrypt for USER-ID (can be used multiple times)")]
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
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = Logger::root(drain, o!());

    let args = GpgArgs::parse();

    // Warn about ignored options
    if args.local_user.is_some() {
        warn!(log, "Option --local-user is ignored by the app");
    }
    // Add other warnings for unsupported args here if desired...

    info!(log, "okc-gpg starting"; "version" => env!("CARGO_PKG_VERSION"), "protocol" => GPG_PROTO_VER);
    if let Err(e) = run_gpg_proxy(args, log.clone()).await {
        error!(log, "A critical error occurred: {e:?}");
        return Err(e);
    }
    Ok(())
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

async fn run_gpg_proxy(args: GpgArgs, log: Logger) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("Failed to bind to an ephemeral port")?;
    let port = listener.local_addr()?.port();
    info!(log, "Listening for app connections on port {}", port);

    // Reconstruct args and send broadcast
    let gpg_args_for_app = reconstruct_args(&args);

    let mut cmd = tokio::process::Command::new("am");
    cmd.arg("broadcast")
        .arg("-n")
        .arg(GPG_APP_RECEIVER)
        .arg("--ei")
        .arg("org.ddosolitary.okcagent.extra.GPG_PROTO_VER")
        .arg(GPG_PROTO_VER.to_string())
        .arg("--ei")
        .arg("org.ddosolitary.okcagent.extra.PROXY_PORT")
        .arg(port.to_string());

    if !gpg_args_for_app.is_empty() {
        let encoded_args = gpg_args_for_app
            .into_iter()
            .map(|s| STANDARD.encode(s))
            .collect::<Vec<_>>()
            .join(",");
        cmd.arg("--esa")
            .arg("org.ddosolitary.okcagent.extra.GPG_ARGS")
            .arg(encoded_args);
    }
    cmd.status()
        .await
        .context("Failed to send 'am broadcast' to the Android app.")?;
    info!(
        log,
        "Broadcast sent. Waiting for 3 connections from the app..."
    );

    // The rest of the logic remains the same...
    let (control, input, output) = time::timeout(
        Duration::from_secs(15),
        accept_all_connections(&listener, &log),
    )
    .await
    .context("Timed out waiting for the app to establish all 3 connections.")??;

    let (control_result, _, _) = tokio::try_join!(
        tokio::spawn(handle_control_connection(control, log.clone())),
        tokio::spawn(handle_input_connection(input, log.clone())),
        tokio::spawn(handle_output_connection(output, log.clone()))
    )
    .context("A concurrent connection handler failed.")?;

    let exit_code = control_result.context("Control connection task panicked.")?;
    info!(
        log,
        "All connections finished. Final status code: {}", exit_code
    );

    if exit_code == 0 {
        Ok(())
    } else {
        bail!("The app reported an error (status code: {})", exit_code)
    }
}

/// Accepts connections and sorts them into control, input, and output streams.
async fn accept_all_connections(
    listener: &TcpListener,
    log: &Logger,
) -> Result<(TcpStream, TcpStream, TcpStream)> {
    let mut control = None;
    let mut input = None;
    let mut output = None;

    for _ in 0..3 {
        let (mut stream, addr) = listener.accept().await?;
        let op_type = stream
            .read_u8()
            .await
            .context("Failed to read connection type")?;
        debug!(log, "Accepted connection"; "from" => addr, "type" => op_type);

        match op_type {
            0 => control = Some(stream),
            1 => input = Some(stream),
            2 => output = Some(stream),
            _ => bail!("Invalid connection type received: {}", op_type),
        };
    }

    if let (Some(c), Some(i), Some(o)) = (control, input, output) {
        Ok((c, i, o))
    } else {
        bail!("Failed to establish all three required connections (control, input, output).")
    }
}

/// Handles the control stream: receives logs/status from the app.
async fn handle_control_connection(mut stream: TcpStream, log: Logger) -> Result<u8> {
    info!(log, "Control connection established.");
    loop {
        let msg = read_length_prefixed_str(&mut stream).await?;
        if msg.is_empty() {
            break; // End of messages
        }
        // Log messages received from the app
        match msg.get(..4) {
            Some("[E] ") => error!(log, "[app] {}", &msg[4..]),
            Some("[W] ") => warn!(log, "[app] {}", &msg[4..]),
            _ => info!(log, "[app] {}", msg),
        }
    }
    let status_code = stream
        .read_u8()
        .await
        .context("Failed to read final status code")?;
    debug!(log, "Control connection finished.");
    Ok(status_code)
}

/// Handles the input stream: reads from stdin/file and sends to the app.
async fn handle_input_connection(mut stream: TcpStream, log: Logger) -> Result<()> {
    let path = read_length_prefixed_str(&mut stream).await?;
    info!(log, "Input connection established"; "source" => &path);

    if path == "-" {
        let mut stdin = io::stdin();
        copy_to_length_prefixed(&mut stdin, &mut stream, &log).await?;
    } else {
        let mut file = tokio::fs::File::open(&path)
            .await
            .context("Failed to open input file")?;
        copy_to_length_prefixed(&mut file, &mut stream, &log).await?;
    }
    debug!(log, "Input connection finished.");
    Ok(())
}

/// Handles the output stream: receives from the app and writes to stdout/file.
async fn handle_output_connection(mut stream: TcpStream, log: Logger) -> Result<()> {
    let path = read_length_prefixed_str(&mut stream).await?;
    info!(log, "Output connection established"; "destination" => &path);
    if path == "-" {
        let mut stdout = io::stdout();
        copy_from_length_prefixed(&mut stream, &mut stdout, &log).await?;
    } else {
        let mut file = tokio::fs::File::create(&path)
            .await
            .context("Failed to create output file")?;
        copy_from_length_prefixed(&mut stream, &mut file, &log).await?;
    }
    debug!(log, "Output connection finished.");
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
async fn copy_to_length_prefixed<R, W>(source: &mut R, dest: &mut W, log: &Logger) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 4096];
    loop {
        let len_read = source.read(&mut buf).await?;
        if len_read == 0 {
            break;
        }
        debug!(log, "Sending {} bytes", len_read);
        dest.write_u16(len_read as u16).await?;
        dest.write_all(&buf[..len_read]).await?;
    }
    dest.write_u16(0).await?; // EOF marker
    Ok(())
}

/// Reads from a u16-length-prefixed stream and writes the contents to a destination.
async fn copy_from_length_prefixed<R, W>(source: &mut R, dest: &mut W, log: &Logger) -> Result<()>
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
        debug!(log, "Receiving {} bytes", len_to_read);
        let chunk = &mut buf[..len_to_read];
        source.read_exact(chunk).await?;
        dest.write_all(chunk).await?;
    }
    Ok(())
}
