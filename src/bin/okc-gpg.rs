use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Parser;
use eyre::{Context, Result, bail};
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

const GPG_PROTO_VER: i32 = 2;

#[cfg(test)]
#[path = "tests/gpg.rs"]
mod tests;

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

    // Key management and listing actions
    #[arg(long, help = "List public keys")]
    list_keys: bool,
    #[arg(long, help = "List secret keys")]
    list_secret_keys: bool,
    #[arg(long, help = "Show fingerprints")]
    fingerprint: bool,
    #[arg(long, help = "Show fingerprints with --list-keys")]
    with_fingerprint: bool,
    #[arg(long, help = "Show subkey fingerprints with --list-keys")]
    with_subkey_fingerprint: bool,
    #[arg(long, help = "Show keygrips with --list-keys")]
    with_keygrip: bool,
    #[arg(long, help = "Show secret material availability with --list-keys")]
    with_secret: bool,
    #[arg(long, help = "Export public keys")]
    export: bool,
    #[arg(long, help = "Export secret keys (unsupported, use --backup)")]
    export_secret_keys: bool,
    #[arg(
        long,
        help = "Create an OpenKeychain backup (not a GnuPG secret-key export)"
    )]
    backup: bool,
    #[arg(
        long,
        requires = "backup",
        help = "Include secret keys in the OpenKeychain backup"
    )]
    backup_secret: bool,
    #[arg(long, help = "Export SSH public keys")]
    export_ssh_key: bool,
    #[arg(long, help = "Import keys through OpenKeychain")]
    import: bool,
    #[arg(long, help = "Create a key through OpenKeychain")]
    gen_key: bool,
    #[arg(long, help = "Create a key through OpenKeychain (quick form)")]
    quick_gen_key: bool,
    #[arg(long, help = "Delete keys through OpenKeychain")]
    delete_keys: bool,
    #[arg(long, help = "Delete secret keys through OpenKeychain")]
    delete_secret_keys: bool,
    #[arg(long, help = "Edit keys through OpenKeychain")]
    edit_key: bool,
    #[arg(long, help = "Receive keys from a keyserver")]
    recv_keys: bool,
    #[arg(long, help = "Search keys on a keyserver")]
    search_keys: bool,
    #[arg(long, help = "Check OpenKeychain permission")]
    check_permission: bool,
    #[arg(long, help = "Decrypt metadata only")]
    metadata: bool,
    #[arg(long, help = "Show keys")]
    show_keys: bool,
    #[arg(long, help = "List packets")]
    list_packets: bool,
    #[arg(long, help = "Symmetric encryption")]
    symmetric: bool,
    #[arg(long, help = "Store only")]
    store: bool,
    #[arg(long, help = "Card status")]
    card_status: bool,
    #[arg(long, help = "Edit card")]
    card_edit: bool,
    #[arg(long, help = "Change card PIN")]
    change_pin: bool,
    #[arg(long, help = "Send keys to a keyserver")]
    send_keys: bool,
    #[arg(long, help = "Refresh keys from a keyserver")]
    refresh_keys: bool,

    // Additional recipient and option fields
    #[arg(long, value_name = "USER-ID", help = "Additional encryption recipient")]
    encrypt_to: Vec<String>,
    #[arg(long, value_name = "USER-ID", help = "Hidden encryption recipient")]
    hidden_recipient: Vec<String>,
    #[arg(long, value_name = "PASSPHRASE", help = "Use PASSPHRASE")]
    passphrase: Option<String>,
    #[arg(long, value_name = "FD", help = "Read passphrase from FD")]
    passphrase_fd: Option<String>,
    #[arg(long, value_name = "MODE", help = "Pinentry mode")]
    pinentry_mode: Option<String>,
    #[arg(long, value_name = "FD", help = "Read commands from FD")]
    command_fd: Option<String>,
    #[arg(long, help = "Text mode")]
    textmode: bool,
    #[arg(long, value_name = "STRING", help = "Comment string")]
    comment: Option<String>,
    #[arg(long, help = "Emit version")]
    emit_version: bool,
    #[arg(long, value_name = "N", help = "Include certificates")]
    include_certs: Option<String>,
    #[arg(long, help = "Force MDC")]
    force_mdc: bool,
    #[arg(long, help = "Do not warn about missing MDC")]
    no_mdc_warning: bool,
    #[arg(long, help = "Throw key IDs")]
    throw_keyids: bool,
    #[arg(long, value_name = "URL", help = "Keyserver URL")]
    keyserver: Option<String>,
    #[arg(long, value_name = "DIR", help = "Home directory")]
    homedir: Option<String>,
    #[arg(long, value_name = "FILE", help = "Options file")]
    options: Option<String>,
    #[arg(long, value_name = "FILE", help = "Keyring file")]
    keyring: Option<String>,
    #[arg(long, value_name = "FILE", help = "Secret keyring file")]
    secret_keyring: Option<String>,
    #[arg(long, value_name = "FILE", help = "Trust database")]
    trustdb_name: Option<String>,
    #[arg(long, value_name = "OPTS", help = "Export options")]
    export_options: Option<String>,
    #[arg(long, value_name = "OPTS", help = "Import options")]
    import_options: Option<String>,
    #[arg(long, value_name = "MODEL", help = "Trust model")]
    trust_model: Option<String>,
    #[arg(long, help = "Always trust")]
    always_trust: bool,
    #[arg(long, help = "Use agent")]
    use_agent: bool,
    #[arg(long, help = "Do not use agent")]
    no_use_agent: bool,
    #[arg(long, help = "Do not warn about secmem")]
    no_secmem_warning: bool,
    #[arg(long, help = "Do not warn about permissions")]
    no_permission_warning: bool,
    #[arg(long, help = "No verbose mode")]
    no_verbose: bool,

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
    #[arg(long, visible_alias = "default-user", value_name = "KEY-ID")]
    default_key: Option<String>,
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
    let unsupported = [
        (args.list_keys, "list-keys"),
        (args.list_secret_keys, "list-secret-keys"),
        (args.fingerprint, "fingerprint"),
        (args.with_fingerprint, "with-fingerprint"),
        (args.with_subkey_fingerprint, "with-subkey-fingerprint"),
        (args.with_keygrip, "with-keygrip"),
        (args.with_secret, "with-secret"),
        (args.with_colons, "with-colons"),
        (args.show_keys, "show-keys"),
        (args.export_secret_keys, "export-secret-keys"),
        (args.import, "import"),
        (args.gen_key, "gen-key"),
        (args.quick_gen_key, "quick-gen-key"),
        (args.delete_keys, "delete-keys"),
        (args.delete_secret_keys, "delete-secret-keys"),
        (args.edit_key, "edit-key"),
        (args.recv_keys, "recv-keys"),
        (args.search_keys, "search-keys"),
        (args.send_keys, "send-keys"),
        (args.refresh_keys, "refresh-keys"),
        (args.list_packets, "list-packets"),
        (args.symmetric, "symmetric"),
        (args.store, "store"),
        (args.card_status, "card-status"),
        (args.card_edit, "card-edit"),
        (args.change_pin, "change-pin"),
        (!args.hidden_recipient.is_empty(), "hidden-recipient"),
        (args.throw_keyids, "throw-keyids"),
        (args.no_encrypt_to, "no-encrypt-to"),
        (args.passphrase.is_some(), "passphrase"),
        (args.passphrase_fd.is_some(), "passphrase-fd"),
        (args.pinentry_mode.is_some(), "pinentry-mode"),
        (args.command_fd.is_some(), "command-fd"),
        (args.batch, "batch"),
        (args.no_use_agent, "no-use-agent"),
        (args.keyserver.is_some(), "keyserver"),
        (args.homedir.is_some(), "homedir"),
        (args.options.is_some(), "options"),
        (args.keyring.is_some(), "keyring"),
        (args.secret_keyring.is_some(), "secret-keyring"),
        (args.trustdb_name.is_some(), "trustdb-name"),
        (args.export_options.is_some(), "export-options"),
        (args.import_options.is_some(), "import-options"),
        (args.trust_model.is_some(), "trust-model"),
        (args.always_trust, "always-trust"),
        (args.compress_algo.is_some(), "compress-algo"),
        (args.textmode, "textmode"),
        (args.comment.is_some(), "comment"),
        (args.emit_version, "emit-version"),
        (args.include_certs.is_some(), "include-certs"),
        (args.force_mdc, "force-mdc"),
        (args.no_mdc_warning, "no-mdc-warning"),
        (args.keyid_format.is_some(), "keyid-format"),
    ];
    for (selected, option) in unsupported {
        if selected {
            bail!(
                "--{option} is not supported. Use OpenKeychain for key management and authorization."
            );
        }
    }
    if args.sign && !(args.encrypt || args.detach_sign || args.clear_sign) {
        bail!(
            "Signed-packet --sign is not supported. Use --clear-sign, --detach-sign, or --sign --encrypt."
        );
    }
    if args.status_fd.as_deref().is_some_and(|fd| fd != "2") {
        bail!("Only --status-fd 2 is supported.");
    }
    if let Some(level) = &args.bzip2_compress_level {
        if level
            .parse::<u8>()
            .ok()
            .filter(|level| *level <= 9)
            .is_none()
        {
            bail!("Compression level must be between 0 and 9.");
        }
    }
    let action_groups = [
        args.encrypt || (args.sign && !(args.detach_sign || args.clear_sign)),
        args.clear_sign,
        args.detach_sign,
        args.decrypt || args.verify,
        args.export,
        args.backup,
        args.export_ssh_key,
        args.check_permission,
        args.list_config,
    ];
    if action_groups
        .into_iter()
        .filter(|selected| *selected)
        .count()
        != 1
    {
        bail!("Select one action, or --sign --encrypt / --decrypt --verify.");
    }
    if args.backup_secret && !args.backup {
        bail!("--backup-secret requires --backup.");
    }
    if args.export_ssh_key && args.files.len() > 1 {
        bail!("--export-ssh-key accepts one key selector.");
    }
    if !(args.export || args.backup || args.export_ssh_key)
        && args.files.len() > if args.verify { 2 } else { 1 }
    {
        bail!("Too many input files for this action.");
    }
    if (args.check_permission || args.list_config) && !args.files.is_empty() {
        bail!("This action does not accept input files.");
    }
    if args.metadata && !args.decrypt {
        bail!("--metadata requires --decrypt.");
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
    add_flag!(args.list_keys, "--list-keys");
    add_flag!(args.list_secret_keys, "--list-secret-keys");
    add_flag!(args.fingerprint, "--fingerprint");
    add_flag!(args.with_fingerprint, "--with-fingerprint");
    add_flag!(args.with_subkey_fingerprint, "--with-subkey-fingerprint");
    add_flag!(args.with_keygrip, "--with-keygrip");
    add_flag!(args.with_secret, "--with-secret");
    add_flag!(args.export, "--export");
    add_flag!(args.export_secret_keys, "--export-secret-keys");
    add_flag!(args.backup, "--backup");
    add_flag!(args.backup_secret, "--backup-secret");
    add_flag!(args.export_ssh_key, "--export-ssh-key");
    add_flag!(args.import, "--import");
    add_flag!(args.gen_key, "--gen-key");
    add_flag!(args.quick_gen_key, "--quick-gen-key");
    add_flag!(args.delete_keys, "--delete-keys");
    add_flag!(args.delete_secret_keys, "--delete-secret-keys");
    add_flag!(args.edit_key, "--edit-key");
    add_flag!(args.recv_keys, "--recv-keys");
    add_flag!(args.search_keys, "--search-keys");
    add_flag!(args.check_permission, "--check-permission");
    add_flag!(args.metadata, "--metadata");
    add_flag!(args.show_keys, "--show-keys");
    add_flag!(args.list_packets, "--list-packets");
    add_flag!(args.symmetric, "--symmetric");
    add_flag!(args.store, "--store");
    add_flag!(args.card_status, "--card-status");
    add_flag!(args.card_edit, "--card-edit");
    add_flag!(args.change_pin, "--change-pin");
    add_flag!(args.send_keys, "--send-keys");
    add_flag!(args.refresh_keys, "--refresh-keys");

    // Options
    add_flag!(args.armor, "--armor");
    add_flag!(args.quiet, "--quiet");
    add_flag!(args.yes, "--yes");
    add_flag!(args.no, "--no");
    add_flag!(args.no_encrypt_to, "--no-encrypt-to");
    add_flag!(args.verbose, "--verbose");
    add_flag!(args.list_config, "--list-config");
    add_flag!(args.with_colons, "--with-colons");
    add_flag!(args.textmode, "--textmode");
    add_flag!(args.emit_version, "--emit-version");
    add_flag!(args.force_mdc, "--force-mdc");
    add_flag!(args.no_mdc_warning, "--no-mdc-warning");
    add_flag!(args.throw_keyids, "--throw-keyids");
    add_flag!(args.always_trust, "--always-trust");
    add_flag!(args.use_agent, "--use-agent");
    add_flag!(args.no_use_agent, "--no-use-agent");
    add_flag!(args.no_secmem_warning, "--no-secmem-warning");
    add_flag!(args.no_permission_warning, "--no-permission-warning");
    add_flag!(args.no_verbose, "--no-verbose");

    // Options with values
    add_option!(&args.output, "--output");
    add_option!(&args.bzip2_compress_level, "--bzip2-compress-level");
    add_option!(&args.set_filename, "--set-filename");
    add_option!(&args.status_fd, "--status-fd");
    add_option!(&args.local_user, "--local-user");
    add_option!(&args.default_key, "--default-key");
    add_option!(&args.passphrase, "--passphrase");
    add_option!(&args.passphrase_fd, "--passphrase-fd");
    add_option!(&args.pinentry_mode, "--pinentry-mode");
    add_option!(&args.command_fd, "--command-fd");
    add_option!(&args.compress_algo, "--compress-algo");
    add_option!(&args.comment, "--comment");
    add_option!(&args.include_certs, "--include-certs");
    add_option!(&args.keyserver, "--keyserver");
    add_option!(&args.homedir, "--homedir");
    add_option!(&args.options, "--options");
    add_option!(&args.keyring, "--keyring");
    add_option!(&args.secret_keyring, "--secret-keyring");
    add_option!(&args.trustdb_name, "--trustdb-name");
    add_option!(&args.export_options, "--export-options");
    add_option!(&args.import_options, "--import-options");
    add_option!(&args.trust_model, "--trust-model");

    // Multi-value options
    for r in &args.recipient {
        constructed_args.push("--recipient".to_string());
        constructed_args.push(r.clone());
    }
    for r in &args.encrypt_to {
        constructed_args.push("--encrypt-to".to_string());
        constructed_args.push(r.clone());
    }
    for r in &args.hidden_recipient {
        constructed_args.push("--hidden-recipient".to_string());
        constructed_args.push(r.clone());
    }

    // Do not interpret a filename beginning with '-' as an app option.
    if !args.files.is_empty() {
        constructed_args.push("--".to_string());
        constructed_args.extend(args.files.clone());
    }

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

    let inputs = if args.encrypt
        || args.sign
        || args.clear_sign
        || args.detach_sign
        || args.decrypt
        || args.verify
    {
        if args.files.is_empty() {
            vec!["-".to_string()]
        } else {
            args.files
        }
    } else {
        Vec::new()
    };
    serve_gpg_connections(
        listener,
        inputs,
        args.output.unwrap_or_else(|| "-".to_string()),
    )
    .await
}

async fn serve_gpg_connections(
    listener: TcpListener,
    allowed_inputs: Vec<String>,
    allowed_output: String,
) -> Result<()> {
    let (mut control, addr) = time::timeout(Duration::from_secs(15), listener.accept())
        .await
        .context("Timed out waiting for the app control connection.")??;
    let kind = ConnectionType::try_from(
        time::timeout(Duration::from_secs(15), control.read_u8())
            .await
            .context("Timed out reading control connection type")?
            .context("Failed to read connection type")?,
    )?;
    if !matches!(kind, ConnectionType::Control) {
        bail!("Expected the control connection first, got {kind:?}");
    }
    debug!(from = %addr, "Accepted control connection");

    let control_task = handle_control_connection(control);
    tokio::pin!(control_task);
    let mut inputs = tokio::task::JoinSet::new();
    let mut outputs = tokio::task::JoinSet::new();
    let exit_code = loop {
        tokio::select! {
            // The app closes data streams before sending its final status. Accept
            // queued connections first so fast, output-only actions lose no data.
            biased;
            accepted = listener.accept() => {
                let (mut stream, addr) = accepted?;
                let kind = ConnectionType::try_from(
                    time::timeout(Duration::from_secs(15), stream.read_u8())
                        .await
                        .context("Timed out reading connection type")??,
                )?;
                debug!(from = %addr, ?kind, "Accepted app connection");
                match kind {
                    ConnectionType::Control => bail!("Received duplicate control connection"),
                    ConnectionType::Input => { inputs.spawn(handle_input_connection(stream, allowed_inputs.clone())); }
                    ConnectionType::Output => { outputs.spawn(handle_output_connection(stream, allowed_output.clone())); }
                }
            }
            result = inputs.join_next(), if !inputs.is_empty() => {
                result.expect("Input task exists").context("Input handler panicked")??;
            }
            result = outputs.join_next(), if !outputs.is_empty() => {
                result.expect("Output task exists").context("Output handler panicked")??;
            }
            status = &mut control_task => { break status?; }
        }
    };

    // An API action can stop reading input early. Never leave a stdin reader
    // alive after completion or failure. JoinSet also cancels tasks on errors.
    inputs.abort_all();
    if exit_code != 0 {
        bail!("The app reported an error (status code: {exit_code})");
    }
    time::timeout(Duration::from_secs(15), async {
        while let Some(result) = outputs.join_next().await {
            result.context("Output handler panicked")??;
        }
        Ok::<_, eyre::Report>(())
    })
    .await
    .context("Timed out draining app output")??;
    info!(exit_code, "All app connections finished");
    Ok(())
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
            _ if msg.starts_with("[GNUPG:] ") => eprintln!("{msg}"),
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
async fn handle_input_connection(mut stream: TcpStream, allowed_paths: Vec<String>) -> Result<()> {
    let path = read_length_prefixed_str(&mut stream).await?;
    if !allowed_paths.contains(&path) {
        bail!("The app requested an input path not selected by this invocation");
    }
    info!(source = %path, "Input connection established");

    if path == "-" {
        // Tokio's stdin uses a blocking-pool read that prevents runtime shutdown
        // when an API action finishes before stdin reaches EOF. A bounded worker
        // thread can be discarded at process exit without holding that pool open.
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        std::thread::spawn(move || {
            let mut input = std::io::stdin().lock();
            loop {
                let mut bytes = vec![0; FRAME_CHUNK_SIZE];
                let frame = std::io::Read::read(&mut input, &mut bytes).map(|size| {
                    bytes.truncate(size);
                    bytes
                });
                let finished = frame.as_ref().map_or(true, Vec::is_empty);
                if sender.blocking_send(frame).is_err() || finished {
                    break;
                }
            }
        });
        while let Some(frame) = receiver.recv().await {
            let bytes = frame.context("Failed to read stdin")?;
            stream.write_u16(bytes.len() as u16).await?;
            stream.write_all(&bytes).await?;
            if bytes.is_empty() {
                stream.shutdown().await?;
                break;
            }
        }
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
async fn handle_output_connection(mut stream: TcpStream, allowed_path: String) -> Result<()> {
    let path = read_length_prefixed_str(&mut stream).await?;
    if path != allowed_path {
        bail!("The app requested an output path not selected by this invocation");
    }
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
