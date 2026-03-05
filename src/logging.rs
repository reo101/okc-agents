use std::sync::OnceLock;
use tracing_subscriber::EnvFilter;

static TRACING_INIT: OnceLock<()> = OnceLock::new();

pub fn init_tracing() {
    TRACING_INIT.get_or_init(|| {
        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        if let Err(error) = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(false)
            .try_init()
        {
            eprintln!("warning: failed to initialize tracing subscriber: {error}");
        }
    });
}
