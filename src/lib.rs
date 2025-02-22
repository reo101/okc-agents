use slog::{Drain, Logger};
use slog_async::{Async, AsyncGuard};
use slog_term::{FullFormat, TermDecorator};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::sync::Mutex;

pub type Result = std::result::Result<(), Box<dyn Error>>;

#[derive(Debug)]
pub struct StringError(pub String);

impl Display for StringError {
    fn fmt(&self, f: &mut Formatter) -> std::result::Result<(), std::fmt::Error> {
        self.0.fmt(f)
    }
}

impl Error for StringError {}

impl StringError {
    pub fn new(s: impl AsRef<str>) -> Self {
        Self(s.as_ref().to_owned())
    }
}

lazy_static! {
    pub static ref LOG_GUARD: Mutex<Option<AsyncGuard>> = Mutex::new(None);
}

pub fn exit_process(code: i32) -> ! {
    if let Some(guard) = LOG_GUARD.lock().unwrap().take() {
        std::mem::drop(guard);
    }
    std::process::exit(code)
}

#[tokio::main]
pub async fn lib_main<T>(run: impl FnOnce(Logger) -> T)
where
    T: Future<Output = Result>,
{
    if std::env::var("RUST_LOG")
        .map(|s| s.is_empty())
        .unwrap_or(true)
    {
        std::env::set_var("RUST_LOG", "warn");
    }
    let drain = FullFormat::new(TermDecorator::new().stderr().build())
        .build()
        .ignore_res();
    let drain = slog_envlogger::new(drain).ignore_res();
    let (drain, guard) = Async::new(drain).build_with_guard();
    *LOG_GUARD.lock().unwrap() = Some(guard);
    let logger = Logger::root(drain.ignore_res(), o!());
    if let Err(e) = run(logger.clone()).await {
        error!(logger, "{:?}", e);
        exit_process(1);
    }
}
