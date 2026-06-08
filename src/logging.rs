use std::path::Path;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, prelude::*, reload, Registry};

pub type LogLevelHandle = reload::Handle<tracing_subscriber::filter::LevelFilter, Registry>;

pub fn init_file_logger<P: AsRef<Path>>(directory_path: P) -> (WorkerGuard, LogLevelHandle) {
    let current_timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    let file_prefix = format!("fracture_{}", current_timestamp);

    let file_appender =
        tracing_appender::rolling::never(directory_path, format!("{}.log", file_prefix));
    let (non_blocking_writer, guard) = tracing_appender::non_blocking(file_appender);

    let (filter, reload_handle) =
        reload::Layer::new(tracing_subscriber::filter::LevelFilter::DEBUG);

    tracing_subscriber::registry()
        .with(filter) // Apply our live-reload filter globally across all layers
        .with(
            fmt::layer()
                .with_ansi(false)
                .with_target(true)
                .with_writer(non_blocking_writer),
        )
        // log to console
        //.with(fmt::layer().with_ansi(true).with_target(false))
        .init();

    tracing::info!("Tracing ecosystem loaded successfully with reloadable filters.");

    (guard, reload_handle)
}
