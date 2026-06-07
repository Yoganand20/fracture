use clap::{Parser, Subcommand};
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::watch;

use fracture::{start_proxy_engine, AppConfig, ProxyController};

#[derive(Parser)]
#[command(name = "fracture")]
#[command(about = "DNS proxy with TLS fragmentation support", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Port to run the proxy on
    #[arg(short, long, default_value = "8081")]
    port: u16,

    /// Enable TLS record fragmentation
    #[arg(short, long)]
    fragment: bool,

    /// Fragmentation size in bytes
    #[arg(short, long, default_value = "100")]
    size: usize,

    /// HTTPS only mode
    #[arg(long)]
    https_only: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the proxy server
    Start {
        /// Port to run the proxy on
        #[arg(short, long, default_value = "8081")]
        port: u16,
    },
}

#[cfg(feature = "cli")]
fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Start { port }) => {
            run_server(port, cli.fragment, cli.size, cli.https_only);
        }
        None => {
            run_server(cli.port, cli.fragment, cli.size, cli.https_only);
        }
    }
}

#[cfg(feature = "cli")]
fn build_app_config(fragment: bool, size: usize, https_only: bool) -> Arc<AppConfig> {
    Arc::new(AppConfig {
        tls_record_fragmentation: fragment,
        fragmentation_size: size,
        https_only,
        ..AppConfig::default()
    })
}

#[cfg(feature = "cli")]
fn run_server(port: u16, fragment: bool, size: usize, https_only: bool) {
    let initial_config = build_app_config(fragment, size, https_only);
    let proxy_state = Arc::new(ProxyController::new(port));

    let (_tx, rx) = watch::channel(initial_config.clone());

    // Spawn proxy engine in background thread
    let proxy_state_clone = Arc::clone(&proxy_state);
    std::thread::spawn(move || {
        let rt = Runtime::new().expect("Failed to create Tokio runtime");
        rt.block_on(async {
            if let Err(e) = start_proxy_engine(port, initial_config, rx, proxy_state_clone).await {
                eprintln!("✗ Proxy error: {}", e);
            }
        });
    });

    proxy_state.set_active(true);

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Fracture - DNS Proxy with TLS Fragmentation");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Running on:     127.0.0.1:{}", port);
    println!("🔀 Fragmentation:  {}", if fragment { "ON" } else { "OFF" });
    if fragment {
        println!("Fragment size:  {} bytes", size);
    }
    println!(
        "HTTPS only:     {}",
        if https_only { "ON" } else { "OFF" }
    );
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("\nPress Ctrl+C to stop the proxy\n");

    // Keep the main thread alive
    std::thread::park();
}
