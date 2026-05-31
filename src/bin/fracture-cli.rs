use clap::{Parser, Subcommand};
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::watch;

use fracture::{start_proxy_engine, AppConfig, IS_PROXY_ACTIVE};

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
fn run_server(port: u16, fragment: bool, size: usize, https_only: bool) {
    let initial_config = Arc::new(AppConfig {
        tls_record_fragmentation: fragment,
        fragmentation_size: size,
        https_only,
        dns: AppConfig::default().dns,
    });

    let (_tx, rx) = watch::channel(initial_config.clone());

    // Spawn proxy engine in background thread
    std::thread::spawn(move || {
        let rt = Runtime::new().expect("Failed to create Tokio runtime");
        rt.block_on(async {
            if let Err(e) = start_proxy_engine(port, initial_config, rx).await {
                eprintln!("✗ Proxy error: {}", e);
            }
        });
    });

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  🔒 Fracture - DNS Proxy with TLS Fragmentation");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📍 Running on:     127.0.0.1:{}", port);
    println!("🔀 Fragmentation:  {}", if fragment { "ON" } else { "OFF" });
    if fragment {
        println!("📦 Fragment size:  {} bytes", size);
    }
    println!(
        "🔐 HTTPS only:     {}",
        if https_only { "ON" } else { "OFF" }
    );
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("\n⏳ Press Ctrl+C to stop the proxy\n");

    // Activate proxy
    IS_PROXY_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);

    // Keep the main thread alive
    std::thread::park();
}
