use clap::{Parser, Subcommand};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};

use fracture::dns::resolver::DnsConfig;
use fracture::logging::{init_file_logger, LogLevelHandle}; // Import alias handle
use fracture::os::proxy::SystemProxy;
use fracture::{spawn_background_engine, AppConfig, EngineHandle};

#[derive(Parser)]
#[command(name = "fracture")]
#[command(about = "DNS proxy with TLS fragmentation support", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(short, long, default_value = "8081")]
    port: u16,

    #[arg(short, long)]
    fragment: bool,

    #[arg(short, long, default_value = "100")]
    size: usize,

    #[arg(long)]
    https_only: bool,
}

#[derive(Subcommand)]
enum Commands {
    Start {
        #[arg(short, long, default_value = "8081")]
        port: u16,
    },
}

#[cfg(feature = "cli")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target_log_dir = "./logs";

    // Destructure both the lifetime guard and our dynamic filter configuration handle
    let (_log_guard, log_handle) = init_file_logger(target_log_dir);

    tracing::info!("Starting up network manipulation subsystem...");

    let cli = Cli::parse();
    let config = build_app_config(cli.fragment, cli.size, cli.https_only);

    match cli.command {
        Some(Commands::Start { port }) => {
            run_interactive_cli(port, config, log_handle);
        }
        None => {
            run_interactive_cli(cli.port, config, log_handle);
        }
    }

    tracing::info!("Exiting primary thread runtime application environment cleanly.");
    std::process::exit(0);
}

fn build_app_config(fragment: bool, size: usize, https_only: bool) -> Arc<AppConfig> {
    Arc::new(AppConfig {
        tls_record_fragmentation: fragment,
        fragmentation_size: size,
        https_only,
        dns: DnsConfig::default(),
    })
}

fn run_interactive_cli(port: u16, initial_config: Arc<AppConfig>, log_handle: LogLevelHandle) {
    let engine = spawn_background_engine(port, initial_config.clone());
    let mut current_config = (*initial_config).clone();

    if let Err(e) = SystemProxy::enable(port) {
        eprintln!("⚠ Failed to set system proxy: {}", e);
    }
    engine.proxy_state.set_active(true);

    let rt = tokio::runtime::Runtime::new().expect("Failed to create interactive runtime");

    rt.block_on(async {
        print_welcome_banner(port, &current_config, engine.proxy_state.is_active());
        print_help_menu();

        let mut stdin_lines = BufReader::new(tokio::io::stdin()).lines();

        loop {
            print!("fracture> ");
            use std::io::Write;
            std::io::stdout().flush().unwrap();

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("\n\n[!] Interrupt detected. Commencing shutdown sequence...");
                    break;
                }

                line_result = stdin_lines.next_line() => {
                    match line_result {
                        Ok(Some(line)) => {
                            let input = line.trim();
                            if input.is_empty() { continue; }

                            // Pass log_handle into the command parser interface
                            if handle_command(input, port, &engine, &mut current_config, &log_handle).await {
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("✗ Error reading console stream: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });

    println!("Cleaning up network routing allocations...");
    if let Err(e) = SystemProxy::disable() {
        eprintln!("⚠ Failed to cleanly reset system proxy settings: {}", e);
    }
    engine.proxy_state.set_active(false);
    println!("Fracture CLI terminated cleanly.");
}

async fn handle_command(
    input: &str,
    port: u16,
    engine: &EngineHandle,
    config: &mut AppConfig,
    log_handle: &LogLevelHandle,
) -> bool {
    let parts: Vec<&str> = input.split_whitespace().collect();
    let command = parts[0].to_lowercase();

    match command.as_str() {
        "help" | "?" => {
            print_help_menu();
        }
        "status" => {
            print_status(port, config, engine.proxy_state.is_active());
        }
        "start" => {
            if engine.proxy_state.is_active() {
                println!("Proxy engine is already running.");
            } else {
                if let Err(e) = SystemProxy::enable(port) {
                    eprintln!("⚠ Failed to enable system proxy: {}", e);
                }
                engine.proxy_state.set_active(true);
                println!("✓ Proxy engine started and system routing is active.");
            }
        }
        "stop" => {
            if !engine.proxy_state.is_active() {
                println!("Proxy engine is already stopped.");
            } else {
                let _ = SystemProxy::disable();
                engine.proxy_state.set_active(false);
                println!("🛑 Proxy engine stopped. Traffic routing bypassed back to raw system.");
            }
        }
        // =====================================================================
        // NEW INTERACTIVE COMMAND: log <error|warn|info|debug|trace|off>
        // =====================================================================
        "log" => {
            if parts.len() < 2 {
                println!("Usage: log <trace|debug|info|warn|error|off>");
                return false;
            }

            use tracing_subscriber::filter::LevelFilter;
            let target_filter = match parts[1].to_lowercase().as_str() {
                "off" => Some(LevelFilter::OFF),
                "trace" => Some(LevelFilter::TRACE),
                "debug" => Some(LevelFilter::DEBUG),
                "info" => Some(LevelFilter::INFO),
                "warn" => Some(LevelFilter::WARN),
                "error" => Some(LevelFilter::ERROR),
                _ => None,
            };

            if let Some(filter) = target_filter {
                // Hot-swap the runtime tracing filter safely across executing tasks
                if log_handle.modify(|f| *f = filter).is_ok() {
                    println!(
                        "⚙ Logging pipeline updated threshold metrics to: [{}]",
                        parts[1].to_uppercase()
                    );
                    tracing::info!(
                        "Logger threshold altered to {} via console interaction shell.",
                        parts[1].to_uppercase()
                    );
                } else {
                    println!(
                        "✗ Critical Error: Internal tracking framework reload channel faulted."
                    );
                }
            } else {
                println!(
                    "✗ Invalid log metric. Choose from: trace, debug, info, warn, error, off."
                );
            }
        }
        "fragment" => {
            if parts.len() < 2 {
                println!("Usage: fragment <on|off>");
                return false;
            }
            match parts[1].to_lowercase().as_str() {
                "on" => config.tls_record_fragmentation = true,
                "off" => config.tls_record_fragmentation = false,
                _ => {
                    println!("Invalid argument. Use 'on' or 'off'.");
                    return false;
                }
            }
            let _ = engine.config_tx.send(Arc::new(config.clone()));
            println!(
                "⚙ Config updated: TLS fragmentation is now {}",
                if config.tls_record_fragmentation {
                    "ON"
                } else {
                    "OFF"
                }
            );
        }
        "size" => {
            if parts.len() < 2 {
                println!("Usage: size <bytes>");
                return false;
            }
            if let Ok(new_size) = parts[1].parse::<usize>() {
                config.fragmentation_size = new_size;
                let _ = engine.config_tx.send(Arc::new(config.clone()));
                println!(
                    "⚙ Config updated: Fragmentation payload boundaries split at {} bytes.",
                    new_size
                );
            } else {
                println!(
                    "✗ Invalid size unit parsing parameter. Provide a valid integer payload size."
                );
            }
        }
        "https" => {
            if parts.len() < 2 {
                println!("Usage: https <on|off>");
                return false;
            }
            match parts[1].to_lowercase().as_str() {
                "on" => config.https_only = true,
                "off" => config.https_only = false,
                _ => {
                    println!("Invalid option. Use 'on' or 'off'.");
                    return false;
                }
            }
            let _ = engine.config_tx.send(Arc::new(config.clone()));
            println!(
                "⚙ Config updated: HTTPS Strict Mode is {}",
                if config.https_only { "ON" } else { "OFF" }
            );
        }
        "exit" | "quit" => {
            println!("Exiting interface shell...");
            return true;
        }
        _ => {
            println!(
                "⚠ Unknown interactive command: '{}'. Type 'help' to see list of options.",
                command
            );
        }
    }
    false
}

fn print_welcome_banner(port: u16, config: &AppConfig, is_active: bool) {
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Fracture Engine CLI Interface Interactive Mode");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    print_status(port, config, is_active);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

fn print_help_menu() {
    println!("\nAvailable Interactive Commands:");
    println!("  status           - Displays current status and configurations");
    println!("  start            - Activates engine and updates system proxy rules");
    println!("  stop             - Suspends engine processing and detaches system proxy");
    println!("  log <level|off>  - Live hot-swap logging levels (trace|debug|info|warn|error|off)");
    println!("  fragment <on|off> - Toggles TLS packet segmentation configurations");
    println!("  size <bytes>   - Configures maximum size of fragmented records");
    println!("  https <on|off>    - Forces strictly encrypted validation downstream");
    println!("  help / ?       - Shows this reference table menu");
    println!("  exit / quit    - Terminates session safely\n");
}

fn print_status(port: u16, config: &AppConfig, is_active: bool) {
    println!(
        "Engine Loop Status: {}",
        if is_active {
            "🟢 ACTIVE (ON)"
        } else {
            "🔴 SUSPENDED (OFF)"
        }
    );
    println!("Listening Port:     127.0.0.1:{}", port);
    println!(
        "Fragmentation:      {}",
        if config.tls_record_fragmentation {
            "ON"
        } else {
            "OFF"
        }
    );
    if config.tls_record_fragmentation {
        println!("└── split threshold: {} bytes", config.fragmentation_size);
    }
    println!(
        "HTTPS Only Enforcement: {}",
        if config.https_only { "ON" } else { "OFF" }
    );
}
