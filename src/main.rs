mod components;
mod dns;
mod icons;
mod os;
mod proxy;
mod route;
mod views;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::watch;

use crate::dns::resolver::{DnsConfig, DnsResolver, DnsType};
use crate::os::proxy::SystemProxy;
use crate::proxy::handler::handle_connection;

#[cfg(target_os = "windows")]
use dioxus::desktop::tao::platform::windows::WindowBuilderExtWindows;
use dioxus::desktop::{Config, LogicalSize, WindowBuilder};
use dioxus::prelude::*;
use route::Route;

const FAVICON: Asset = asset!("/assets/favicon.ico");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

pub static IS_PROXY_ACTIVE: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub tls_record_fragmentation: bool,
    pub fragmentation_size: usize,
    pub https_only: bool,
    pub dns: DnsConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            tls_record_fragmentation: false,
            fragmentation_size: 100,
            https_only: false,
            dns: DnsConfig {
                dns_type: DnsType::Https,
                server_url: "cloudflare-dns.com".to_string(),
                ips: vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
                port: 443,
                cache_size: 1000,
            },
        }
    }
}

fn main() {
    let port = 8081;

    // Create the Watch Channel wrapped in an Arc for cheap cloning
    let initial_config = Arc::new(AppConfig::default());
    let (tx, mut rx) = watch::channel(initial_config);

    // Spawn the background Proxy Engine
    thread::spawn(move || {
        let rt: Runtime = Runtime::new().expect("Failed to create Tokio runtime");

        rt.block_on(async {
            // Read initial state from the channel
            let mut current_config = rx.borrow().clone();

            // Initialize DNS Resolver
            let mut current_dns =
                Arc::new(DnsResolver::new(&current_config.dns).expect("Failed to init DNS"));

            // Bind the TCP port
            let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
                .await
                .expect("Failed to bind proxy port");

            println!(
                "Proxy engine loaded in background on 127.0.0.1:{} (Currently OFF)",
                port
            );

            // Listen for connections
            loop {
                // A. VERY FAST NON-BLOCKING CHECK: Has the Dioxus UI sent a new config?
                if rx.has_changed().unwrap_or(false) {
                    current_config = rx.borrow_and_update().clone();
                    println!("Proxy Engine detected a settings update! Applying...");

                    // Re-initialize the DNS resolver if the settings changed
                    match DnsResolver::new(&current_config.dns) {
                        Ok(new_dns) => current_dns = Arc::new(new_dns),
                        Err(e) => eprintln!("Failed to update DNS resolver: {}", e),
                    }
                }

                // B. Wait for a browser connection
                match listener.accept().await {
                    Ok((socket, _)) => {
                        // Drop the connection immediately if the user toggled the proxy off
                        if !IS_PROXY_ACTIVE.load(Ordering::Relaxed) {
                            continue;
                        }

                        // Cheaply clone the Arc pointers to pass to the connection handler
                        let config_clone = Arc::clone(&current_config);
                        let dns_clone = Arc::clone(&current_dns);

                        // Spawn handler
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(socket, config_clone, dns_clone).await
                            {
                                // Ignore standard disconnections, log unexpected ones
                                let kind = e.kind();
                                if kind != std::io::ErrorKind::ConnectionReset
                                    && kind != std::io::ErrorKind::UnexpectedEof
                                {
                                    eprintln!("Connection handler error: {}", e);
                                }
                            }
                        });
                    }
                    Err(e) => eprintln!("Failed to accept connection: {}", e),
                }
            }
        });
    });

    // Spawn the Dioxus Desktop UI
    let mut window = WindowBuilder::new()
        .with_decorations(false)
        .with_transparent(true)
        .with_undecorated_shadow(false)
        .with_inner_size(LogicalSize::new(300.0, 600.0))
        .with_resizable(false);

    #[cfg(target_os = "windows")]
    {
        window = window.with_undecorated_shadow(false);
    }

    let config = Config::new().with_window(window);

    // INJECT the Transmitter into the Dioxus App context!
    LaunchBuilder::desktop()
        .with_cfg(config)
        .with_context(tx)
        .launch(App);

    // Cleanup when UI window is closed
    println!("UI Closed. Disabling system proxy...");
    let _ = SystemProxy::disable();
}

/// App is the main component of our app.
#[component]
fn App() -> Element {
    // Read the global watch channel sender that was passed into LaunchBuilder
    let tx = use_context::<tokio::sync::watch::Sender<Arc<AppConfig>>>();

    // Provide the initial state to the rest of the Dioxus UI
    use_context_provider(|| Signal::new((*tx.borrow()).as_ref().clone()));

    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        div { class: "w-screen h-screen bg-white rounded-2xl overflow-hidden border-2",
            Router::<Route> {}
        }
    }
}
