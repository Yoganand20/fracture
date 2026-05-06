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
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            tls_record_fragmentation: false, // Default to blind chunking
            fragmentation_size: 100,
            https_only: false,
        }
    }
}

fn main() {
    let port = 8081;

    // Spawn the background Proxy Engine
    thread::spawn(move || {
        let rt = Runtime::new().expect("Failed to create Tokio runtime");

        rt.block_on(async {
            // 1. Initialize DNS
            let dns_config = DnsConfig {
                dns_type: DnsType::Https,
                server_url: "cloudflare-dns.com".to_string(),
                ip: "1.1.1.1".to_string(),
                port: 443,
                cache_size: 1000,
            };
            let dns = Arc::new(DnsResolver::new(&dns_config).expect("Failed to init DNS"));

            // 2. Initialize Proxy Settings (Currently hardcoded, needs to be synced with Dioxus UI later!)
            let app_config = Arc::new(AppConfig::default());

            // 3. Bind the local TCP port
            let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
                .await
                .expect("Failed to bind proxy port");

            println!(
                "Proxy engine loaded in background on 127.0.0.1:{} (Currently OFF)",
                port
            );

            // 4. Listen for incoming browser connections
            loop {
                match listener.accept().await {
                    Ok((socket, _)) => {
                        // Drop the connection immediately if the user toggled the proxy off
                        if !IS_PROXY_ACTIVE.load(Ordering::Relaxed) {
                            continue;
                        }

                        // Cheaply clone the Arc pointers to pass to the connection handler
                        let config_clone = Arc::clone(&app_config);
                        let dns_clone = Arc::clone(&dns);

                        // Spawn a lightweight Tokio task for the new connection
                        tokio::spawn(async move {
                            let result =
                                handle_connection(socket, config_clone, dns_clone).await;
                            if let Err(e) = result {
                                eprintln!("Connection handler error: {}", e);
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
        .with_inner_size(LogicalSize::new(300.0, 500.0))
        .with_resizable(false);

    #[cfg(target_os = "windows")]
    {
        window = window.with_undecorated_shadow(false);
    }

    let config = Config::new().with_window(window);
    LaunchBuilder::desktop().with_cfg(config).launch(App);

    // Cleanup when UI window is closed
    println!("UI Closed. Disabling system proxy...");
    let _ = SystemProxy::disable();
}

/// App is the main component of our app.
#[component]
fn App() -> Element {
    // This currently creates an isolated UI state.
    // You will need a global sync mechanism to push these changes to the Tokio thread!
    use_context_provider(|| Signal::new(AppConfig::default()));

    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        div { class: "w-screen h-screen bg-white rounded-2xl overflow-hidden border-2",
            Router::<Route> {}
        }
    }
}
