#[cfg(feature = "desktop")]
pub mod components;
#[cfg(feature = "desktop")]
pub mod icons;
#[cfg(feature = "desktop")]
pub mod route;
#[cfg(feature = "desktop")]
pub mod views;

pub mod dns;
pub mod os;
pub mod proxy;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::dns::resolver::{DnsConfig, DnsResolver, DnsType};
use crate::proxy::handler::handle_connection;

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

/// Start the proxy engine server
pub async fn start_proxy_engine(
    port: u16,
    config: Arc<AppConfig>,
    rx: watch::Receiver<Arc<AppConfig>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut current_config = config;
    let mut current_dns =
        Arc::new(DnsResolver::new(&current_config.dns).expect("Failed to init DNS"));
    let mut rx = rx;

    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind proxy port");

    println!(
        "✓ Proxy engine loaded on 127.0.0.1:{} (Currently OFF)",
        port
    );

    loop {
        // Check for config updates
        if rx.has_changed().unwrap_or(false) {
            current_config = rx.borrow_and_update().clone();
            println!("⚙ Settings update detected! Applying...");

            match DnsResolver::new(&current_config.dns) {
                Ok(new_dns) => current_dns = Arc::new(new_dns),
                Err(e) => eprintln!("✗ Failed to update DNS resolver: {}", e),
            }
        }

        // Wait for a connection
        match listener.accept().await {
            Ok((socket, _)) => {
                if !IS_PROXY_ACTIVE.load(Ordering::Relaxed) {
                    continue;
                }

                let config_clone = Arc::clone(&current_config);
                let dns_clone = Arc::clone(&current_dns);

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(socket, config_clone, dns_clone).await {
                        let kind = e.kind();
                        if kind != std::io::ErrorKind::ConnectionReset
                            && kind != std::io::ErrorKind::UnexpectedEof
                        {
                            eprintln!("✗ Connection error: {}", e);
                        }
                    }
                });
            }
            Err(e) => eprintln!("✗ Failed to accept connection: {}", e),
        }
    }
}
