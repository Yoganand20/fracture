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

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::str::FromStr;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::dns::resolver::{DnsConfig, DnsResolver, DnsType};
use crate::proxy::handler::handle_connection;

#[derive(Debug)]
pub struct ProxyController {
    active: AtomicBool,
    port: u16,
}

impl ProxyController {
    pub fn new(port: u16) -> Self {
        Self {
            active: AtomicBool::new(false),
            port,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    pub fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::Relaxed);
    }
}

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
            dns: DnsConfig::default(),
        }
    }
}

impl fmt::Display for DnsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                DnsType::Https => "Https",
                DnsType::Tls => "Tls",
                DnsType::Quic => "Quic",
                DnsType::Unencrypted => "Unencrypted",
            }
        )
    }
}

impl FromStr for DnsType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Https" | "https" => Ok(DnsType::Https),
            "Tls" | "tls" => Ok(DnsType::Tls),
            "Quic" | "quic" => Ok(DnsType::Quic),
            "Unencrypted" | "unencrypted" => Ok(DnsType::Unencrypted),
            _ => Err(()),
        }
    }
}

/// Start the proxy engine server
pub async fn start_proxy_engine(
    port: u16,
    config: Arc<AppConfig>,
    mut rx: watch::Receiver<Arc<AppConfig>>,
    proxy_state: Arc<ProxyController>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut current_config = config;
    let mut current_dns = Arc::new(DnsResolver::new(&current_config.dns)?);

    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;

    println!(
        "✓ Proxy engine loaded on 127.0.0.1:{} (Currently OFF)",
        port
    );

    loop {
        tokio::select! {
            changed = rx.changed() => {
                if changed.is_err() {
                    break Ok(());
                }
                current_config = rx.borrow_and_update().clone();
                println!("⚙ Settings update detected! Applying...");

                match DnsResolver::new(&current_config.dns) {
                    Ok(new_dns) => current_dns = Arc::new(new_dns),
                    Err(e) => eprintln!("✗ Failed to update DNS resolver: {}", e),
                }
            }
            accept_result = listener.accept() => {
                let (socket, _) = accept_result?;

                if !proxy_state.is_active() {
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
        }
    }
}
