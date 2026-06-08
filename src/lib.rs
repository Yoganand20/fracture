#[cfg(feature = "desktop")]
pub mod components;
#[cfg(feature = "desktop")]
pub mod icons;
#[cfg(feature = "desktop")]
pub mod route;
#[cfg(feature = "desktop")]
pub mod views;

pub mod dns;
pub mod logging;
pub mod os;
pub mod proxy;

use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{debug, error, info, trace, warn};

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
        debug!(
            is_active = active,
            port = self.port,
            "Global runtime state mutation requested for proxy engine"
        );
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

/// A unified handle returned to frontend entry points (CLI or Desktop UI).
pub struct EngineHandle {
    pub proxy_state: Arc<ProxyController>,
    pub config_tx: watch::Sender<Arc<AppConfig>>,
}

/// Abstracted startup sequence that boots up a Tokio runtime on a dedicated
/// background OS thread and runs the main proxy engine loop.
pub fn spawn_background_engine(port: u16, initial_config: Arc<AppConfig>) -> EngineHandle {
    debug!(
        port,
        "Initializing dedicated background OS thread for system engine execution"
    );
    let (tx, rx) = watch::channel(initial_config.clone());
    let proxy_state = Arc::new(ProxyController::new(port));
    let proxy_state_for_engine = Arc::clone(&proxy_state);

    std::thread::spawn(move || {
        trace!("Asynchronous runtime container booting inside background thread");
        let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

        rt.block_on(async {
            if let Err(e) =
                start_proxy_engine(port, initial_config, rx, proxy_state_for_engine).await
            {
                error!(error = %e, "Core processing reactor loop exited with fatal constraint exception");
            }
        });
    });

    EngineHandle {
        proxy_state,
        config_tx: tx,
    }
}

/// Runs the asynchronous core proxy engine server, processing runtime configuration updates
/// alongside incoming client network connections.
pub async fn start_proxy_engine(
    port: u16,
    config: Arc<AppConfig>,
    mut rx: watch::Receiver<Arc<AppConfig>>,
    proxy_state: Arc<ProxyController>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut current_config = config;
    let mut current_dns = Arc::new(DnsResolver::new(&current_config.dns)?);

    let bind_address = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&bind_address).await?;

    info!(
        listen_addr = %bind_address,
        engine_status = "INITIALIZED_SUSPENDED",
        "Proxy pipeline server bound successfully; system-wide interceptor is currently idle"
    );

    loop {
        tokio::select! {
            // Evaluated when the frontend updates configuration values via the channel
            changed = rx.changed() => {
                if changed.is_err() {
                    warn!("Downstream tracking configuration reference node dropped; breaking engine sync loop");
                    break Ok(()); // Stop engine loop if the Sender handle drops
                }
                current_config = rx.borrow_and_update().clone();
                info!("Configuration alteration signature detected: hot-swapping operational engine parameters");

                match DnsResolver::new(&current_config.dns) {
                    Ok(new_dns) => {
                        current_dns = Arc::new(new_dns);
                        debug!("Hickory asynchronous resolver recompiled and deployed successfully");
                    }
                    Err(e) => error!(error = %e, "Hot-swap nameserver environment reconstruction sequence aborted"),
                }
            }
            // Evaluated when new local proxy traffic arrives
            accept_result = listener.accept() => {
                let (socket, peer_addr) = accept_result?;

                if !proxy_state.is_active() {
                    trace!(peer = %peer_addr, "Inbound local connection closed immediately: interceptor is toggled OFF");
                    continue; // Drop/Ignore connection attempt if proxy toggle is switched off
                }

                trace!(peer = %peer_addr, "Accepting local interceptor connection; dispatching handler thread");
                let config_clone = Arc::clone(&current_config);
                let dns_clone = Arc::clone(&current_dns);

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(socket, config_clone, dns_clone).await {
                        let kind = e.kind();
                        if kind != std::io::ErrorKind::ConnectionReset
                            && kind != std::io::ErrorKind::UnexpectedEof
                        {
                            error!(error = %e, error_kind = ?kind, client_host = %peer_addr, "Session handler loop faulted processing inbound transport stream");
                        } else {
                            trace!(error_kind = ?kind, client_host = %peer_addr, "Connection closed cleanly by proxy consumer or runtime socket exhaustion");
                        }
                    }
                });
            }
        }
    }
}
