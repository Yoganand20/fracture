use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tracing::{debug, error, info, trace, warn};

#[derive(Debug, Clone, PartialEq)]
pub enum DnsType {
    Https,       // DoH
    Tls,         // DoT
    Quic,        // DoQ
    Unencrypted, // Port 53 UDP/TCP
}

#[derive(Clone, Debug)]
pub struct DnsConfig {
    pub dns_type: DnsType,
    pub server_url: String, // e.g., "cloudflare-dns.com"
    pub ips: Vec<String>,   // e.g., ["1.1.1.1", "1.0.0.1"]
    pub port: u16,          // 443, 853, or 53
    pub cache_size: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            dns_type: DnsType::Https,
            server_url: "cloudflare-dns.com".to_string(),
            ips: vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
            port: 443,
            cache_size: 1000,
        }
    }
}

#[derive(Debug)]
pub struct DnsResolver {
    resolver: TokioAsyncResolver,
}

impl DnsResolver {
    /// Creates a new cross-platform DNS resolver based on the provided config.
    pub fn new(config: &DnsConfig) -> std::io::Result<Self> {
        debug!(
            dns_type = ?config.dns_type,
            server_url = %config.server_url,
            configured_ips = config.ips.len(),
            cache_limit = config.cache_size,
            "Assembling Hickory-backed async network DNS core cluster"
        );

        let mut resolver_config = ResolverConfig::new();
        let mut opts = ResolverOpts::default();

        // 1. Configure Hickory's native, highly-optimized cache
        opts.cache_size = config.cache_size as usize;
        opts.try_tcp_on_error = true;

        // 2. Determine TLS SNI Name
        let tls_dns_name = if config.server_url.is_empty() {
            None
        } else {
            Some(config.server_url.clone())
        };

        // 3. Build Name Servers
        for ip_str in &config.ips {
            let ip_addr = IpAddr::from_str(ip_str).map_err(|e| {
                error!(error = %e, invalid_raw_ip = %ip_str, "Aborting runtime resolver bootstrap due to malformed static IP constraint");
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid IP address: {}", ip_str),
                )
            })?;
            let socket_addr = SocketAddr::new(ip_addr, config.port);

            // A helper closure to avoid repeating NameServerConfig boilerplate
            let mut add_server = |protocol: Protocol| {
                trace!(
                    target_socket = %socket_addr,
                    transport_proto = ?protocol,
                    sni_identity = ?tls_dns_name,
                    "Registering upstream system authority entry to route network queries"
                );
                resolver_config.add_name_server(NameServerConfig {
                    socket_addr,
                    protocol,
                    tls_dns_name: tls_dns_name.clone(),
                    trust_negative_responses: false,
                    bind_addr: None,
                    tls_config: None,
                });
            };

            // Notice how much cleaner this is now!
            match config.dns_type {
                DnsType::Https => add_server(Protocol::Https),
                DnsType::Tls => add_server(Protocol::Tls),
                DnsType::Quic => add_server(Protocol::Quic),
                DnsType::Unencrypted => {
                    add_server(Protocol::Udp);
                    add_server(Protocol::Tcp); // Fallback
                }
            }
        }

        let resolver = TokioAsyncResolver::tokio(resolver_config, opts);
        info!("Async cross-platform DNS resolver initialized and armed successfully");
        Ok(Self { resolver })
    }

    /// Resolves a domain name to an IP Address, utilizing Hickory's built-in cache.
    pub async fn lookup(&self, domain: &str) -> std::io::Result<IpAddr> {
        trace!(
            query_domain = domain,
            "Initiating domain address resolution sequence"
        );

        // 1. If it's already a raw IP, return immediately
        if let Ok(ip) = IpAddr::from_str(domain) {
            debug!(matched_literal = %ip, "Domain evaluation bypassed; target identifier is a raw IP literal format");
            return Ok(ip);
        }

        // 2. Perform network lookup (Hickory automatically checks its internal cache first!)
        let response = self.resolver.lookup_ip(domain).await.map_err(|e| {
            warn!(error = %e, lookup_target = domain, "Upstream DNS endpoint mapping interface query failed or timed out");
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("DNS resolution failed for {}: {}", domain, e),
            )
        })?;

        // 3. Grab the first valid IP and return
        let target_ip = response.iter().next().ok_or_else(|| {
            error!(lookup_target = domain, "Upstream pipeline transaction indicated success but yielded empty dynamic record arrays");
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No IP records found for domain",
            )
        })?;

        debug!(lookup_target = domain, mapped_ip = %target_ip, "Successfully completed atomic host resolution cycle");
        Ok(target_ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to generate DNS configs for testing
    fn create_test_config(dns_type: DnsType, ips: Vec<&str>, url: &str, port: u16) -> DnsConfig {
        DnsConfig {
            dns_type,
            server_url: url.to_string(),
            ips: ips.into_iter().map(|s| s.to_string()).collect(),
            port,
            cache_size: 100,
        }
    }

    // =====================================================================
    // 1. PROTOCOL TESTS (Happy Paths)
    // =====================================================================

    #[tokio::test]
    async fn test_dns_unencrypted_udp_tcp_fallback() {
        // Testing Google's Primary and Secondary Unencrypted DNS
        let config = create_test_config(DnsType::Unencrypted, vec!["8.8.8.8", "8.8.4.4"], "", 53);
        let resolver = DnsResolver::new(&config).expect("Failed to init UDP resolver");

        let ip = resolver
            .lookup("example.com")
            .await
            .expect("UDP resolution failed");
        assert!(ip.is_ipv4() || ip.is_ipv6());

        // To test the internal Hickory cache, we perform the exact same lookup again.
        // It should resolve instantly without network overhead.
        let cached_ip = resolver
            .lookup("example.com")
            .await
            .expect("Cached resolution failed");
        assert_eq!(ip, cached_ip, "Cached IP did not match original resolution");
    }

    #[tokio::test]
    async fn test_dns_over_https_doh() {
        // Testing encrypted DoH (Port 443) using Cloudflare
        let config = create_test_config(
            DnsType::Https,
            vec!["1.1.1.1", "1.0.0.1"],
            "cloudflare-dns.com",
            443,
        );
        let resolver = DnsResolver::new(&config).expect("Failed to init DoH resolver");

        let ip = resolver
            .lookup("rust-lang.org")
            .await
            .expect("DoH resolution failed");
        assert!(ip.is_ipv4() || ip.is_ipv6());
    }

    #[tokio::test]
    async fn test_dns_over_tls_dot() {
        // Testing encrypted DoT (Port 853) using Cloudflare
        let config = create_test_config(
            DnsType::Tls,
            vec!["1.1.1.1", "1.0.0.1"],
            "cloudflare-dns.com",
            853,
        );
        let resolver = DnsResolver::new(&config).expect("Failed to init DoT resolver");

        let ip = resolver
            .lookup("cloudflare.com")
            .await
            .expect("DoT resolution failed");
        assert!(ip.is_ipv4() || ip.is_ipv6());
    }

    #[tokio::test]
    async fn test_dns_over_quic_doq() {
        // Testing encrypted DoQ (Port 853) using AdGuard
        let config = create_test_config(
            DnsType::Quic,
            vec!["94.140.14.14"],
            "dns.adguard-dns.com",
            853,
        );
        let resolver = DnsResolver::new(&config).expect("Failed to init DoQ resolver");

        let ip = resolver
            .lookup("github.com")
            .await
            .expect("DoQ resolution failed");
        assert!(ip.is_ipv4() || ip.is_ipv6());
    }

    // =====================================================================
    // 2. EDGE CASES & ERROR HANDLING (Sad Paths)
    // =====================================================================

    #[tokio::test]
    async fn test_raw_ip_bypass() {
        let config = create_test_config(DnsType::Unencrypted, vec!["8.8.8.8"], "", 53);
        let resolver = DnsResolver::new(&config).unwrap();

        // Providing a raw IP instead of a domain should return instantly without network calls
        let ip = resolver.lookup("127.0.0.1").await.unwrap();
        assert_eq!(ip, IpAddr::from_str("127.0.0.1").unwrap());
    }

    #[tokio::test]
    async fn test_invalid_ip_in_config() {
        // Simulating bad user input from the UI
        let config = create_test_config(DnsType::Unencrypted, vec!["not_an_ip_address"], "", 53);

        let result = DnsResolver::new(&config);

        assert!(
            result.is_err(),
            "Resolver should fail to initialize with a malformed IP"
        );
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn test_lookup_nonexistent_domain() {
        let config = create_test_config(DnsType::Unencrypted, vec!["8.8.8.8"], "", 53);
        let resolver = DnsResolver::new(&config).expect("Failed to init resolver");

        // Attempting to resolve a domain that absolutely does not exist
        let result = resolver
            .lookup("this-domain-definitely-does-not-exist-12345.local")
            .await;

        assert!(
            result.is_err(),
            "Resolver should return an error for non-existent domains"
        );
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }
}
