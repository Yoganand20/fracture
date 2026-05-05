use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use moka::future::Cache;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub enum DnsType {
    Https,
    Tls,
    Unencrypted,
}

pub struct DnsConfig {
    pub dns_type: DnsType,
    pub server_url: String,
    pub ip: String,
    pub port: u16,
    pub cache_size: u64,
}

pub struct DnsResolver {
    cache: Cache<String, IpAddr>,
    resolver: TokioAsyncResolver,
}

impl DnsResolver {
    /// Creates a new cross-platform DNS resolver based on the provided config.
    pub fn new(config: &DnsConfig) -> std::io::Result<Self> {
        // 1. Initialize the LRU Cache
        let cache = Cache::builder()
            .max_capacity(config.cache_size)
            .time_to_idle(Duration::from_secs(5 * 60)) // Expire entries after 5 mins of inactivity
            .build();

        // 2. Configure the DNS strategy based on user preference
        let mut resolver_config = ResolverConfig::new();
        let mut opts = ResolverOpts::default();
        opts.use_hosts_file = false; // We want to route around local OS restrictions

        let server_ip = IpAddr::from_str(&config.ip)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;

        match config.dns_type {
            DnsType::Https => {
                // DNS over HTTPS (DoH)
                let mut ns =
                    NameServerConfig::new(SocketAddr::new(server_ip, 443), Protocol::Https);
                ns.tls_dns_name = Some(config.server_url.clone());
                resolver_config.add_name_server(ns);
            }
            DnsType::Tls => {
                // DNS over TLS (DoT)
                let mut ns = NameServerConfig::new(SocketAddr::new(server_ip, 853), Protocol::Tls);
                ns.tls_dns_name = Some(config.server_url.clone());
                resolver_config.add_name_server(ns);
            }
            DnsType::Unencrypted => {
                // Standard UDP DNS (Port 53)
                let ns =
                    NameServerConfig::new(SocketAddr::new(server_ip, config.port), Protocol::Udp);
                resolver_config.add_name_server(ns);
            }
        }

        // Initialize the unified Hickory Resolver using Tokio
        let resolver = TokioAsyncResolver::tokio(resolver_config, opts);

        Ok(Self { cache, resolver })
    }

    /// Resolves a hostname to an IP address, utilizing the Moka LRU cache.
    /// Equivalent to the `lookup` function in `base.js`.
    pub async fn lookup(&self, hostname: &str) -> std::io::Result<IpAddr> {
        // 1. Check if the IP is already an IP address string
        if let Ok(ip) = IpAddr::from_str(hostname) {
            return Ok(ip);
        }

        // 2. Check the LRU cache
        if let Some(cached_ip) = self.cache.get(hostname).await {
            return Ok(cached_ip);
        }

        // 3. Query the upstream DNS server
        let response = self
            .resolver
            .lookup_ip(hostname)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e.to_string()))?;

        // 4. Extract the first available IP (preferring IPv4 if multiple exist)
        if let Some(ip) = response.iter().next() {
            // Update cache
            self.cache.insert(hostname.to_string(), ip).await;
            Ok(ip)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No IP found for hostname",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // A small helper function to easily construct configs for different test scenarios
    fn create_test_config(dns_type: DnsType, ip: &str, server_url: &str, port: u16) -> DnsConfig {
        DnsConfig {
            dns_type,
            server_url: server_url.to_string(),
            ip: ip.to_string(),
            port,
            cache_size: 100,
        }
    }

    #[tokio::test]
    async fn test_direct_ip_parsing() {
        // If the user's browser requests an exact IP instead of a hostname,
        // the proxy should instantly return the IP without querying the network.
        let config = create_test_config(DnsType::Unencrypted, "8.8.8.8", "", 53);
        let resolver = DnsResolver::new(&config).expect("Failed to init resolver");

        let ip = resolver
            .lookup("192.168.1.50")
            .await
            .expect("Failed to parse IPv4");
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));

        let ipv6 = resolver
            .lookup("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
            .await
            .expect("Failed to parse IPv6");
        assert!(ipv6.is_ipv6());
    }

    #[tokio::test]
    async fn test_moka_cache_hit() {
        // Verifies that if a domain is manually placed in the cache, the resolver
        // fetches it instantly without using the underlying TokioResolver.
        let config = create_test_config(DnsType::Unencrypted, "8.8.8.8", "", 53);
        let resolver = DnsResolver::new(&config).unwrap();

        let mock_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));

        // Inject fake data into the cache
        resolver
            .cache
            .insert("my-secret-domain.com".to_string(), mock_ip)
            .await;

        // Lookup should hit the cache immediately and NOT throw a DNS resolution error
        let ip = resolver.lookup("my-secret-domain.com").await.unwrap();
        assert_eq!(ip, mock_ip);
    }

    #[tokio::test]
    async fn test_invalid_domain_fails_gracefully() {
        // Verifies that non-existent domains correctly bubble up an std::io::Error
        let config = create_test_config(DnsType::Unencrypted, "8.8.8.8", "", 53);
        let resolver = DnsResolver::new(&config).unwrap();

        let result = resolver
            .lookup("this-domain-definitely-does-not-exist-123456789.local")
            .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn test_unencrypted_udp_resolution() {
        // Tests standard Port 53 resolution using Google's Public DNS
        let config = create_test_config(DnsType::Unencrypted, "8.8.8.8", "", 53);
        let resolver = DnsResolver::new(&config).expect("Failed to init UDP resolver");

        let ip = resolver
            .lookup("example.com")
            .await
            .expect("UDP resolution failed");
        assert!(ip.is_ipv4() || ip.is_ipv6());

        // Verify it was automatically cached for future use
        assert!(resolver.cache.contains_key("example.com"));
    }

    #[tokio::test]
    async fn test_dns_over_https_doh() {
        // Tests encrypted DoH (Port 443) using Cloudflare's 1.1.1.1
        let config = create_test_config(DnsType::Https, "1.1.1.1", "cloudflare-dns.com", 443);
        let resolver = DnsResolver::new(&config).expect("Failed to init DoH resolver");

        // Resolve a site
        let ip = resolver
            .lookup("rust-lang.org")
            .await
            .expect("DoH resolution failed");
        assert!(ip.is_ipv4() || ip.is_ipv6());
    }

    #[tokio::test]
    async fn test_dns_over_tls_dot() {
        // Tests encrypted DoT (Port 853) using Google's DNS-over-TLS
        let config = create_test_config(DnsType::Tls, "8.8.8.8", "dns.google", 853);
        let resolver = DnsResolver::new(&config).expect("Failed to init DoT resolver");

        // Resolve a site
        let ip = resolver
            .lookup("github.com")
            .await
            .expect("DoT resolution failed");
        assert!(ip.is_ipv4() || ip.is_ipv6());
    }
}
