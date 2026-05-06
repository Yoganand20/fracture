use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::AppConfig;
// Assuming you have a shared state holding your DNS Resolver and Config
use crate::dns::resolver::DnsResolver;
use crate::proxy::http::handle_http;
use crate::proxy::https::handle_https;

/// This acts as the main router. It reads the first few bytes of a connection
/// and delegates it to either the HTTP or HTTPS handler.
pub async fn handle_connection(
    mut client_stream: TcpStream,
    config: Arc<AppConfig>,
    dns: Arc<DnsResolver>,
) -> std::io::Result<()> {
    let mut buffer = vec![0; 4096]; // Read the first 4KB to inspect the request

    let bytes_read = match client_stream.read(&mut buffer).await {
        Ok(0) => return Ok(()), // Connection closed immediately
        Ok(n) => n,
        Err(e) => return Err(e),
    };

    buffer.truncate(bytes_read);
    let request_str = String::from_utf8_lossy(&buffer);

    // Route based on the first word of the request
    if request_str.starts_with("CONNECT ") {
        // It's an HTTPS request
        handle_https(client_stream, buffer, config, dns).await
    } else if config.https_only {
        // Block insecure HTTP if configured
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "Insecure HTTP blocked",
        ))
    } else {
        // It's a plain HTTP request
        handle_http(client_stream, buffer, config, dns).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::resolver::{DnsConfig, DnsResolver, DnsType};
    use crate::AppConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Helper to generate a dummy AppConfig for testing
    fn create_test_config(https_only: bool, mtu: usize) -> Arc<AppConfig> {
        Arc::new(AppConfig {
            tls_record_fragmentation: false,
            fragmentation_size: mtu,
            https_only,
        })
    }

    // Helper to generate a dummy DNS resolver
    fn create_test_dns() -> Arc<DnsResolver> {
        let dns_config = DnsConfig {
            dns_type: DnsType::Unencrypted,
            server_url: "".to_string(),
            ip: "8.8.8.8".to_string(),
            port: 53,
            cache_size: 100,
        };
        Arc::new(DnsResolver::new(&dns_config).expect("Failed to create DNS resolver"))
    }

    // =====================================================================
    // 1. ROUTER LOGIC TESTS
    // =====================================================================

    #[tokio::test]
    async fn test_https_only_blocks_plain_http() {
        let config = create_test_config(true, 100); // https_only = true
        let dns = create_test_dns();

        // 1. Setup a dummy proxy listener on a random local port
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        // 2. Spawn the proxy handler in the background
        tokio::spawn(async move {
            let (socket, _) = proxy.accept().await.unwrap();
            let result = handle_connection(socket, config, dns).await;

            // We EXPECT this to fail and return an error
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().to_string(), "Insecure HTTP blocked");
        });

        // 3. Connect a mock client and send a plain HTTP GET request
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();

        // 4. Verify the proxy slams the connection shut (reads 0 bytes)
        let mut buf = vec![0; 128];
        let bytes_read = client.read(&mut buf).await.unwrap();
        assert_eq!(bytes_read, 0, "Proxy did not drop the insecure connection");
    }

    // =====================================================================
    // 2. DPI BYPASS & FRAGMENTATION TESTS (The Core Engine)
    // =====================================================================

    #[tokio::test]
    async fn test_https_connect_and_dpi_fragmentation() {
        // We will force a tiny MTU of 5 bytes to guarantee our mock ClientHello gets heavily fragmented
        let config = create_test_config(false, 5);
        let dns = create_test_dns();

        // 1. Setup a Mock Upstream Server (Acting as the blocked website, e.g., YouTube)
        let upstream_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream_server.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut socket, _) = upstream_server.accept().await.unwrap();
            let mut buf = vec![0; 1024];

            // Wait for the ClientHello fragments to arrive and be reassembled by the OS
            let n = socket.read(&mut buf).await.unwrap();

            // Verify the payload arrived perfectly intact despite fragmentation!
            assert_eq!(&buf[..n], b"HELLO_TLS_WORLD_12345");

            // Reply back to the client
            socket
                .write_all(b"SERVER_ACK_ENCRYPTED_DATA")
                .await
                .unwrap();
        });

        // 2. Setup the Proxy Server
        let proxy_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_server.local_addr().unwrap().port();

        let config_clone = config.clone();
        let dns_clone = dns.clone();
        tokio::spawn(async move {
            let (socket, _) = proxy_server.accept().await.unwrap();
            // This will trigger `handle_https` internally
            let result = handle_connection(socket, config_clone, dns_clone).await;

            // CRITICAL: We assert ok here so if the proxy fails, the test tells us why!
            assert!(
                result.is_ok(),
                "Proxy handler failed: {:?}",
                result.unwrap_err()
            );
        });

        // 3. Setup the Mock Browser (Client)
        let mut browser = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();

        // Step A: Send the CONNECT request
        let connect_req = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            upstream_port
        );
        browser.write_all(connect_req.as_bytes()).await.unwrap();

        // Step B: Expect "200 Connection Established" from the Proxy
        let mut buf = vec![0; 1024];
        let n = browser.read(&mut buf).await.unwrap();
        let response_str = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response_str.contains("200 Connection Established"),
            "Did not receive tunnel confirmation. Proxy sent: {}",
            response_str
        );

        // Step C: Send the fake TLS ClientHello
        browser.write_all(b"HELLO_TLS_WORLD_12345").await.unwrap();

        // Step D: Ensure the bidirectional pipe works by receiving the server's response
        let n = browser.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            b"SERVER_ACK_ENCRYPTED_DATA",
            "Bidirectional pipe failed"
        );
    }

    #[tokio::test]
    async fn test_router_forwards_plain_http() {
        let config = create_test_config(false, 100); // https_only = false
        let dns = create_test_dns();

        // 1. Setup Mock Upstream Server
        let upstream_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream_server.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut socket, _) = upstream_server.accept().await.unwrap();
            let mut buf = vec![0; 1024];
            let n = socket.read(&mut buf).await.unwrap();

            // Verify the upstream server got the raw HTTP request
            let req_str = String::from_utf8_lossy(&buf[..n]);
            assert!(req_str.starts_with("GET / HTTP/1.1"));

            // Reply back
            socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        });

        // 2. Setup the Proxy Server
        let proxy_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_server.local_addr().unwrap().port();

        let config_clone = config.clone();
        let dns_clone = dns.clone();
        tokio::spawn(async move {
            let (socket, _) = proxy_server.accept().await.unwrap();
            // This should route to `handle_http`
            let result = handle_connection(socket, config_clone, dns_clone).await;
            assert!(
                result.is_ok(),
                "Proxy handler failed: {:?}",
                result.unwrap_err()
            );
        });

        // 3. Connect Mock Client and send an HTTP GET
        let mut browser = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();
        let get_req = format!(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            upstream_port
        );
        browser.write_all(get_req.as_bytes()).await.unwrap();

        // 4. Verify we get the HTTP response back from the upstream server
        let mut buf = vec![0; 1024];
        let n = browser.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"HTTP/1.1 200 OK\r\n\r\n");
    }

    #[tokio::test]
    async fn test_immediate_client_disconnect() {
        let config = create_test_config(false, 100);
        let dns = create_test_dns();

        // 1. Setup the Proxy Server
        let proxy_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_server.local_addr().unwrap().port();

        // 2. Spawn the proxy handler
        let proxy_task = tokio::spawn(async move {
            let (socket, _) = proxy_server.accept().await.unwrap();
            let result = handle_connection(socket, config, dns).await;

            // We expect Ok(()) because it should gracefully exit, not Err()
            assert!(result.is_ok());
        });

        // 3. Connect a client, then immediately drop the connection
        let browser = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();
        drop(browser); // Force a TCP FIN/RST

        // 4. Wait for the proxy task to finish and ensure it didn't panic
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), proxy_task)
            .await
            .expect("Proxy task hung instead of exiting gracefully on disconnect!");
    }
}
