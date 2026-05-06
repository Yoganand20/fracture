use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proxy::buffer::blind_chunk_buffer;
use crate::proxy::fragment_tls_record; // From Phase 1

use crate::dns::resolver::DnsResolver;
use crate::AppConfig;

/// Handles encrypted HTTPS traffic via the HTTP CONNECT method.
/// Dependencies are explicitly injected.
pub async fn handle_https(
    mut client_stream: TcpStream,
    initial_data: Vec<u8>,
    config: Arc<AppConfig>,
    dns: Arc<DnsResolver>,
) -> std::io::Result<()> {
    // 1. Extract the host and port from the "CONNECT host:port HTTP/1.1" string
    let request_str = String::from_utf8_lossy(&initial_data);
    let first_line = request_str.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();

    parts.next(); // Skip "CONNECT"
    let target = parts.next().unwrap_or(""); // "example.com:443"

    let (host, port_str) = target.split_once(':').unwrap_or((target, "443"));
    let port: u16 = port_str.parse().unwrap_or(443);

    // 2. Resolve DNS using our injected resolver
    let ip = dns.lookup(host).await?;

    // 3. Connect to the upstream server
    let mut server_stream = TcpStream::connect((ip, port)).await?;

    // CRITICAL: Disable Nagle's Algorithm to force fragments to send immediately
    server_stream.set_nodelay(true)?;
    client_stream.set_nodelay(true)?;

    // 4. Tell the local browser that the tunnel is established
    client_stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // 5. Wait for the browser to send the TLS ClientHello packet
    let mut client_hello_buf = vec![0; 8192];
    let n = client_stream.read(&mut client_hello_buf).await?;
    client_hello_buf.truncate(n);

    // 6. THE GREEN TUNNEL MAGIC: Fragment the ClientHello using the injected config
    let chunks = if config.tls_record_fragmentation {
        fragment_tls_record(&client_hello_buf, config.fragmentation_size)
    } else {
        blind_chunk_buffer(&client_hello_buf, config.fragmentation_size)
    };

    // Send the tiny fragments to the server one by one to bypass DPI
    for chunk in chunks {
        server_stream.write_all(&chunk).await?;
    }

    // 7. Pipe the rest of the connection back and forth blindly
    tokio::io::copy_bidirectional(&mut client_stream, &mut server_stream).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::resolver::{DnsConfig, DnsResolver, DnsType};
    use crate::AppConfig;
    use tokio::net::TcpListener;

    // Helper to generate a dummy AppConfig for testing
    fn create_test_config(mtu: usize, strict_fragmentation: bool) -> Arc<AppConfig> {
        Arc::new(AppConfig {
            tls_record_fragmentation: strict_fragmentation,
            fragmentation_size: mtu,
            https_only: false,
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
        Arc::new(DnsResolver::new(&dns_config).unwrap())
    }

    #[tokio::test]
    async fn test_https_successful_connection_and_pipe() {
        let config = create_test_config(10, false);
        let dns = create_test_dns();

        // 1. Start a mock "Upstream Server" (e.g., simulating YouTube's server)
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();

        // Spawn upstream server logic
        tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let mut buf = vec![0; 1024];

            // Read the initial ClientHello that the proxy forwards
            let n = socket.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"MOCK_CLIENT_HELLO_DATA");

            // Reply back to the proxy
            socket.write_all(b"UPSTREAM_SERVER_RESPONSE").await.unwrap();
        });

        // 2. Start a temporary local listener so our mock client can connect via TCP
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();

        // 3. Connect our mock client (browser) to the proxy listener
        let mut client_mock = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();

        // Accept the incoming connection so we have a real TcpStream to pass to the handler
        let (proxy_socket, _) = proxy_listener.accept().await.unwrap();

        // 4. Formulate the CONNECT header (pointing to our mock upstream server)
        let initial_data = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            upstream_port
        )
        .into_bytes();

        // 5. Run `handle_https` in the background with explicitly injected config and dns
        tokio::spawn(async move {
            let result = handle_https(proxy_socket, initial_data, config, dns).await;
            assert!(result.is_ok());
        });

        // 6. Client behavior validation
        let mut buf = vec![0; 1024];

        // Wait for Proxy to reply with "200 Connection Established"
        let n = client_mock.read(&mut buf).await.unwrap();
        assert!(
            String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200 Connection Established")
        );

        // Send the mock ClientHello (which the proxy will fragment and forward to upstream)
        client_mock
            .write_all(b"MOCK_CLIENT_HELLO_DATA")
            .await
            .unwrap();

        // Read the response that the upstream server sent back through the bidirectional pipe
        let n = client_mock.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"UPSTREAM_SERVER_RESPONSE");
    }

    #[tokio::test]
    async fn test_https_malformed_connect_string() {
        let config = create_test_config(100, false);
        let dns = create_test_dns();

        // Create a real TCP pair for testing the failure case
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let _client_mock = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();
        let (proxy_socket, _) = proxy_listener.accept().await.unwrap();

        // Pass a completely garbage string instead of a valid CONNECT target
        let initial_data = b"CONNECT INVALID_TARGET_NO_PORT HTTP/1.1\r\n\r\n".to_vec();

        // Because "INVALID_TARGET_NO_PORT" cannot be resolved by DNS or connected to,
        // handle_https should gracefully fail and return an IO error, NOT panic.
        let result = handle_https(proxy_socket, initial_data, config, dns).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_https_client_drops_before_client_hello() {
        let config = create_test_config(10, false);
        let dns = create_test_dns();

        // 1. Setup a mock upstream server (it will accept the connection but receive no data)
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = upstream.accept().await.unwrap();
        });

        // 2. Setup the proxy listener
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();

        // 3. Connect client
        let mut client_mock = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();
        let (proxy_socket, _) = proxy_listener.accept().await.unwrap();

        // 4. Send a valid CONNECT request
        let initial_data = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            upstream_port
        )
        .into_bytes();

        // 5. Spawn the handler in a task so we can monitor its exit status
        let proxy_task = tokio::spawn(async move {
            let result = handle_https(proxy_socket, initial_data, config, dns).await;

            // It should exit gracefully with Ok(()) or an expected IO Error, not a panic.
            assert!(
                result.is_ok()
                    || result.unwrap_err().kind() == std::io::ErrorKind::ConnectionAborted
            );
        });

        // 6. Wait for proxy to send "200 Connection Established"
        let mut buf = vec![0; 1024];
        let n = client_mock.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("200 Connection Established"));

        // 7. CRITICAL ACTION: Client maliciously drops the TCP connection without sending ClientHello!
        drop(client_mock);

        // 8. Ensure the proxy handler finishes successfully and doesn't hang forever or crash
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), proxy_task)
            .await
            .expect("Proxy task hung waiting for ClientHello instead of exiting!");
    }
}
