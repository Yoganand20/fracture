use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proxy::buffer::{blind_chunk_buffer, fragment_tls_record};

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
    let mut header = [0u8; 5];
    client_stream.read_exact(&mut header).await?;

    // The 4th and 5th bytes contain the payload length (Big-Endian format)
    let payload_len = ((header[3] as usize) << 8) | (header[4] as usize);

    // Security Check: Prevent a malicious client from causing a massive RAM allocation
    // A standard TLS record cannot exceed 16KB (16384 bytes).
    if payload_len > 16384 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS record payload exceeded maximum allowed size",
        ));
    }

    // Now that we know the exact size, wait until the complete payload arrives
    let mut payload = vec![0u8; payload_len];
    client_stream.read_exact(&mut payload).await?;

    // Combine the header and payload back into a single, complete TLS record
    let mut client_hello_buf = header.to_vec();
    client_hello_buf.extend_from_slice(&payload);

    // 6. THE GREEN TUNNEL MAGIC: Fragment the ClientHello using the injected config
    let chunks = if config.tls_record_fragmentation {
        fragment_tls_record(&client_hello_buf, config.fragmentation_size)
    } else {
        blind_chunk_buffer(&client_hello_buf, config.fragmentation_size)
    };

    // Send the tiny fragments to the server one by one to bypass DPI
    for chunk in chunks {
        server_stream.write_all(&chunk[..]).await?;
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

    fn create_test_config(mtu: usize, strict_fragmentation: bool) -> Arc<AppConfig> {
        Arc::new(AppConfig {
            tls_record_fragmentation: strict_fragmentation,
            fragmentation_size: mtu,
            https_only: false,
            dns: DnsConfig {
                dns_type: DnsType::Unencrypted,
                server_url: "".to_string(),
                ips: vec!["8.8.8.8".to_string()],
                port: 53,
                cache_size: 100,
            },
        })
    }

    fn create_test_dns() -> Arc<DnsResolver> {
        let dns_config = DnsConfig {
            dns_type: DnsType::Unencrypted,
            server_url: "".to_string(),
            ips: vec!["8.8.8.8".to_string()],
            port: 53,
            cache_size: 100,
        };
        Arc::new(DnsResolver::new(&dns_config).unwrap())
    }

    #[tokio::test]
    async fn test_https_successful_connection_and_pipe() {
        let config = create_test_config(10, false);
        let dns = create_test_dns();

        // 1. Start a mock "Upstream Server"
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let mut buf = vec![0; 1024];

            // Wait for the fragmented TLS ClientHello to arrive
            let n = socket.read(&mut buf).await.unwrap();

            // Assert we received data successfully (since it's fragmented, we just ensure > 0)
            assert!(n > 0);

            // Reply back to the proxy
            socket.write_all(b"UPSTREAM_SERVER_RESPONSE").await.unwrap();
        });

        // 2. Start proxy listener
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();

        // 3. Connect mock client
        let mut client_mock = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();
        let (proxy_socket, _) = proxy_listener.accept().await.unwrap();

        // 4. Formulate CONNECT header
        let initial_data = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            upstream_port
        )
        .into_bytes();

        tokio::spawn(async move {
            let result = handle_https(proxy_socket, initial_data, config, dns).await;
            assert!(result.is_ok());
        });

        let mut buf = vec![0; 1024];

        // Wait for Proxy to reply with "200 Connection Established"
        let n = client_mock.read(&mut buf).await.unwrap();
        assert!(
            String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200 Connection Established")
        );

        // Construct a valid fake TLS Handshake record (22 = Handshake, 3,3 = TLS 1.2, 0,10 = Length)
        let mut fake_tls_record = vec![22, 3, 3, 0, 10];
        fake_tls_record.extend_from_slice(b"1234567890"); // Exactly 10 bytes payload

        client_mock.write_all(&fake_tls_record).await.unwrap();

        // Read upstream response
        let n = client_mock.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"UPSTREAM_SERVER_RESPONSE");
    }

    #[tokio::test]
    async fn test_https_malformed_connect_string() {
        let config = create_test_config(100, false);
        let dns = create_test_dns();

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let _client_mock = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();
        let (proxy_socket, _) = proxy_listener.accept().await.unwrap();

        let initial_data = b"CONNECT INVALID_TARGET_NO_PORT HTTP/1.1\r\n\r\n".to_vec();
        let result = handle_https(proxy_socket, initial_data, config, dns).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_https_client_drops_before_client_hello() {
        let config = create_test_config(10, false);
        let dns = create_test_dns();

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = upstream.accept().await.unwrap();
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();

        let mut client_mock = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();
        let (proxy_socket, _) = proxy_listener.accept().await.unwrap();

        let initial_data = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            upstream_port
        )
        .into_bytes();

        let proxy_task = tokio::spawn(async move {
            let result = handle_https(proxy_socket, initial_data, config, dns).await;
            match result {
                Ok(()) => {} // Success is acceptable
                Err(e) => {
                    let kind = e.kind();
                    assert!(
                        kind == std::io::ErrorKind::ConnectionAborted
                            || kind == std::io::ErrorKind::UnexpectedEof,
                        "Proxy task failed with an unexpected error: {:?}",
                        e
                    );
                }
            }
        });

        let mut buf = vec![0; 1024];
        let n = client_mock.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("200 Connection Established"));

        drop(client_mock);

        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), proxy_task)
            .await
            .expect("Proxy task hung waiting for ClientHello instead of exiting!");
    }
}
