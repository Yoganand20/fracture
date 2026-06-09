use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::dns::resolver::DnsResolver;
use crate::proxy::http::handle_http;
use crate::proxy::https::handle_https;
use crate::AppConfig;

/// This acts as the main router. It reads the HTTP/CONNECT headers
/// and delegates the connection to either the HTTP or HTTPS handler.
pub async fn handle_connection(
    mut client_stream: TcpStream,
    config: Arc<AppConfig>,
    dns: Arc<DnsResolver>,
) -> std::io::Result<()> {
    let peer_addr = client_stream.peer_addr().ok();

    let mut buffer = Vec::new();
    let mut temp_buf = [0u8; 1024];

    // Loop until we find the end of the HTTP/CONNECT headers (\r\n\r\n)
    loop {
        let n = client_stream.read(&mut temp_buf).await?;
        if n == 0 {
            if buffer.is_empty() {
                return Ok(()); // Connection closed immediately cleanly
            } else {
                tracing::warn!(peer = ?peer_addr, "Connection closed prematurely before finishing HTTP headers");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Connection closed before complete headers received",
                ));
            }
        }

        buffer.extend_from_slice(&temp_buf[..n]);

        // Check if we reached the end of the headers
        if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }

        if buffer.len() > 8192 {
            tracing::error!(peer = ?peer_addr, buffer_len = buffer.len(), "Rejected inbound stream: HTTP headers exceeded 8KB safety limit");
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Header too large",
            ));
        }
    }

    let (is_connect, target) = {
        let request_str = String::from_utf8_lossy(&buffer);
        let is_connect = request_str.starts_with("CONNECT ");
        let target = request_str
            .lines()
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(1)
            .unwrap_or("unknown")
            .to_string(); // Allocating a small String breaks the borrow-chain to `buffer`
        (is_connect, target)
    };

    // Route based on the first word of the request
    if is_connect {
        tracing::info!(peer = ?peer_addr, target = %target, "Routing HTTPS CONNECT tunnel");

        // `buffer` can now be moved cleanly because all borrows on it have completely expired!
        if let Err(e) = handle_https(client_stream, buffer, config, dns).await {
            tracing::error!(peer = ?peer_addr, target = %target, error = %e, "HTTPS tunnel pipeline processing failed");
            return Err(e);
        }
        Ok(())
    } else if config.https_only {
        tracing::warn!(peer = ?peer_addr, "Blocked insecure plain HTTP request under strict https_only configuration policy");
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "Insecure HTTP blocked",
        ))
    } else {
        tracing::info!(peer = ?peer_addr, target = %target, "Routing plain HTTP stream redirection");

        if let Err(e) = handle_http(client_stream, buffer, config, dns).await {
            tracing::error!(peer = ?peer_addr, target = %target, error = %e, "Plain HTTP processing failed");
            return Err(e);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::resolver::{DnsConfig, DnsResolver, DnsType};
    use crate::AppConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn create_test_config(https_only: bool, mtu: usize) -> Arc<AppConfig> {
        Arc::new(AppConfig {
            tls_record_fragmentation: false,
            fragmentation_size: mtu,
            https_only,
            dns: DnsConfig {
                dns_type: DnsType::Unencrypted,
                server_url: "".to_string(),
                ips: vec!["8.8.8.8".to_string()],
                port: 53,
                cache_size: 100,
            },
            ..Default::default()
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
        Arc::new(DnsResolver::new(&dns_config).expect("Failed to create DNS resolver"))
    }

    // ROUTER LOGIC TESTS

    #[tokio::test]
    async fn test_https_only_blocks_plain_http() {
        let config = create_test_config(true, 100);
        let dns = create_test_dns();

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (socket, _) = proxy.accept().await.unwrap();
            let result = handle_connection(socket, config, dns).await;

            assert!(result.is_err());
            assert_eq!(result.unwrap_err().to_string(), "Insecure HTTP blocked");
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();

        let mut buf = vec![0; 128];
        let bytes_read = client.read(&mut buf).await.unwrap();
        assert_eq!(bytes_read, 0);
    }

    // DPI BYPASS & FRAGMENTATION TESTS (The Core Engine)

    #[tokio::test]
    async fn test_https_connect_and_dpi_fragmentation() {
        let config = create_test_config(false, 5);
        let dns = create_test_dns();

        // Setup a Mock Upstream Server
        let upstream_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream_server.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut socket, _) = upstream_server.accept().await.unwrap();

            let mut buf = vec![0; 15];
            socket.read_exact(&mut buf).await.unwrap();

            let mut expected_tls = vec![22, 3, 3, 0, 10];
            expected_tls.extend_from_slice(b"1234567890");
            assert_eq!(buf, expected_tls);

            socket
                .write_all(b"SERVER_ACK_ENCRYPTED_DATA")
                .await
                .unwrap();
        });

        // Setup the Proxy Server
        let proxy_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_server.local_addr().unwrap().port();

        let config_clone = config.clone();
        let dns_clone = dns.clone();
        tokio::spawn(async move {
            let (socket, _) = proxy_server.accept().await.unwrap();
            let result = handle_connection(socket, config_clone, dns_clone).await;

            assert!(
                result.is_ok(),
                "Proxy handler failed: {:?}",
                result.unwrap_err()
            );
        });

        // Setup the Mock Browser (Client)
        let mut browser = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();

        let connect_req = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            upstream_port
        );
        browser.write_all(connect_req.as_bytes()).await.unwrap();

        let mut buf = vec![0; 1024];
        let n = browser.read(&mut buf).await.unwrap();
        let response_str = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response_str.contains("200 Connection Established"),
            "Did not receive tunnel confirmation. Proxy sent: {}",
            response_str
        );

        let mut fake_tls_record = vec![22, 3, 3, 0, 10];
        fake_tls_record.extend_from_slice(b"1234567890");
        browser.write_all(&fake_tls_record).await.unwrap();

        let n = browser.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            b"SERVER_ACK_ENCRYPTED_DATA",
            "Bidirectional pipe failed"
        );
    }

    #[tokio::test]
    async fn test_router_forwards_plain_http() {
        let config = create_test_config(false, 100);
        let dns = create_test_dns();

        // Setup Mock Upstream Server
        let upstream_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream_server.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut socket, _) = upstream_server.accept().await.unwrap();
            let mut buf = vec![0; 1024];
            let n = socket.read(&mut buf).await.unwrap();

            let req_str = String::from_utf8_lossy(&buf[..n]);
            assert!(req_str.starts_with("GET / HTTP/1.1"));

            socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        });

        // Setup the Proxy Server
        let proxy_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_server.local_addr().unwrap().port();

        let config_clone = config.clone();
        let dns_clone = dns.clone();
        tokio::spawn(async move {
            let (socket, _) = proxy_server.accept().await.unwrap();
            let result = handle_connection(socket, config_clone, dns_clone).await;
            assert!(
                result.is_ok(),
                "Proxy handler failed: {:?}",
                result.unwrap_err()
            );
        });

        // Connect Mock Client and send an HTTP GET
        let mut browser = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();
        let get_req = format!(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            upstream_port
        );
        browser.write_all(get_req.as_bytes()).await.unwrap();

        // Verify we get the HTTP response back from the upstream server
        let mut buf = vec![0; 1024];
        let n = browser.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"HTTP/1.1 200 OK\r\n\r\n");
    }

    #[tokio::test]
    async fn test_immediate_client_disconnect() {
        let config = create_test_config(false, 100);
        let dns = create_test_dns();

        let proxy_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_server.local_addr().unwrap().port();

        let proxy_task = tokio::spawn(async move {
            let (socket, _) = proxy_server.accept().await.unwrap();
            let result = handle_connection(socket, config, dns).await;

            assert!(result.is_ok());
        });

        let browser = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();
        drop(browser);

        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), proxy_task)
            .await
            .expect("Proxy task hung instead of exiting gracefully on disconnect!");
    }
}
