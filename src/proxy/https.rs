use rand;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn}; // Required for DPI bypass jitter generation

use crate::dns::resolver::DnsResolver;
use crate::proxy::buffer::{blind_chunk_buffer, fragment_tls_record};
use crate::AppConfig;

/// Handles encrypted HTTPS traffic via the HTTP CONNECT method with predictive read loops.
pub async fn handle_https(
    mut client_stream: TcpStream,
    initial_data: Vec<u8>,
    config: Arc<AppConfig>,
    dns: Arc<DnsResolver>,
) -> std::io::Result<()> {
    let client_addr = client_stream.peer_addr().ok();
    let mut buffer = initial_data;

    // 1. Dynamic Buffering Loop: Ensure the entire HTTP CONNECT message block (\r\n\r\n) is fully captured
    loop {
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buffer.len() > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Inbound HTTP CONNECT target payload breached header line safety margins",
            ));
        }

        let mut take_buf = [0u8; 512];
        match timeout(Duration::from_secs(5), client_stream.read(&mut take_buf)).await {
            Ok(Ok(0)) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Early client EOF during proxy tunnel allocation request",
                ))
            }
            Ok(Ok(n)) => buffer.extend_from_slice(&take_buf[..n]),
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                warn!(peer = ?client_addr, "Inbound HTTP CONNECT protocol stream stalled (5s limit)");
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "CONNECT sequence buffer timeout",
                ));
            }
        }
    }

    // Extract the host and port from the assembled "CONNECT host:port HTTP/1.1" payload block
    let (host, port) = match parse_connect_target(&buffer) {
        Ok(target) => target,
        Err(e) => {
            warn!(peer = ?client_addr, "Malformed HTTP CONNECT protocol sequence received");
            return Err(e);
        }
    };

    // 2. Resolve DNS using our injected resolver
    debug!(peer = ?client_addr, host = %host, "Resolving HTTPS target hostname via secured resolver channel");
    let ip = match dns.lookup(&host).await {
        Ok(resolved_ip) => resolved_ip,
        Err(e) => {
            error!(peer = ?client_addr, host = %host, error = %e, "DNS lookup failure while evaluating proxy route target");
            return Err(e);
        }
    };

    // 3. Connect to the upstream server
    info!(peer = ?client_addr, target = %format!("{}:{}", host, port), upstream_ip = %ip, "Establishing TCP handshake loop with remote upstream endpoint");
    let mut server_stream = TcpStream::connect((ip, port)).await?;

    // Disable Nagle's Algorithm to force segments to send immediately
    server_stream.set_nodelay(true)?;
    client_stream.set_nodelay(true)?;

    // 4. Tell the local browser that the tunnel is established
    debug!(peer = ?client_addr, target = %host, "Returning 200 Tunnel Connection Established handshake back to local origin");
    client_stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // 5. Wait for the browser to send the TLS ClientHello header (5 bytes)
    let mut header = [0u8; 5];
    if timeout(
        Duration::from_secs(5),
        client_stream.read_exact(&mut header),
    )
    .await
    .is_err()
    {
        warn!(peer = ?client_addr, target = %host, "Inbound TLS client header streaming halted: session timed out (5s limit)");
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "ClientHello header read timeout",
        ));
    }

    // The 4th and 5th bytes contain the payload length (Big-Endian format)
    let payload_len = ((header[3] as usize) << 8) | (header[4] as usize);

    if payload_len > 16384 {
        error!(peer = ?client_addr, target = %host, invalid_payload_len = payload_len, "Inbound validation aborted: payload size breaches max permitted TLS frame metrics");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS record payload exceeded maximum allowed size",
        ));
    }

    debug!(peer = ?client_addr, target = %host, payload_bytes_expected = payload_len, "Awaiting downstream application TLS ClientHello data payload bytes");
    let mut payload = vec![0u8; payload_len];
    if timeout(
        Duration::from_secs(5),
        client_stream.read_exact(&mut payload),
    )
    .await
    .is_err()
    {
        warn!(peer = ?client_addr, target = %host, "Inbound ClientHello frame transmission suspended mid-stream (timeout)");
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "ClientHello payload read timeout",
        ));
    }

    // Combine the header and payload back into a single, complete TLS record
    let mut client_hello_buf = header.to_vec();
    client_hello_buf.extend_from_slice(&payload);

    // Fragment the ClientHello using the injected config
    let chunks = if config.tls_record_fragmentation {
        debug!(peer = ?client_addr, target = %host, "Applying cryptographically strict TLS record segmentation strategy");
        fragment_tls_record(&client_hello_buf, config.fragmentation_size)
    } else {
        debug!(peer = ?client_addr, target = %host, "Applying blind slicing buffer division methodology");
        blind_chunk_buffer(&client_hello_buf, config.fragmentation_size)
    };

    // Send the tiny fragments to the server one by one to bypass DPI
    debug!(peer = ?client_addr, target = %host, chunks_count = chunks.len(), segment_size = config.fragmentation_size, "Streaming split TLS signature segments to cross bypass DPI tracking layers");

    // CRITICAL DPI BYPASS: Flush after every single write and introduce random micro-jitter delays.
    for chunk in chunks {
        server_stream.write_all(&chunk[..]).await?;
        server_stream.flush().await?;

        let jitter = Duration::from_millis(rand::random_range(2..=8));
        tokio::time::sleep(jitter).await;
    }

    // Pipe the rest of the connection back and forth blindly with a lifetime guard
    debug!(peer = ?client_addr, target = %host, "DPI bypass injection cycle completed; entering transparent full-duplex tunnel mode");

    let relay_lifetime_guard = timeout(
        Duration::from_secs(1800), // Enforce a defensive 30-minute absolute session limit per connection
        tokio::io::copy_bidirectional(&mut client_stream, &mut server_stream),
    )
    .await;

    match relay_lifetime_guard {
        Ok(Ok((to_server, to_client))) => {
            info!(peer = ?client_addr, target = %host, bytes_sent = to_server, bytes_received = to_client, "HTTPS secured tunnel closed gracefully");
        }
        Ok(Err(e)) => {
            debug!(peer = ?client_addr, target = %host, error = %e, "HTTPS tunnel runtime disconnected or socket dropped context");
        }
        Err(_) => {
            warn!(peer = ?client_addr, target = %host, "HTTPS tunnel automatically torn down due to lifetime fallback limit (30 min)");
        }
    }

    Ok(())
}

fn parse_connect_target(initial_data: &[u8]) -> io::Result<(String, u16)> {
    let request_str = std::str::from_utf8(initial_data).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "CONNECT request is not valid UTF-8",
        )
    })?;

    let first_line = request_str
        .lines()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Empty CONNECT request"))?;

    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "CONNECT request is missing target host:port",
        )
    })?;

    if method != "CONNECT" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected CONNECT method",
        ));
    }

    let (host, port) = if let Some((host, port_str)) = target.split_once(':') {
        (host.trim().to_owned(), port_str.parse().unwrap_or(443))
    } else {
        (target.trim().to_owned(), 443)
    };

    if host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CONNECT target host is empty",
        ));
    }

    Ok((host, port))
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
        Arc::new(DnsResolver::new(&dns_config).unwrap())
    }

    #[tokio::test]
    async fn test_https_successful_connection_and_pipe() {
        let config = create_test_config(10, false);
        let dns = create_test_dns();

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();

            let mut buf = vec![0; 15];
            socket.read_exact(&mut buf).await.unwrap();

            socket.write_all(b"UPSTREAM_SERVER_RESPONSE").await.unwrap();
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

        tokio::spawn(async move {
            let result = handle_https(proxy_socket, initial_data, config, dns).await;
            assert!(result.is_ok());
        });

        let mut buf = vec![0; 1024];

        let n = client_mock.read(&mut buf).await.unwrap();
        assert!(
            String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200 Connection Established")
        );

        let mut fake_tls_record = vec![22, 3, 3, 0, 10];
        fake_tls_record.extend_from_slice(b"1234567890");

        client_mock.write_all(&fake_tls_record).await.unwrap();

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
                Ok(()) => {}
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
