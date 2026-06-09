use rand;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn}; // Required for DPI bypass jitter generation

use crate::dns::resolver::DnsResolver;
use crate::proxy::buffer::blind_chunk_buffer;
use crate::AppConfig;

/// Handles standard, unencrypted HTTP traffic.
pub async fn handle_http(
    mut client_stream: TcpStream,
    initial_data: Vec<u8>,
    config: Arc<AppConfig>,
    dns: Arc<DnsResolver>,
) -> std::io::Result<()> {
    let client_addr = client_stream.peer_addr().ok();
    debug!(peer = ?client_addr, bytes_received = initial_data.len(), "Processing inbound plain HTTP request");

    let mut buffer = initial_data;

    // 1. Dynamic Buffering Loop: Continuously read streaming packet slices until HTTP headers are complete.
    // We bind the extracted host and port directly from the loop break.
    let (host, port) = loop {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        match req.parse(&buffer) {
            Ok(httparse::Status::Complete(_)) => {
                // Parse the host while the immutable borrow is active,
                // and break out of the loop with the owned data.
                match parse_host_header(req.headers) {
                    Ok(target) => break target,
                    Err(e) => {
                        warn!(peer = ?client_addr, error = %e, "Could not extract fallback target host from headers");
                        return Err(e);
                    }
                }
            }
            Ok(httparse::Status::Partial) => {
                // Security Guard: Cap header limits to prevent high-RAM DoS attacks
                if buffer.len() > 8192 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HTTP header metrics breached maximum allowed ceiling (8KB limit)",
                    ));
                }

                let mut take_buf = [0u8; 1024];
                match timeout(Duration::from_secs(5), client_stream.read(&mut take_buf)).await {
                    Ok(Ok(0)) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Early client EOF during HTTP header acquisition",
                        ))
                    }
                    Ok(Ok(n)) => {
                        // The immutable borrow from `req.parse` has ended its lifetime
                        // for this iteration, making it perfectly safe to mutate `buffer` here.
                        buffer.extend_from_slice(&take_buf[..n]);
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        warn!(peer = ?client_addr, "Inbound HTTP header streaming halted: session timed out (5s limit)");
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "HTTP header read timeout",
                        ));
                    }
                }
            }
            Err(err) => {
                error!(peer = ?client_addr, error = %err, "Failed to parse HTTP request stream via httparse");
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to parse HTTP request: {}", err),
                ));
            }
        }
    };

    // 2. Resolve the IP using our injected Encrypted DNS
    debug!(peer = ?client_addr, host = %host, "Resolving HTTP destination address");
    let ip = match dns.lookup(&host).await {
        Ok(resolved_ip) => resolved_ip,
        Err(e) => {
            error!(peer = ?client_addr, host = %host, error = %e, "DNS resolution failed for HTTP destination");
            return Err(e);
        }
    };

    // 3. Connect to the destination HTTP server
    info!(peer = ?client_addr, target = %format!("{}:{}", host, port), upstream_ip = %ip, "Connecting to upstream HTTP server");
    let mut server_stream = TcpStream::connect((ip, port)).await?;

    // Enable TCP_NODELAY to ensure our fragmented packets send immediately
    server_stream.set_nodelay(true)?;
    client_stream.set_nodelay(true)?;

    // 4. Fragment the accumulated HTTP Request buffer using the config's MTU
    let chunks = blind_chunk_buffer(&buffer, config.fragmentation_size);
    debug!(peer = ?client_addr, target = %host, chunks_count = chunks.len(), chunk_size = config.fragmentation_size, "Splitting initial HTTP request into fragments to bypass DPI");

    // CRITICAL DPI BYPASS: Flush after every single write and introduce random micro-jitter delays.
    for chunk in chunks {
        server_stream.write_all(&chunk).await?;
        server_stream.flush().await?;

        let jitter = Duration::from_millis(rand::random_range(2..=8));
        tokio::time::sleep(jitter).await;
    }

    // 5. Pipe the rest of the connection back and forth with a fallback session duration safety net
    debug!(peer = ?client_addr, target = %host, "Initial payloads dispatched; bridging cleartext bidirectional streams");

    let relay_lifetime_guard = timeout(
        Duration::from_secs(1800), // Enforce a defensive 30-minute absolute session limit per connection
        tokio::io::copy_bidirectional(&mut client_stream, &mut server_stream),
    )
    .await;

    match relay_lifetime_guard {
        Ok(Ok((to_server, to_client))) => {
            info!(peer = ?client_addr, target = %host, bytes_sent = to_server, bytes_received = to_client, "HTTP connection closed cleanly");
        }
        Ok(Err(e)) => {
            debug!(peer = ?client_addr, target = %host, error = %e, "HTTP relay tunnel disconnected or forced reset");
        }
        Err(_) => {
            warn!(peer = ?client_addr, target = %host, "HTTP relay tunnel automatically torn down due to lifetime fallback limit (30 min)");
        }
    }

    Ok(())
}
fn parse_host_header(headers: &[httparse::Header<'_>]) -> io::Result<(String, u16)> {
    for header in headers.iter() {
        if header.name.eq_ignore_ascii_case("host") {
            let host_str = std::str::from_utf8(header.value).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Host header contains invalid UTF-8",
                )
            })?;

            let (host, port) = if let Some((h, p)) = host_str.split_once(':') {
                (h.trim().to_owned(), p.parse().unwrap_or(80))
            } else {
                (host_str.trim().to_owned(), 80)
            };

            return Ok((host, port));
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "No Host header found in HTTP request",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::resolver::{DnsConfig, DnsResolver, DnsType};
    use crate::AppConfig;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn create_test_config() -> Arc<AppConfig> {
        Arc::new(AppConfig {
            tls_record_fragmentation: false,
            fragmentation_size: 5,
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
    async fn test_http_parsing_and_fragmentation() {
        let config = create_test_config();
        let dns = create_test_dns();

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let mut buf = vec![0; 1024];
            let mut total_read = 0;

            loop {
                let n = socket.read(&mut buf[total_read..]).await.unwrap();
                if n == 0 {
                    break;
                }
                total_read += n;
                if String::from_utf8_lossy(&buf[..total_read]).contains("\r\n\r\n") {
                    break;
                }
            }

            let request_str = String::from_utf8_lossy(&buf[..total_read]);
            assert!(request_str.contains("GET / HTTP/1.1"));
            assert!(request_str.contains(&format!("Host: 127.0.0.1:{}", upstream_port)));

            socket
                .write_all(b"HTTP/1.1 200 OK\r\n\r\nBODY")
                .await
                .unwrap();
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();

        let mut client_mock = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();
        let (proxy_socket, _) = proxy_listener.accept().await.unwrap();

        let raw_http_request = format!(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUser-Agent: curl/7.68.0\r\n\r\n",
            upstream_port
        )
        .into_bytes();

        tokio::spawn(async move {
            let result = handle_http(proxy_socket, raw_http_request, config, dns).await;
            assert!(result.is_ok());
        });

        let mut buf = vec![0; 1024];
        let n = client_mock.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"HTTP/1.1 200 OK\r\n\r\nBODY");
    }

    #[tokio::test]
    async fn test_http_missing_host_header() {
        let config = create_test_config();
        let dns = create_test_dns();

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let _client_mock = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();
        let (proxy_socket, _) = proxy_listener.accept().await.unwrap();

        let raw_http_request = b"GET / HTTP/1.1\r\nUser-Agent: curl\r\n\r\n".to_vec();

        let result = handle_http(proxy_socket, raw_http_request, config, dns).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("No Host header found"));
    }

    #[test]
    fn test_http_missing_port_fallback() {
        let mut headers = [httparse::EMPTY_HEADER; 1];
        headers[0].name = "Host";
        headers[0].value = b"127.0.0.1";

        let result = parse_host_header(&headers);

        assert!(result.is_ok(), "Parser failed to process valid Host header");
        let (host, port) = result.unwrap();

        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 80, "Did not fallback to the default HTTP port 80");
    }

    #[tokio::test]
    async fn test_http_incomplete_headers() {
        let config = create_test_config();
        let dns = create_test_dns();

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let _client_mock = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();
        let (proxy_socket, _) = proxy_listener.accept().await.unwrap();

        let raw_http_request = b"GET / HTTP/1.1\r\nMalformedHeaderLineNoColon\r\n\r\n".to_vec();

        let result = handle_http(proxy_socket, raw_http_request, config, dns).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }
}
