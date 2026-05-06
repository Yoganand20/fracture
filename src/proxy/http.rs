use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

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
    // 1. Parse the HTTP headers to find the destination Host
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    let _ = req.parse(&initial_data);

    let mut host = String::new();
    let mut port: u16 = 80;

    for header in req.headers.iter() {
        if header.name.eq_ignore_ascii_case("host") {
            let host_str = String::from_utf8_lossy(header.value);
            if let Some((h, p)) = host_str.split_once(':') {
                host = h.to_string();
                port = p.parse().unwrap_or(80);
            } else {
                host = host_str.to_string();
            }
            break;
        }
    }

    if host.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "No Host header found in HTTP request",
        ));
    }

    // 2. Resolve the IP using our injected Encrypted DNS
    let ip = dns.lookup(&host).await?;

    // 3. Connect to the destination HTTP server
    let mut server_stream = TcpStream::connect((ip, port)).await?;

    // Enable TCP_NODELAY to ensure our fragmented packets send immediately
    server_stream.set_nodelay(true)?;
    client_stream.set_nodelay(true)?;

    // 4. Fragment the HTTP Request using the config's MTU
    let chunks = blind_chunk_buffer(&initial_data, config.fragmentation_size);

    for chunk in chunks {
        server_stream.write_all(&chunk).await?;
    }

    // 5. Pipe the rest of the connection back and forth
    tokio::io::copy_bidirectional(&mut client_stream, &mut server_stream).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::resolver::{DnsConfig, DnsResolver, DnsType};
    use crate::AppConfig;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    // Helper to generate a dummy AppConfig for testing
    fn create_test_config() -> Arc<AppConfig> {
        Arc::new(AppConfig {
            tls_record_fragmentation: false,
            fragmentation_size: 5, // Tiny MTU to ensure chunking happens
            https_only: false,     // Must be false for HTTP to work
            dns: DnsConfig {
                dns_type: DnsType::Unencrypted,
                server_url: "".to_string(),
                ips: vec!["8.8.8.8".to_string()],
                port: 53,
                cache_size: 100,
            },
        })
    }

    // Helper to generate a dummy DNS resolver
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

        // 1. Setup mock upstream HTTP server
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let mut buf = vec![0; 1024];
            let n = socket.read(&mut buf).await.unwrap();

            // Verify the upstream server successfully received the reassembled HTTP request
            let request_str = String::from_utf8_lossy(&buf[..n]);
            assert!(request_str.contains("GET / HTTP/1.1"));
            assert!(request_str.contains(&format!("Host: 127.0.0.1:{}", upstream_port)));

            socket
                .write_all(b"HTTP/1.1 200 OK\r\n\r\nBODY")
                .await
                .unwrap();
        });

        // 2. Setup a local proxy handler socket
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();

        let mut client_mock = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();
        let (proxy_socket, _) = proxy_listener.accept().await.unwrap();

        // 3. Create a raw HTTP GET request pointing to our local upstream server
        let raw_http_request = format!(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUser-Agent: curl/7.68.0\r\n\r\n",
            upstream_port
        )
        .into_bytes();

        // 4. Run `handle_http` with purely injected parameters
        tokio::spawn(async move {
            let result = handle_http(proxy_socket, raw_http_request, config, dns).await;
            assert!(result.is_ok());
        });

        // 5. Verify the client gets the server's response
        let mut buf = vec![0; 1024];
        let n = client_mock.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"HTTP/1.1 200 OK\r\n\r\nBODY");
    }

    #[tokio::test]
    async fn test_http_missing_host_header() {
        // 1. Standard config
        let config = create_test_config();
        let dns = create_test_dns();

        // 2. Setup dummy socket
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let _client_mock = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();
        let (proxy_socket, _) = proxy_listener.accept().await.unwrap();

        // 3. Create a malformed HTTP request (MISSING the Host header)
        let raw_http_request = b"GET / HTTP/1.1\r\nUser-Agent: curl\r\n\r\n".to_vec();

        // 4. Run `handle_http` and expect an InvalidData error
        let result = handle_http(proxy_socket, raw_http_request, config, dns).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("No Host header found"));
    }

    #[tokio::test]
    async fn test_http_missing_port_fallback() {
        let config = create_test_config();
        let dns = create_test_dns();

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let _client_mock = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();
        let (proxy_socket, _) = proxy_listener.accept().await.unwrap();

        // No port specified in Host header. Should default to port 80.
        let raw_http_request = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_vec();

        let result = handle_http(proxy_socket, raw_http_request, config, dns).await;

        // We expect it to try connecting to 127.0.0.1:80 and fail cleanly
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::ConnectionRefused,
            "Did not attempt to connect to the default port 80"
        );
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

        // Incomplete HTTP request (Missing the double \r\n at the end, and half a host header)
        let raw_http_request = b"GET / HTTP/1.1\r\nHo".to_vec();

        let result = handle_http(proxy_socket, raw_http_request, config, dns).await;

        // httparse will return Status::Partial, so headers will be empty, leading to a dropped connection.
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }
}
