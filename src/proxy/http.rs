use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::handler::ProxyContext;
use crate::proxy::buffer::buffer_to_chunks;

/// Handles standard, unencrypted HTTP traffic.
pub async fn handle_http(
    mut client_stream: TcpStream,
    initial_data: Vec<u8>,
    context: Arc<ProxyContext>,
) -> std::io::Result<()> {
    // 1. Parse the HTTP headers to find the destination Host
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    // We ignore the parse result here because even if it's incomplete,
    // we just need to scan the headers that DID arrive for the "Host" field.
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

    // 2. Resolve the IP using our Encrypted DNS (Bypassing ISP blocklists)
    let ip = context.dns.lookup(&host).await?;

    // 3. Connect to the destination HTTP server
    let mut server_stream = TcpStream::connect((ip, port)).await?;

    // Enable TCP_NODELAY to ensure our fragmented packets send immediately
    server_stream.set_nodelay(true)?;
    client_stream.set_nodelay(true)?;

    // 4. THE GREEN TUNNEL MAGIC: Fragment the HTTP Request
    // DPI systems actively look for the "Host: blocked-website.com" string in plaintext HTTP.
    // By chopping the request into tiny chunks, the DPI cannot match the string!
    let chunks = buffer_to_chunks(&initial_data, context.client_hello_mtu);

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
    use tokio::net::TcpListener;

    fn create_local_context() -> Arc<ProxyContext> {
        let config = DnsConfig {
            dns_type: DnsType::Unencrypted,
            server_url: "".to_string(),
            ip: "8.8.8.8".to_string(),
            port: 53,
            cache_size: 100,
        };
        let dns = DnsResolver::new(&config).unwrap();

        Arc::new(ProxyContext {
            dns,
            https_only: false,
            client_hello_mtu: 5,
            tls_record_fragmentation: false,
        })
    }

    #[tokio::test]
    async fn test_http_parsing_and_fragmentation() {
        let context = create_local_context();

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

        // 4. Run `handle_http`
        tokio::spawn(async move {
            let result = handle_http(proxy_socket, raw_http_request, context).await;
            assert!(result.is_ok());
        });

        // 5. Verify the client gets the server's response
        let mut buf = vec![0; 1024];
        let n = client_mock.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"HTTP/1.1 200 OK\r\n\r\nBODY");
    }
}
