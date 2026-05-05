use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

// Assuming you have a shared state holding your DNS Resolver and Config
use crate::dns::resolver::DnsResolver;
use crate::proxy::http::handle_http;
use crate::proxy::https::handle_https;

pub struct ProxyContext {
    pub dns: DnsResolver,
    pub https_only: bool,
    pub client_hello_mtu: usize,
    pub tls_record_fragmentation: bool,
}

/// Equivalent to `handleRequest` in `request.js`
pub async fn handle_client_connection(
    mut client_stream: TcpStream,
    context: Arc<ProxyContext>,
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
        handle_https(client_stream, buffer, context).await
    } else if context.https_only {
        // Block insecure HTTP if configured
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "Insecure HTTP blocked",
        ))
    } else {
        // It's a plain HTTP request (We will implement handle_http next!)
        // handle_http(client_stream, buffer, context).await
        handle_http(client_stream, buffer, context).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::resolver::{DnsConfig, DnsResolver, DnsType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Helper function to generate a valid ProxyContext for testing
    fn create_test_context(https_only: bool, mtu: usize) -> Arc<ProxyContext> {
        let config = DnsConfig {
            dns_type: DnsType::Unencrypted,
            server_url: "".to_string(),
            ip: "8.8.8.8".to_string(),
            port: 53,
            cache_size: 100,
        };
        let dns = DnsResolver::new(&config).expect("Failed to create DNS resolver");

        Arc::new(ProxyContext {
            dns,
            https_only,
            client_hello_mtu: mtu,
            tls_record_fragmentation: false,
        })
    }

    // =====================================================================
    // 1. ROUTER LOGIC TESTS
    // =====================================================================

    #[tokio::test]
    async fn test_https_only_blocks_plain_http() {
        let context = create_test_context(true, 100); // https_only = true

        // 1. Setup a dummy proxy listener on a random local port
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        // 2. Spawn the proxy handler in the background
        tokio::spawn(async move {
            let (socket, _) = proxy.accept().await.unwrap();
            let result = handle_client_connection(socket, context).await;

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
        let context = create_test_context(false, 5);

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

        let ctx_clone = context.clone();
        tokio::spawn(async move {
            let (socket, _) = proxy_server.accept().await.unwrap();
            // This will trigger `handle_https` internally
            let _ = handle_client_connection(socket, ctx_clone).await;
        });

        // 3. Setup the Mock Browser (Client)
        let mut browser = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();

        // Step A: Send the CONNECT request
        // Because our DnsResolver immediately parses raw IPs, we pass the raw IP of our local upstream server
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
            "Did not receive tunnel confirmation"
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
}
