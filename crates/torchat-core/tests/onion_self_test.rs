//! Onion Service Self-Connection Test
//!
//! Creates an onion service and attempts to connect to it via Tor.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use torchat_core::identity::generate_identity;
use torchat_core::tor::{OnionService, OnionServiceConfig, TorConnection, TorConnectionConfig};

#[tokio::test]
async fn test_onion_self_connection() {
    println!("\n=== ONION SELF-CONNECTION TEST ===\n");

    // Step 1: Create identity and onion service
    println!("[1/5] Creating identity...");
    let identity = generate_identity().expect("Failed to generate identity");
    println!("      Address: {}", identity.onion_address());

    println!("[2/5] Starting onion service...");
    let config = OnionServiceConfig {
        local_port: 19999,
        ..Default::default()
    };

    let service = timeout(Duration::from_secs(30), OnionService::start(identity.clone(), config))
        .await
        .expect("Timeout starting service")
        .expect("Failed to start onion service");

    println!("      Service started on port 19999, virtual port 443");
    println!("      Onion address: {}", service.onion_address());

    // Step 2: Wait for service to propagate
    println!("[3/5] Waiting 30s for onion service to propagate...");
    println!("      (This allows Tor to publish the descriptor)");

    for i in 1..=6 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        println!("      {}s elapsed...", i * 5);
    }

    // Step 3: Spawn a task to accept connections
    println!("[4/5] Starting connection acceptor...");
    let accept_handle = tokio::spawn({
        let onion_addr = service.onion_address().to_string();
        async move {
            println!("      Acceptor waiting for connection...");
            match timeout(Duration::from_secs(120), service.accept()).await {
                Ok(Ok(mut stream)) => {
                    println!("      Acceptor: Connection received!");

                    // Read the test message
                    let mut buf = [0u8; 100];
                    match stream.read(&mut buf).await {
                        Ok(n) => {
                            let msg = String::from_utf8_lossy(&buf[..n]);
                            println!("      Acceptor received: {}", msg);

                            // Send response
                            stream.write_all(b"PONG").await.ok();
                            return Ok(format!("Received: {}", msg));
                        }
                        Err(e) => return Err(format!("Read error: {}", e)),
                    }
                }
                Ok(Err(e)) => Err(format!("Accept error: {}", e)),
                Err(_) => Err("Accept timed out after 120s".to_string()),
            }
        }
    });

    // Step 4: Try to connect to our own onion service
    println!("[5/5] Attempting to connect via Tor SOCKS5...");
    let tor_config = TorConnectionConfig::default();

    let connect_result = timeout(
        Duration::from_secs(120),
        TorConnection::connect(&tor_config, identity.onion_address())
    ).await;

    match connect_result {
        Ok(Ok(mut conn)) => {
            println!("      Connected to self via Tor!");

            // Send test message
            conn.send(b"PING").await.expect("Failed to send");
            println!("      Sent: PING");

            // Read response
            let mut buf = [0u8; 100];
            match conn.recv(&mut buf).await {
                Ok(n) => {
                    let response = String::from_utf8_lossy(&buf[..n]);
                    println!("      Received: {}", response);
                }
                Err(e) => println!("      Recv error: {}", e),
            }

            println!("\n=== SUCCESS: Self-connection via Tor works! ===\n");
        }
        Ok(Err(e)) => {
            println!("      FAILED: Connection error: {}", e);
            println!("\n=== FAILURE: Cannot connect to self via Tor ===\n");
            println!("      Possible causes:");
            println!("      1. Onion service descriptor not yet published");
            println!("      2. Tor network congestion");
            println!("      3. Firewall blocking Tor traffic");
        }
        Err(_) => {
            println!("      FAILED: Connection timed out after 120s");
            println!("\n=== FAILURE: Connection timed out ===\n");
        }
    }

    // Wait for acceptor to finish
    match accept_handle.await {
        Ok(Ok(msg)) => println!("Acceptor result: {}", msg),
        Ok(Err(e)) => println!("Acceptor error: {}", e),
        Err(e) => println!("Acceptor task panic: {}", e),
    }
}

/// Quick test of direct local connection (no Tor)
#[tokio::test]
async fn test_local_tcp_connection() {
    println!("\n=== LOCAL TCP TEST ===\n");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:19998")
        .await
        .expect("Failed to bind");

    println!("Listener bound to 127.0.0.1:19998");

    // Spawn acceptor
    let accept_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("Accept failed");
        stream.write_all(b"HELLO").await.expect("Write failed");
        "Accepted and sent HELLO"
    });

    // Connect
    let mut stream = tokio::net::TcpStream::connect("127.0.0.1:19998")
        .await
        .expect("Connect failed");

    let mut buf = [0u8; 10];
    let n = stream.read(&mut buf).await.expect("Read failed");

    println!("Received: {}", String::from_utf8_lossy(&buf[..n]));

    accept_handle.await.expect("Acceptor panic");

    println!("\n=== LOCAL TCP WORKS ===\n");
}
