//! P2P Messaging Diagnostic Tests
//!
//! Tests the complete message flow to identify failure points.

use std::time::Duration;
use tokio::time::timeout;

use torchat_core::identity::generate_identity;
use torchat_core::messaging::MessagingDaemon;
use torchat_core::storage::{Database, DatabaseConfig, derive_db_key};
use torchat_core::tor::{OnionServiceConfig, TorConnection, TorConnectionConfig};

/// Test 1: Can we generate identities?
#[test]
fn test_identity_generation_works() {
    let alice = generate_identity().expect("Failed to generate Alice's identity");
    let bob = generate_identity().expect("Failed to generate Bob's identity");

    assert_ne!(alice.onion_address().to_string(), bob.onion_address().to_string());
    println!("Alice's onion: {}", alice.onion_address());
    println!("Bob's onion: {}", bob.onion_address());
}

/// Test 2: Can we connect to Tor SOCKS5 proxy?
#[tokio::test]
async fn test_tor_socks5_connection() {
    use tokio::net::TcpStream;

    let result = TcpStream::connect("127.0.0.1:9050").await;
    assert!(result.is_ok(), "Cannot connect to Tor SOCKS5 proxy at 127.0.0.1:9050");
    println!("SOCKS5 proxy connection: OK");
}

/// Test 3: Can we connect to Tor control port?
#[tokio::test]
async fn test_tor_control_port() {
    use tokio::net::TcpStream;

    let result = TcpStream::connect("127.0.0.1:9051").await;
    assert!(result.is_ok(), "Cannot connect to Tor control port at 127.0.0.1:9051");
    println!("Control port connection: OK");
}

/// Test 4: Can we create an onion service?
#[tokio::test]
async fn test_onion_service_creation() {
    use torchat_core::tor::OnionService;

    let identity = generate_identity().expect("Failed to generate identity");
    let config = OnionServiceConfig {
        local_port: 19876,
        ..Default::default()
    };

    let result = timeout(
        Duration::from_secs(30),
        OnionService::start(identity.clone(), config)
    ).await;

    match result {
        Ok(Ok(service)) => {
            println!("OnionService created successfully!");
            println!("Address: {}", service.onion_address());
            let _ = service.stop().await;
        }
        Ok(Err(e)) => {
            panic!("OnionService creation failed: {}", e);
        }
        Err(_) => {
            panic!("OnionService creation timed out after 30s");
        }
    }
}

/// Test 5: Can we create the messaging daemon?
#[tokio::test]
async fn test_daemon_creation() {
    let identity = generate_identity().expect("Failed to generate identity");

    let db_config = DatabaseConfig {
        path: "/tmp/torchat_test_daemon.db".to_string(),
        in_memory: false,
    };
    let key = derive_db_key(b"test-key", b"test-salt");
    let database = Database::open(&db_config, &key[..]).expect("Failed to open database");
    let database = std::sync::Arc::new(tokio::sync::Mutex::new(database));

    let daemon = MessagingDaemon::new(identity, database, 1);
    println!("Daemon created, onion: {}", daemon.onion_address());

    // Cleanup
    let _ = std::fs::remove_file("/tmp/torchat_test_daemon.db");
}

/// Test 6: Can we start the daemon and listen for connections?
#[tokio::test]
async fn test_daemon_start() {
    let identity = generate_identity().expect("Failed to generate identity");

    let db_config = DatabaseConfig {
        path: "/tmp/torchat_test_daemon_start.db".to_string(),
        in_memory: false,
    };
    let key = derive_db_key(b"test-key-start", b"test-salt");
    let database = Database::open(&db_config, &key[..]).expect("Failed to open database");
    let database = std::sync::Arc::new(tokio::sync::Mutex::new(database));

    let daemon = std::sync::Arc::new(MessagingDaemon::new(identity.clone(), database, 1));

    let config = OnionServiceConfig {
        local_port: 19877,
        ..Default::default()
    };

    let result = timeout(
        Duration::from_secs(30),
        daemon.start(config)
    ).await;

    match result {
        Ok(Ok(())) => {
            println!("Daemon started successfully!");
            println!("Listening on: {}", identity.onion_address());
        }
        Ok(Err(e)) => {
            panic!("Daemon start failed: {}", e);
        }
        Err(_) => {
            panic!("Daemon start timed out after 30s");
        }
    }

    // Cleanup
    let _ = std::fs::remove_file("/tmp/torchat_test_daemon_start.db");
}

/// Test 7: Full P2P test - Alice sends to Bob
#[tokio::test]
async fn test_full_p2p_message_flow() {
    println!("\n=== FULL P2P MESSAGE FLOW TEST ===\n");

    // Create Alice
    println!("[1/8] Creating Alice's identity...");
    let alice_identity = generate_identity().expect("Failed to generate Alice's identity");
    println!("      Alice's onion: {}", alice_identity.onion_address());

    // Create Bob
    println!("[2/8] Creating Bob's identity...");
    let bob_identity = generate_identity().expect("Failed to generate Bob's identity");
    println!("      Bob's onion: {}", bob_identity.onion_address());

    // Create databases
    println!("[3/8] Creating databases...");
    let alice_db_config = DatabaseConfig {
        path: "/tmp/torchat_alice_p2p.db".to_string(),
        in_memory: false,
    };
    let bob_db_config = DatabaseConfig {
        path: "/tmp/torchat_bob_p2p.db".to_string(),
        in_memory: false,
    };

    let alice_key = derive_db_key(b"alice-key", b"alice-salt");
    let bob_key = derive_db_key(b"bob-key", b"bob-salt");

    let alice_db = Database::open(&alice_db_config, &alice_key[..]).expect("Failed to open Alice's DB");
    let bob_db = Database::open(&bob_db_config, &bob_key[..]).expect("Failed to open Bob's DB");
    let alice_db = std::sync::Arc::new(tokio::sync::Mutex::new(alice_db));
    let bob_db = std::sync::Arc::new(tokio::sync::Mutex::new(bob_db));
    println!("      Databases created");

    // Create daemons
    println!("[4/8] Creating messaging daemons...");
    let alice_daemon = std::sync::Arc::new(MessagingDaemon::new(alice_identity.clone(), alice_db, 1));
    let bob_daemon = std::sync::Arc::new(MessagingDaemon::new(bob_identity.clone(), bob_db, 2));
    println!("      Daemons created");

    // Subscribe to events
    let mut alice_events = alice_daemon.subscribe();
    let mut bob_events = bob_daemon.subscribe();

    // Start Bob's daemon (receiver)
    println!("[5/8] Starting Bob's daemon (receiver)...");
    let bob_config = OnionServiceConfig {
        local_port: 19880,
        ..Default::default()
    };

    let bob_start = timeout(Duration::from_secs(30), bob_daemon.start(bob_config)).await;
    match bob_start {
        Ok(Ok(())) => println!("      Bob's daemon started!"),
        Ok(Err(e)) => {
            println!("      ERROR: Bob's daemon failed to start: {}", e);
            cleanup_test_files();
            panic!("Bob's daemon failed to start");
        }
        Err(_) => {
            println!("      ERROR: Bob's daemon start timed out");
            cleanup_test_files();
            panic!("Bob's daemon start timed out");
        }
    }

    // Wait for Bob's Started event
    let bob_started = timeout(Duration::from_secs(5), bob_events.recv()).await;
    match bob_started {
        Ok(Ok(event)) => println!("      Bob's event: {:?}", event),
        _ => println!("      Warning: Didn't receive Bob's started event"),
    }

    // Start Alice's daemon (sender)
    println!("[6/8] Starting Alice's daemon (sender)...");
    let alice_config = OnionServiceConfig {
        local_port: 19881,
        ..Default::default()
    };

    let alice_start = timeout(Duration::from_secs(30), alice_daemon.start(alice_config)).await;
    match alice_start {
        Ok(Ok(())) => println!("      Alice's daemon started!"),
        Ok(Err(e)) => {
            println!("      ERROR: Alice's daemon failed to start: {}", e);
            cleanup_test_files();
            panic!("Alice's daemon failed to start");
        }
        Err(_) => {
            println!("      ERROR: Alice's daemon start timed out");
            cleanup_test_files();
            panic!("Alice's daemon start timed out");
        }
    }

    // Give onion services time to propagate (CRITICAL!)
    println!("      Waiting 60s for onion services to propagate...");
    println!("      (Tor needs time to publish descriptors to HSDir nodes)");
    for i in 1..=12 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        println!("      {}s elapsed...", i * 5);
    }

    // Alice sends a message to Bob
    println!("[7/8] Alice sending message to Bob...");
    let bob_address = bob_identity.onion_address().to_string();
    let message_content = "Hello Bob! This is a test message.";
    let message_id: [u8; 16] = rand::random();

    let cmd_tx = alice_daemon.command_sender();
    let send_result = cmd_tx.try_send(torchat_core::messaging::DaemonCommand::SendMessage {
        to: bob_address.clone(),
        content: message_content.to_string(),
        message_id,
    });

    match send_result {
        Ok(()) => println!("      Message queued for sending"),
        Err(e) => {
            println!("      ERROR: Failed to queue message: {}", e);
            cleanup_test_files();
            panic!("Failed to queue message");
        }
    }

    // Wait for delivery confirmation or failure
    println!("[8/8] Waiting for delivery events (180s timeout)...");

    let event_result = timeout(Duration::from_secs(180), async {
        loop {
            tokio::select! {
                alice_event = alice_events.recv() => {
                    match alice_event {
                        Ok(event) => {
                            println!("      Alice event: {:?}", event);
                            match event {
                                torchat_core::messaging::DaemonEvent::MessageDelivered { .. } => {
                                    return Ok("Message delivered!");
                                }
                                torchat_core::messaging::DaemonEvent::MessageFailed { error, .. } => {
                                    return Err(format!("Message failed: {}", error));
                                }
                                _ => {}
                            }
                        }
                        Err(e) => println!("      Alice event error: {}", e),
                    }
                }
                bob_event = bob_events.recv() => {
                    match bob_event {
                        Ok(event) => {
                            println!("      Bob event: {:?}", event);
                            match event {
                                torchat_core::messaging::DaemonEvent::MessageReceived { content, .. } => {
                                    println!("      SUCCESS! Bob received: {}", content);
                                }
                                _ => {}
                            }
                        }
                        Err(e) => println!("      Bob event error: {}", e),
                    }
                }
            }
        }
    }).await;

    match event_result {
        Ok(Ok(msg)) => println!("\n=== TEST PASSED: {} ===\n", msg),
        Ok(Err(e)) => {
            println!("\n=== TEST FAILED: {} ===\n", e);
            cleanup_test_files();
            panic!("P2P message delivery failed: {}", e);
        }
        Err(_) => {
            println!("\n=== TEST FAILED: Timed out waiting for message delivery ===\n");
            cleanup_test_files();
            panic!("P2P message delivery timed out");
        }
    }

    cleanup_test_files();
}

fn cleanup_test_files() {
    let _ = std::fs::remove_file("/tmp/torchat_test_daemon.db");
    let _ = std::fs::remove_file("/tmp/torchat_test_daemon_start.db");
    let _ = std::fs::remove_file("/tmp/torchat_alice_p2p.db");
    let _ = std::fs::remove_file("/tmp/torchat_bob_p2p.db");
}

/// Test 8: Direct Tor connection test - can Alice reach Bob's onion?
#[tokio::test]
async fn test_direct_tor_connection() {
    use torchat_core::tor::OnionService;

    println!("\n=== DIRECT TOR CONNECTION TEST ===\n");

    // Create Bob and start his onion service
    println!("[1/4] Creating Bob's onion service...");
    let bob_identity = generate_identity().expect("Failed to generate Bob's identity");
    let bob_config = OnionServiceConfig {
        local_port: 19890,
        ..Default::default()
    };

    let bob_service = timeout(
        Duration::from_secs(30),
        OnionService::start(bob_identity.clone(), bob_config)
    ).await.expect("Timeout").expect("Failed to start Bob's onion service");

    println!("      Bob's onion: {}", bob_service.onion_address());

    // Wait for propagation
    println!("[2/4] Waiting 10s for onion service propagation...");
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Try to connect to Bob via Tor
    println!("[3/4] Attempting to connect to Bob via Tor SOCKS5...");
    let tor_config = TorConnectionConfig::default();

    let connect_result = timeout(
        Duration::from_secs(60),
        TorConnection::connect(&tor_config, bob_service.onion_address())
    ).await;

    match connect_result {
        Ok(Ok(conn)) => {
            println!("      SUCCESS! Connected to Bob's onion service");
            drop(conn);
        }
        Ok(Err(e)) => {
            println!("      FAILED: Connection error: {}", e);
        }
        Err(_) => {
            println!("      FAILED: Connection timed out after 60s");
        }
    }

    println!("[4/4] Cleanup...");
    let _ = bob_service.stop().await;
    println!("      Done\n");
}
