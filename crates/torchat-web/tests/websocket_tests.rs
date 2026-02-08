//! Comprehensive integration test suite for WebSocket real-time push notifications.
//!
//! Tests cover:
//! - WebSocket connection lifecycle (connect, authenticate, disconnect)
//! - Authentication rejection for invalid tokens
//! - Event delivery from daemon broadcast to WebSocket client
//! - daemon_event_to_ws_event conversion for all DaemonEvent variants
//! - WsEvent JSON serialization format
//! - Multiple concurrent WebSocket connections
//! - Daemon-not-running error handling
//! - Internal event filtering

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::{routing::get, Router};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::Mutex as TokioMutex;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use torchat_core::identity::generate_identity;
use torchat_core::messaging::{DaemonEvent, FileMetadata, FileTransferManager, MessagingDaemon};
use torchat_core::protocol::{AckType, CallSignalType, GroupInvitePayload};
use torchat_core::storage::{Database, DatabaseConfig};

use torchat_web::api;
use torchat_web::models::*;

// Unique token counter to avoid collisions across tests
static TOKEN_COUNTER: AtomicU64 = AtomicU64::new(1);

// ========================================
// Test Helpers
// ========================================

/// Create an in-memory database for testing.
fn test_db() -> Database {
    let config = DatabaseConfig {
        path: String::new(),
        in_memory: true,
    };
    let key = [0u8; 32];
    Database::open(&config, &key).expect("should open in-memory db")
}

/// Create a test AppState with an in-memory database.
fn test_app_state() -> Arc<AppState> {
    Arc::new(AppState {
        database: Arc::new(TokioMutex::new(test_db())),
        data_dir: "/tmp/torchat-test".to_string(),
        daemons: Arc::new(TokioMutex::new(HashMap::new())),
        file_manager: Arc::new(FileTransferManager::new()),
        received_files: Arc::new(TokioMutex::new(HashMap::new())),
        outgoing_transfers: Arc::new(TokioMutex::new(HashMap::new())),
    })
}

/// Create a minimal router with just the WebSocket route for testing.
fn test_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/ws", get(api::ws_handler))
        .with_state(state)
}

/// Register a test user and return (user_id, session_token).
async fn register_test_user(state: &AppState) -> (i64, String) {
    let identity = generate_identity().expect("generate identity");
    let n = TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let session_token = format!("test-token-{}", n);
    let db = state.database.lock().await;
    let user_id = db
        .create_user(&session_token, &identity, Some("TestUser"))
        .expect("create user");
    (user_id, session_token)
}

/// Insert a daemon for the given user and return its event sender.
async fn insert_daemon(state: &AppState, user_id: i64) -> tokio::sync::broadcast::Sender<DaemonEvent> {
    let identity = generate_identity().expect("generate identity");
    let daemon_db = Database::open(
        &DatabaseConfig {
            path: String::new(),
            in_memory: true,
        },
        &[0u8; 32],
    )
    .unwrap();
    let daemon = Arc::new(MessagingDaemon::new(
        identity,
        Arc::new(TokioMutex::new(daemon_db)),
        user_id,
    ));
    let event_tx = daemon.event_sender();
    {
        let mut daemons = state.daemons.lock().await;
        daemons.insert(user_id, daemon);
    }
    event_tx
}

/// Start a test server and return the address it's listening on.
async fn start_test_server(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind to random port");
    let addr = listener.local_addr().expect("get local addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    addr
}

/// Connect a WebSocket client to the test server.
async fn ws_connect(
    addr: SocketAddr,
    token: &str,
) -> (
    futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
    futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) {
    let url = format!("ws://{}/api/ws?token={}", addr, token);
    let (stream, _response) = connect_async(&url)
        .await
        .expect("WebSocket connect should succeed");
    stream.split()
}

/// Read the next text message from the WebSocket stream, parsed as JSON.
async fn read_ws_json(
    rx: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) -> serde_json::Value {
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), rx.next())
        .await
        .expect("should receive message within timeout")
        .expect("stream should not end")
        .expect("message should be ok");

    match msg {
        Message::Text(text) => serde_json::from_str(&text).expect("should be valid JSON"),
        other => panic!("Expected text message, got: {:?}", other),
    }
}

// ========================================
// Integration Tests: WebSocket Connection
// ========================================

#[tokio::test]
async fn test_ws_connect_with_valid_token_and_daemon() {
    let state = test_app_state();
    let (user_id, token) = register_test_user(&state).await;
    let _event_tx = insert_daemon(&state, user_id).await;

    let router = test_router(state.clone());
    let addr = start_test_server(router).await;

    let (_tx, mut rx) = ws_connect(addr, &token).await;

    // First message should be "connected"
    let msg = read_ws_json(&mut rx).await;
    assert_eq!(msg["type"], "connected");
    assert_eq!(msg["data"]["user_id"], user_id);
}

#[tokio::test]
async fn test_ws_reject_invalid_token() {
    let state = test_app_state();
    let router = test_router(state);
    let addr = start_test_server(router).await;

    let url = format!("ws://{}/api/ws?token=invalid-fake-token", addr);
    let result = connect_async(&url).await;

    // Should fail with a non-101 response (401 Unauthorized)
    assert!(result.is_err(), "WebSocket with invalid token should fail");
}

#[tokio::test]
async fn test_ws_reject_missing_token() {
    let state = test_app_state();
    let router = test_router(state);
    let addr = start_test_server(router).await;

    // No token query param at all
    let url = format!("ws://{}/api/ws", addr);
    let result = connect_async(&url).await;

    assert!(result.is_err(), "WebSocket without token should fail");
}

#[tokio::test]
async fn test_ws_daemon_not_running() {
    let state = test_app_state();
    let (_user_id, token) = register_test_user(&state).await;

    // Don't insert a daemon — simulates daemon not running
    let router = test_router(state);
    let addr = start_test_server(router).await;

    let url = format!("ws://{}/api/ws?token={}", addr, token);
    let (stream, _response) = connect_async(&url)
        .await
        .expect("WS handshake should succeed even when daemon is not running");

    let (_tx, mut rx) = stream.split();

    // Should receive "error" event about daemon not running
    let msg = read_ws_json(&mut rx).await;
    assert_eq!(msg["type"], "error");
    assert_eq!(msg["data"]["message"], "Daemon not running");
}

// ========================================
// Integration Tests: Event Delivery
// ========================================

#[tokio::test]
async fn test_ws_receives_message_received_event() {
    let state = test_app_state();
    let (user_id, token) = register_test_user(&state).await;
    let event_tx = insert_daemon(&state, user_id).await;

    let router = test_router(state.clone());
    let addr = start_test_server(router).await;
    let (_ws_tx, mut ws_rx) = ws_connect(addr, &token).await;

    let connected = read_ws_json(&mut ws_rx).await;
    assert_eq!(connected["type"], "connected");

    let msg_id = [1u8; 16];
    event_tx
        .send(DaemonEvent::MessageReceived {
            from: "abc123.onion".to_string(),
            message_id: msg_id,
            content: "Hello, World!".to_string(),
            timestamp: 1700000000,
        })
        .expect("send event");

    let event = read_ws_json(&mut ws_rx).await;
    assert_eq!(event["type"], "message_received");
    assert_eq!(event["data"]["from"], "abc123.onion");
    assert_eq!(event["data"]["content"], "Hello, World!");
    assert_eq!(event["data"]["timestamp"], 1700000000);
    assert_eq!(event["data"]["message_id"], hex::encode(msg_id));
}

#[tokio::test]
async fn test_ws_receives_group_message_event() {
    let state = test_app_state();
    let (user_id, token) = register_test_user(&state).await;
    let event_tx = insert_daemon(&state, user_id).await;

    let router = test_router(state.clone());
    let addr = start_test_server(router).await;
    let (_ws_tx, mut ws_rx) = ws_connect(addr, &token).await;

    let _ = read_ws_json(&mut ws_rx).await; // connected

    let group_id = [42u8; 32];
    let sender_id = [7u8; 16];
    event_tx
        .send(DaemonEvent::GroupMessageReceived {
            group_id,
            sender_id,
            content: "Group hello".to_string(),
            timestamp: 1700000001,
        })
        .expect("send event");

    let event = read_ws_json(&mut ws_rx).await;
    assert_eq!(event["type"], "group_message_received");
    assert_eq!(event["data"]["group_id"], hex::encode(group_id));
    assert_eq!(event["data"]["sender_id"], hex::encode(sender_id));
    assert_eq!(event["data"]["content"], "Group hello");
    assert_eq!(event["data"]["timestamp"], 1700000001);
}

#[tokio::test]
async fn test_ws_receives_message_delivered_event() {
    let state = test_app_state();
    let (user_id, token) = register_test_user(&state).await;
    let event_tx = insert_daemon(&state, user_id).await;

    let router = test_router(state.clone());
    let addr = start_test_server(router).await;
    let (_ws_tx, mut ws_rx) = ws_connect(addr, &token).await;

    let _ = read_ws_json(&mut ws_rx).await; // connected

    let msg_id = [99u8; 16];
    event_tx
        .send(DaemonEvent::MessageDelivered { message_id: msg_id })
        .expect("send event");

    let event = read_ws_json(&mut ws_rx).await;
    assert_eq!(event["type"], "message_delivered");
    assert_eq!(event["data"]["message_id"], hex::encode(msg_id));
}

#[tokio::test]
async fn test_ws_receives_message_failed_event() {
    let state = test_app_state();
    let (user_id, token) = register_test_user(&state).await;
    let event_tx = insert_daemon(&state, user_id).await;

    let router = test_router(state.clone());
    let addr = start_test_server(router).await;
    let (_ws_tx, mut ws_rx) = ws_connect(addr, &token).await;

    let _ = read_ws_json(&mut ws_rx).await; // connected

    let msg_id = [88u8; 16];
    event_tx
        .send(DaemonEvent::MessageFailed {
            message_id: msg_id,
            error: "Peer unreachable".to_string(),
        })
        .expect("send event");

    let event = read_ws_json(&mut ws_rx).await;
    assert_eq!(event["type"], "message_failed");
    assert_eq!(event["data"]["message_id"], hex::encode(msg_id));
    assert_eq!(event["data"]["error"], "Peer unreachable");
}

#[tokio::test]
async fn test_ws_receives_group_joined_event() {
    let state = test_app_state();
    let (user_id, token) = register_test_user(&state).await;
    let event_tx = insert_daemon(&state, user_id).await;

    let router = test_router(state.clone());
    let addr = start_test_server(router).await;
    let (_ws_tx, mut ws_rx) = ws_connect(addr, &token).await;

    let _ = read_ws_json(&mut ws_rx).await; // connected

    let group_id = [11u8; 32];
    event_tx
        .send(DaemonEvent::GroupJoined {
            group_id,
            name: "My Group".to_string(),
        })
        .expect("send event");

    let event = read_ws_json(&mut ws_rx).await;
    assert_eq!(event["type"], "group_joined");
    assert_eq!(event["data"]["group_id"], hex::encode(group_id));
    assert_eq!(event["data"]["name"], "My Group");
}

#[tokio::test]
async fn test_ws_receives_peer_events() {
    let state = test_app_state();
    let (user_id, token) = register_test_user(&state).await;
    let event_tx = insert_daemon(&state, user_id).await;

    let router = test_router(state.clone());
    let addr = start_test_server(router).await;
    let (_ws_tx, mut ws_rx) = ws_connect(addr, &token).await;

    let _ = read_ws_json(&mut ws_rx).await; // connected

    event_tx
        .send(DaemonEvent::PeerConnected {
            address: "peer1.onion".to_string(),
        })
        .expect("send");

    let event = read_ws_json(&mut ws_rx).await;
    assert_eq!(event["type"], "peer_connected");
    assert_eq!(event["data"]["address"], "peer1.onion");

    event_tx
        .send(DaemonEvent::PeerDisconnected {
            address: "peer1.onion".to_string(),
        })
        .expect("send");

    let event = read_ws_json(&mut ws_rx).await;
    assert_eq!(event["type"], "peer_disconnected");
    assert_eq!(event["data"]["address"], "peer1.onion");
}

#[tokio::test]
async fn test_ws_receives_file_transfer_events() {
    let state = test_app_state();
    let (user_id, token) = register_test_user(&state).await;
    let event_tx = insert_daemon(&state, user_id).await;

    let router = test_router(state.clone());
    let addr = start_test_server(router).await;
    let (_ws_tx, mut ws_rx) = ws_connect(addr, &token).await;

    let _ = read_ws_json(&mut ws_rx).await; // connected

    let transfer_id = [55u8; 16];

    event_tx
        .send(DaemonEvent::FileTransferCompleted {
            transfer_id,
            output_path: "/tmp/test.txt".to_string(),
            filename: "test.txt".to_string(),
            from: "sender.onion".to_string(),
            size: 12345,
        })
        .expect("send");

    let event = read_ws_json(&mut ws_rx).await;
    assert_eq!(event["type"], "file_received");
    assert_eq!(event["data"]["transfer_id"], hex::encode(transfer_id));
    assert_eq!(event["data"]["filename"], "test.txt");
    assert_eq!(event["data"]["from"], "sender.onion");
    assert_eq!(event["data"]["size"], 12345);

    let fail_id = [66u8; 16];
    event_tx
        .send(DaemonEvent::FileTransferFailed {
            transfer_id: fail_id,
            error: "Connection lost".to_string(),
        })
        .expect("send");

    let event = read_ws_json(&mut ws_rx).await;
    assert_eq!(event["type"], "file_transfer_failed");
    assert_eq!(event["data"]["transfer_id"], hex::encode(fail_id));
    assert_eq!(event["data"]["error"], "Connection lost");
}

#[tokio::test]
async fn test_ws_receives_group_file_events() {
    let state = test_app_state();
    let (user_id, token) = register_test_user(&state).await;
    let event_tx = insert_daemon(&state, user_id).await;

    let router = test_router(state.clone());
    let addr = start_test_server(router).await;
    let (_ws_tx, mut ws_rx) = ws_connect(addr, &token).await;

    let _ = read_ws_json(&mut ws_rx).await; // connected

    let group_id = [20u8; 32];

    event_tx
        .send(DaemonEvent::GroupFileShared {
            group_id,
            file_id: "file-abc".to_string(),
            filename: "document.pdf".to_string(),
            size: 99999,
            sender_onion: "sharer.onion".to_string(),
        })
        .expect("send");

    let event = read_ws_json(&mut ws_rx).await;
    assert_eq!(event["type"], "group_file_shared");
    assert_eq!(event["data"]["group_id"], hex::encode(group_id));
    assert_eq!(event["data"]["file_id"], "file-abc");
    assert_eq!(event["data"]["filename"], "document.pdf");
    assert_eq!(event["data"]["size"], 99999);

    event_tx
        .send(DaemonEvent::GroupFileDownloaded {
            group_id,
            file_id: "file-abc".to_string(),
            output_path: "/tmp/document.pdf".to_string(),
        })
        .expect("send");

    let event = read_ws_json(&mut ws_rx).await;
    assert_eq!(event["type"], "group_file_downloaded");
    assert_eq!(event["data"]["file_id"], "file-abc");

    event_tx
        .send(DaemonEvent::GroupFileDownloadFailed {
            group_id,
            file_id: "file-xyz".to_string(),
            error: "Peer offline".to_string(),
        })
        .expect("send");

    let event = read_ws_json(&mut ws_rx).await;
    assert_eq!(event["type"], "group_file_download_failed");
    assert_eq!(event["data"]["error"], "Peer offline");
}

#[tokio::test]
async fn test_ws_receives_daemon_lifecycle_events() {
    let state = test_app_state();
    let (user_id, token) = register_test_user(&state).await;
    let event_tx = insert_daemon(&state, user_id).await;

    let router = test_router(state.clone());
    let addr = start_test_server(router).await;
    let (_ws_tx, mut ws_rx) = ws_connect(addr, &token).await;

    let _ = read_ws_json(&mut ws_rx).await; // connected

    event_tx
        .send(DaemonEvent::Started {
            onion_address: "myaddr.onion".to_string(),
        })
        .expect("send");

    let event = read_ws_json(&mut ws_rx).await;
    assert_eq!(event["type"], "daemon_started");
    assert_eq!(event["data"]["onion_address"], "myaddr.onion");

    event_tx.send(DaemonEvent::Stopped).expect("send");

    let event = read_ws_json(&mut ws_rx).await;
    assert_eq!(event["type"], "daemon_stopped");
}

#[tokio::test]
async fn test_ws_receives_group_member_events() {
    let state = test_app_state();
    let (user_id, token) = register_test_user(&state).await;
    let event_tx = insert_daemon(&state, user_id).await;

    let router = test_router(state.clone());
    let addr = start_test_server(router).await;
    let (_ws_tx, mut ws_rx) = ws_connect(addr, &token).await;

    let _ = read_ws_json(&mut ws_rx).await; // connected

    let group_id = [30u8; 32];
    let member_id = [5u8; 16];

    event_tx
        .send(DaemonEvent::GroupMemberJoined { group_id, member_id })
        .expect("send");

    let event = read_ws_json(&mut ws_rx).await;
    assert_eq!(event["type"], "group_member_joined");
    assert_eq!(event["data"]["group_id"], hex::encode(group_id));
    assert_eq!(event["data"]["member_id"], hex::encode(member_id));

    event_tx
        .send(DaemonEvent::GroupMemberLeft { group_id, member_id })
        .expect("send");

    let event = read_ws_json(&mut ws_rx).await;
    assert_eq!(event["type"], "group_member_left");
    assert_eq!(event["data"]["group_id"], hex::encode(group_id));
    assert_eq!(event["data"]["member_id"], hex::encode(member_id));
}

#[tokio::test]
async fn test_ws_receives_group_created_event() {
    let state = test_app_state();
    let (user_id, token) = register_test_user(&state).await;
    let event_tx = insert_daemon(&state, user_id).await;

    let router = test_router(state.clone());
    let addr = start_test_server(router).await;
    let (_ws_tx, mut ws_rx) = ws_connect(addr, &token).await;

    let _ = read_ws_json(&mut ws_rx).await; // connected

    let group_id = [77u8; 32];
    event_tx
        .send(DaemonEvent::GroupCreated {
            group_id,
            name: "New Group".to_string(),
        })
        .expect("send");

    let event = read_ws_json(&mut ws_rx).await;
    assert_eq!(event["type"], "group_created");
    assert_eq!(event["data"]["group_id"], hex::encode(group_id));
    assert_eq!(event["data"]["name"], "New Group");
}

// ========================================
// Integration Tests: Multiple Connections
// ========================================

#[tokio::test]
async fn test_ws_multiple_clients_receive_same_events() {
    let state = test_app_state();
    let (user_id, token) = register_test_user(&state).await;
    let event_tx = insert_daemon(&state, user_id).await;

    let router = test_router(state.clone());
    let addr = start_test_server(router).await;

    // Connect two clients (simulating two browser tabs)
    let (_tx1, mut rx1) = ws_connect(addr, &token).await;
    let (_tx2, mut rx2) = ws_connect(addr, &token).await;

    let c1 = read_ws_json(&mut rx1).await;
    let c2 = read_ws_json(&mut rx2).await;
    assert_eq!(c1["type"], "connected");
    assert_eq!(c2["type"], "connected");

    // Send an event — both clients should receive it
    let msg_id = [44u8; 16];
    event_tx
        .send(DaemonEvent::MessageReceived {
            from: "someone.onion".to_string(),
            message_id: msg_id,
            content: "Broadcast test".to_string(),
            timestamp: 1700000099,
        })
        .expect("send");

    let e1 = read_ws_json(&mut rx1).await;
    let e2 = read_ws_json(&mut rx2).await;
    assert_eq!(e1["type"], "message_received");
    assert_eq!(e2["type"], "message_received");
    assert_eq!(e1["data"]["content"], "Broadcast test");
    assert_eq!(e2["data"]["content"], "Broadcast test");
}

// ========================================
// Integration Tests: Internal events filtered
// ========================================

#[tokio::test]
async fn test_ws_internal_events_not_forwarded() {
    let state = test_app_state();
    let (user_id, token) = register_test_user(&state).await;
    let event_tx = insert_daemon(&state, user_id).await;

    let router = test_router(state.clone());
    let addr = start_test_server(router).await;
    let (_ws_tx, mut ws_rx) = ws_connect(addr, &token).await;

    let _ = read_ws_json(&mut ws_rx).await; // connected

    // Send internal-only events that should be filtered out
    event_tx
        .send(DaemonEvent::AckReceived {
            message_id: [0u8; 16],
            ack_type: AckType::Delivered,
        })
        .expect("send");

    event_tx
        .send(DaemonEvent::Error {
            message: "internal error".to_string(),
        })
        .expect("send");

    event_tx
        .send(DaemonEvent::GroupKeyRotated {
            group_id: [0u8; 32],
            new_epoch: 5,
        })
        .expect("send");

    // Now send a visible event to verify we only get this one
    event_tx
        .send(DaemonEvent::PeerConnected {
            address: "visible.onion".to_string(),
        })
        .expect("send");

    // The next message should be peer_connected, not any of the internal events
    let event = read_ws_json(&mut ws_rx).await;
    assert_eq!(event["type"], "peer_connected");
    assert_eq!(event["data"]["address"], "visible.onion");
}

// ========================================
// Integration Tests: Client disconnect
// ========================================

#[tokio::test]
async fn test_ws_client_close_is_graceful() {
    let state = test_app_state();
    let (user_id, token) = register_test_user(&state).await;
    let _event_tx = insert_daemon(&state, user_id).await;

    let router = test_router(state.clone());
    let addr = start_test_server(router).await;
    let (mut ws_tx, mut ws_rx) = ws_connect(addr, &token).await;

    let _ = read_ws_json(&mut ws_rx).await; // connected

    // Client sends close frame
    ws_tx.send(Message::Close(None)).await.expect("send close");

    // Should not panic or hang — connection terminates
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

// ========================================
// Integration Tests: Rapid event sequence
// ========================================

#[tokio::test]
async fn test_ws_rapid_event_sequence() {
    let state = test_app_state();
    let (user_id, token) = register_test_user(&state).await;
    let event_tx = insert_daemon(&state, user_id).await;

    let router = test_router(state.clone());
    let addr = start_test_server(router).await;
    let (_ws_tx, mut ws_rx) = ws_connect(addr, &token).await;

    let _ = read_ws_json(&mut ws_rx).await; // connected

    // Send 20 events rapidly
    for i in 0u8..20 {
        event_tx
            .send(DaemonEvent::PeerConnected {
                address: format!("peer{}.onion", i),
            })
            .expect("send");
    }

    // All 20 should arrive
    for i in 0u8..20 {
        let event = read_ws_json(&mut ws_rx).await;
        assert_eq!(event["type"], "peer_connected");
        assert_eq!(event["data"]["address"], format!("peer{}.onion", i));
    }
}

// ========================================
// Unit Tests: daemon_event_to_ws_event
// ========================================

#[test]
fn test_event_conversion_message_received() {
    let event = DaemonEvent::MessageReceived {
        from: "test.onion".to_string(),
        message_id: [0xAB; 16],
        content: "test msg".to_string(),
        timestamp: 12345,
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "message_received");
    assert_eq!(ws_event.data["from"], "test.onion");
    assert_eq!(ws_event.data["content"], "test msg");
    assert_eq!(ws_event.data["timestamp"], 12345);
    assert_eq!(ws_event.data["message_id"], hex::encode([0xAB; 16]));
}

#[test]
fn test_event_conversion_message_delivered() {
    let event = DaemonEvent::MessageDelivered {
        message_id: [0xCD; 16],
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "message_delivered");
    assert_eq!(ws_event.data["message_id"], hex::encode([0xCD; 16]));
}

#[test]
fn test_event_conversion_message_failed() {
    let event = DaemonEvent::MessageFailed {
        message_id: [0xEF; 16],
        error: "timeout".to_string(),
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "message_failed");
    assert_eq!(ws_event.data["error"], "timeout");
}

#[test]
fn test_event_conversion_group_message_received() {
    let event = DaemonEvent::GroupMessageReceived {
        group_id: [1u8; 32],
        sender_id: [2u8; 16],
        content: "group msg".to_string(),
        timestamp: 99999,
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "group_message_received");
    assert_eq!(ws_event.data["group_id"], hex::encode([1u8; 32]));
    assert_eq!(ws_event.data["sender_id"], hex::encode([2u8; 16]));
    assert_eq!(ws_event.data["content"], "group msg");
}

#[test]
fn test_event_conversion_group_joined() {
    let event = DaemonEvent::GroupJoined {
        group_id: [3u8; 32],
        name: "TestGroup".to_string(),
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "group_joined");
    assert_eq!(ws_event.data["name"], "TestGroup");
}

#[test]
fn test_event_conversion_group_member_joined() {
    let event = DaemonEvent::GroupMemberJoined {
        group_id: [4u8; 32],
        member_id: [5u8; 16],
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "group_member_joined");
    assert_eq!(ws_event.data["member_id"], hex::encode([5u8; 16]));
}

#[test]
fn test_event_conversion_group_member_left() {
    let event = DaemonEvent::GroupMemberLeft {
        group_id: [6u8; 32],
        member_id: [7u8; 16],
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "group_member_left");
}

#[test]
fn test_event_conversion_group_created() {
    let event = DaemonEvent::GroupCreated {
        group_id: [8u8; 32],
        name: "NewGroup".to_string(),
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "group_created");
    assert_eq!(ws_event.data["name"], "NewGroup");
}

#[test]
fn test_event_conversion_file_transfer_completed() {
    let event = DaemonEvent::FileTransferCompleted {
        transfer_id: [9u8; 16],
        output_path: "/tmp/file".to_string(),
        filename: "photo.jpg".to_string(),
        from: "sender.onion".to_string(),
        size: 54321,
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "file_received");
    assert_eq!(ws_event.data["filename"], "photo.jpg");
    assert_eq!(ws_event.data["size"], 54321);
    // output_path should NOT be exposed to frontend
    assert!(
        ws_event.data.get("output_path").is_none() || ws_event.data["output_path"].is_null()
    );
}

#[test]
fn test_event_conversion_file_transfer_failed() {
    let event = DaemonEvent::FileTransferFailed {
        transfer_id: [10u8; 16],
        error: "disk full".to_string(),
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "file_transfer_failed");
    assert_eq!(ws_event.data["error"], "disk full");
}

#[test]
fn test_event_conversion_group_file_shared() {
    let event = DaemonEvent::GroupFileShared {
        group_id: [11u8; 32],
        file_id: "gf-123".to_string(),
        filename: "report.pdf".to_string(),
        size: 100000,
        sender_onion: "sharer.onion".to_string(),
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "group_file_shared");
    assert_eq!(ws_event.data["file_id"], "gf-123");
}

#[test]
fn test_event_conversion_group_file_downloaded() {
    let event = DaemonEvent::GroupFileDownloaded {
        group_id: [12u8; 32],
        file_id: "gf-456".to_string(),
        output_path: "/tmp/report.pdf".to_string(),
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "group_file_downloaded");
    assert_eq!(ws_event.data["file_id"], "gf-456");
    // output_path should NOT be exposed
    assert!(
        ws_event.data.get("output_path").is_none() || ws_event.data["output_path"].is_null()
    );
}

#[test]
fn test_event_conversion_group_file_download_failed() {
    let event = DaemonEvent::GroupFileDownloadFailed {
        group_id: [13u8; 32],
        file_id: "gf-789".to_string(),
        error: "network error".to_string(),
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "group_file_download_failed");
    assert_eq!(ws_event.data["error"], "network error");
}

#[test]
fn test_event_conversion_peer_connected() {
    let event = DaemonEvent::PeerConnected {
        address: "peer.onion".to_string(),
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "peer_connected");
    assert_eq!(ws_event.data["address"], "peer.onion");
}

#[test]
fn test_event_conversion_peer_disconnected() {
    let event = DaemonEvent::PeerDisconnected {
        address: "peer.onion".to_string(),
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "peer_disconnected");
}

#[test]
fn test_event_conversion_started() {
    let event = DaemonEvent::Started {
        onion_address: "myonion.onion".to_string(),
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "daemon_started");
    assert_eq!(ws_event.data["onion_address"], "myonion.onion");
}

#[test]
fn test_event_conversion_stopped() {
    let event = DaemonEvent::Stopped;
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "daemon_stopped");
}

#[test]
fn test_event_conversion_group_invite_received() {
    let event = DaemonEvent::GroupInviteReceived {
        invite: GroupInvitePayload {
            group_id: [14u8; 32],
            inviter_pubkey: [0u8; 32],
            bootstrap_peer: "bootstrap.onion".to_string(),
            expires_at: 9999999999,
            invite_id: [0u8; 16],
            encrypted_metadata: b"SecretGroup|extra".to_vec(),
            invite_signature: [0u8; 64],
        },
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "group_invite_received");
    assert_eq!(ws_event.data["group_id"], hex::encode([14u8; 32]));
    assert_eq!(ws_event.data["group_name"], "SecretGroup");
}

#[test]
fn test_event_conversion_group_invite_non_utf8_metadata() {
    let event = DaemonEvent::GroupInviteReceived {
        invite: GroupInvitePayload {
            group_id: [15u8; 32],
            inviter_pubkey: [0u8; 32],
            bootstrap_peer: "bootstrap.onion".to_string(),
            expires_at: 9999999999,
            invite_id: [0u8; 16],
            encrypted_metadata: vec![0xFF, 0xFE, 0xFD], // invalid UTF-8
            invite_signature: [0u8; 64],
        },
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.event_type, "group_invite_received");
    // group_name should be null since metadata is not valid UTF-8
    assert!(ws_event.data["group_name"].is_null());
}

// ========================================
// Unit Tests: Internal events return None
// ========================================

#[test]
fn test_internal_events_return_none() {
    let internal_events: Vec<DaemonEvent> = vec![
        DaemonEvent::AckReceived {
            message_id: [0u8; 16],
            ack_type: AckType::Delivered,
        },
        DaemonEvent::Error {
            message: "test".to_string(),
        },
        DaemonEvent::FileChunkReceived {
            transfer_id: [0u8; 16],
            chunk_index: 0,
            total_chunks: 1,
            from: "a.onion".to_string(),
            data: vec![],
        },
        DaemonEvent::FileOfferReceived {
            transfer_id: [0u8; 16],
            filename: "f.txt".to_string(),
            size: 0,
            hash: [0u8; 32],
            total_chunks: 1,
            from: "a.onion".to_string(),
        },
        DaemonEvent::FileTransferStarted {
            transfer_id: [0u8; 16],
            metadata: FileMetadata {
                filename: "f.txt".to_string(),
                size: 0,
                mime_type: "text/plain".to_string(),
                hash: [0u8; 32],
            },
            from: "a.onion".to_string(),
        },
        DaemonEvent::CallSignalReceived {
            call_id: [0u8; 16],
            signal_type: CallSignalType::Offer,
            from: "a.onion".to_string(),
            data: vec![],
        },
        DaemonEvent::GroupInviteGenerated {
            group_id: [0u8; 32],
            invite: GroupInvitePayload {
                group_id: [0u8; 32],
                inviter_pubkey: [0u8; 32],
                bootstrap_peer: "a.onion".to_string(),
                expires_at: 0,
                invite_id: [0u8; 16],
                encrypted_metadata: vec![],
                invite_signature: [0u8; 64],
            },
        },
        DaemonEvent::GroupInviteSent {
            group_id: [0u8; 32],
            invitee: "b.onion".to_string(),
        },
        DaemonEvent::GroupKeyRotated {
            group_id: [0u8; 32],
            new_epoch: 1,
        },
    ];

    for (i, event) in internal_events.into_iter().enumerate() {
        assert!(
            api::daemon_event_to_ws_event(event).is_none(),
            "Internal event #{} should return None",
            i
        );
    }
}

// ========================================
// Unit Tests: WsEvent JSON serialization
// ========================================

#[test]
fn test_ws_event_json_format() {
    let event = WsEvent {
        event_type: "test_event".to_string(),
        data: serde_json::json!({ "key": "value", "num": 42 }),
    };
    let json = serde_json::to_string(&event).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    // "type" field should be renamed from "event_type" via serde
    assert_eq!(parsed["type"], "test_event");
    assert_eq!(parsed["data"]["key"], "value");
    assert_eq!(parsed["data"]["num"], 42);
    // "event_type" should NOT appear in JSON output
    assert!(parsed.get("event_type").is_none());
}

#[test]
fn test_ws_event_empty_data() {
    let event = WsEvent {
        event_type: "daemon_stopped".to_string(),
        data: serde_json::json!({}),
    };
    let json = serde_json::to_string(&event).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["type"], "daemon_stopped");
    assert!(parsed["data"].is_object());
    assert_eq!(parsed["data"].as_object().unwrap().len(), 0);
}

#[test]
fn test_ws_event_special_characters_in_content() {
    let event = WsEvent {
        event_type: "message_received".to_string(),
        data: serde_json::json!({
            "content": "Hello with \"quotes\" and\nnewlines and emoji \u{1F600}",
        }),
    };
    let json = serde_json::to_string(&event).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["data"]["content"]
        .as_str()
        .unwrap()
        .contains("quotes"));
    assert!(parsed["data"]["content"]
        .as_str()
        .unwrap()
        .contains('\n'));
}

// ========================================
// Unit Tests: Hex encoding consistency
// ========================================

#[test]
fn test_hex_encoding_of_byte_arrays() {
    let msg_id: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
        0x32, 0x10,
    ];
    let event = DaemonEvent::MessageDelivered { message_id: msg_id };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(
        ws_event.data["message_id"],
        "0123456789abcdeffedcba9876543210"
    );
}

#[test]
fn test_group_id_hex_encoding_32_bytes() {
    let group_id: [u8; 32] = [0xFF; 32];
    let event = DaemonEvent::GroupJoined {
        group_id,
        name: "test".to_string(),
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    let hex_str = ws_event.data["group_id"].as_str().unwrap();
    assert_eq!(hex_str.len(), 64);
    assert!(hex_str.chars().all(|c| c == 'f'));
}

#[test]
fn test_all_zero_byte_arrays() {
    let event = DaemonEvent::MessageReceived {
        from: "zero.onion".to_string(),
        message_id: [0u8; 16],
        content: "".to_string(),
        timestamp: 0,
    };
    let ws_event = api::daemon_event_to_ws_event(event).unwrap();
    assert_eq!(ws_event.data["message_id"], "00000000000000000000000000000000");
    assert_eq!(ws_event.data["content"], "");
    assert_eq!(ws_event.data["timestamp"], 0);
}
