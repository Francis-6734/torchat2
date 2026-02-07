//! REST API endpoints for multi-user TorChat server
//!
//! Each browser/device gets its own unique onion address.
//! Sessions are tracked via cookies.

use axum::{
    body::Body,
    extract::{Path, Query, State},
    extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    http::{header, header::SET_COOKIE, HeaderMap, StatusCode},
    Json,
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::broadcast;
use axum_extra::extract::Multipart;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

use crate::models::*;
use torchat_core::identity::{generate_identity, TorIdentity};
use torchat_core::storage::UserInfo;

/// Session token cookie name
const SESSION_COOKIE: &str = "torchat_session";

/// Generate a secure random session token
fn generate_session_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..64)
        .map(|_| {
            let idx = rng.gen_range(0..62);
            let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            chars[idx] as char
        })
        .collect()
}

/// Extract session token from request headers (cookies)
fn extract_session_token(headers: &HeaderMap) -> Option<String> {
    // First try X-Session-Token header
    if let Some(token) = headers.get("x-session-token").and_then(|v| v.to_str().ok()) {
        return Some(token.to_string());
    }

    // Fallback to cookie
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                if let Some(value) = cookie.strip_prefix(&format!("{}=", SESSION_COOKIE)) {
                    return Some(value.to_string());
                }
            }
            None
        })
}

/// Create session cookie header
fn create_session_cookie(token: &str) -> String {
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000",
        SESSION_COOKIE, token
    )
}

/// Validate a v3 onion address
fn validate_onion_address(address: &str) -> Result<(), &'static str> {
    if !address.ends_with(".onion") {
        return Err("Address must end with .onion");
    }
    let pubkey_part = &address[..address.len() - 6];
    if pubkey_part.len() != 56 {
        return Err("V3 onion address must be 56 characters + .onion");
    }
    for c in pubkey_part.chars() {
        if !matches!(c, 'a'..='z' | 'A'..='Z' | '2'..='7') {
            return Err("Invalid base32 character in address");
        }
    }
    Ok(())
}

/// Get current user's identity (creates new one if needed)
pub async fn get_identity(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, HeaderMap, Json<ApiResponse<Identity>>) {
    let response_headers = HeaderMap::new();

    // Check for existing session
    let session_token = extract_session_token(&headers);

    let db = state.database.lock().await;

    if let Some(token) = session_token {
        // Try to load existing user
        match db.get_user_by_session(&token) {
            Ok(Some((user_id, identity, display_name))) => {
                // Update activity
                let _ = db.update_user_activity(user_id);

                // Drop the database lock before starting daemon
                let identity_clone = identity.clone();
                drop(db);

                // Auto-start daemon for returning user so they can receive messages
                if let Err(e) = ensure_daemon_running(&state, user_id, &identity_clone).await {
                    warn!(user_id, error = %e, "Failed to auto-start daemon for returning user");
                }

                let api_identity = Identity {
                    onion_address: identity_clone.onion_address().to_string(),
                    fingerprint: identity_clone.formatted_fingerprint(),
                    display_name,
                    session_token: Some(token),
                };

                return (
                    StatusCode::OK,
                    response_headers,
                    Json(ApiResponse::ok(api_identity)),
                );
            }
            Ok(None) => {
                // Invalid session, will create new one below
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    response_headers,
                    Json(ApiResponse {
                        success: false,
                        data: None,
                        error: Some(format!("Database error: {}", e)),
                    }),
                );
            }
        }
    }

    // No valid session - return empty (UI will call register)
    (
        StatusCode::OK,
        response_headers,
        Json(ApiResponse::ok_none()),
    )
}

/// Register a new user (generates unique onion address)
pub async fn register_user(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegisterRequest>,
) -> (StatusCode, HeaderMap, Json<ApiResponse<Identity>>) {
    let mut response_headers = HeaderMap::new();

    // Check if already has valid session
    if let Some(token) = extract_session_token(&headers) {
        let db = state.database.lock().await;
        if let Ok(Some((_, identity, display_name))) = db.get_user_by_session(&token) {
            // Already registered
            let api_identity = Identity {
                onion_address: identity.onion_address().to_string(),
                fingerprint: identity.formatted_fingerprint(),
                display_name,
                session_token: Some(token),
            };
            return (
                StatusCode::OK,
                response_headers,
                Json(ApiResponse::ok(api_identity)),
            );
        }
    }

    // Generate new identity for this user
    let identity = match generate_identity() {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                response_headers,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(format!("Failed to generate identity: {}", e)),
                }),
            );
        }
    };

    // Generate session token
    let session_token = generate_session_token();

    // Store in database
    let user_id = {
        let db = state.database.lock().await;
        match db.create_user(&session_token, &identity, request.display_name.as_deref()) {
            Ok(id) => id,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    response_headers,
                    Json(ApiResponse {
                        success: false,
                        data: None,
                        error: Some(format!("Failed to create user: {}", e)),
                    }),
                );
            }
        }
    };

    info!(
        user_id = user_id,
        onion = %identity.onion_address(),
        "New user registered"
    );

    // Auto-start the P2P daemon so user can receive messages immediately
    if let Err(e) = ensure_daemon_running(&state, user_id, &identity).await {
        warn!(user_id, error = %e, "Failed to auto-start daemon on registration");
        // Continue anyway - user can start manually later
    } else {
        info!(user_id, "P2P daemon auto-started on registration");
    }

    // Set session cookie
    response_headers.insert(
        SET_COOKIE,
        create_session_cookie(&session_token).parse().unwrap(),
    );

    let api_identity = Identity {
        onion_address: identity.onion_address().to_string(),
        fingerprint: identity.formatted_fingerprint(),
        display_name: request.display_name.clone(),
        session_token: Some(session_token),
    };

    (
        StatusCode::CREATED,
        response_headers,
        Json(ApiResponse::ok(api_identity)),
    )
}

/// Helper to get current user from session
async fn get_current_user(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<(i64, TorIdentity, Option<String>), (StatusCode, Json<ApiResponse<()>>)> {
    let session_token = extract_session_token(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some("No session. Please register first.".to_string()),
            }),
        )
    })?;

    let db = state.database.lock().await;
    db.get_user_by_session(&session_token)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(format!("Database error: {}", e)),
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid session. Please register again.".to_string()),
                }),
            )
        })
}

/// Ensure the messaging daemon is running for a user, starting it if needed
async fn ensure_daemon_running(
    state: &Arc<AppState>,
    user_id: i64,
    identity: &TorIdentity,
) -> Result<(), String> {
    // Check if already running
    {
        let daemons = state.daemons.lock().await;
        if daemons.contains_key(&user_id) {
            return Ok(());
        }
    }

    let onion_addr = identity.onion_address().to_string();
    info!(user_id, onion = %onion_addr, "Auto-starting daemon for message delivery");

    // Use the shared server database so the daemon stores messages in the same place as the API
    // This ensures get_messages can see received messages stored by the daemon
    use torchat_core::messaging::MessagingDaemon;
    let daemon = Arc::new(MessagingDaemon::new(identity.clone(), state.database.clone(), user_id));

    // Start the daemon with onion service
    use torchat_core::tor::OnionServiceConfig;
    let service_config = OnionServiceConfig {
        local_port: 11009 + (user_id as u16 % 1000),
        ..Default::default()
    };

    daemon.start(service_config).await
        .map_err(|e| format!("Failed to start daemon: {}", e))?;

    // Subscribe to daemon events for file transfer notifications
    // This is critical - without this, received files won't be tracked!
    let mut event_rx = daemon.subscribe();
    let state_clone = state.clone();
    let user_id_clone = user_id;

    tokio::spawn(async move {
        use torchat_core::messaging::DaemonEvent;
        while let Ok(event) = event_rx.recv().await {
            match event {
                DaemonEvent::FileTransferCompleted { transfer_id, output_path, filename, from, size } => {
                    info!(
                        user_id = user_id_clone,
                        filename = %filename,
                        from = %from,
                        "File received (auto-start daemon), adding to list"
                    );
                    add_received_file(
                        &state_clone,
                        user_id_clone,
                        hex::encode(transfer_id),
                        filename,
                        size,
                        from,
                        output_path,
                    ).await;
                }
                DaemonEvent::GroupInviteReceived { invite } => {
                    info!(
                        user_id = user_id_clone,
                        group_id = ?invite.group_id,
                        bootstrap_peer = %invite.bootstrap_peer,
                        "Group invite received (auto-start daemon)"
                    );
                    // Parse group name from encrypted metadata (format: "name|policy")
                    let group_name = String::from_utf8(invite.encrypted_metadata.clone())
                        .ok()
                        .and_then(|s| s.split('|').next().map(|n| n.to_string()));

                    // Store the invite in the database
                    let db = state_clone.database.lock().await;
                    if let Err(e) = db.store_pending_invite(user_id_clone, &invite, group_name.as_deref()) {
                        warn!(user_id = user_id_clone, error = %e, "Failed to store pending invite");
                    }
                }
                DaemonEvent::Stopped => {
                    info!(user_id = user_id_clone, "Auto-start daemon event listener stopped");
                    break;
                }
                _ => {}
            }
        }
    });

    // Store daemon
    let mut daemons = state.daemons.lock().await;
    daemons.insert(user_id, daemon);

    info!(user_id, onion = %onion_addr, "Daemon auto-started successfully");
    Ok(())
}

/// List contacts for current user
pub async fn list_contacts(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<Vec<Contact>>>) {
    let (user_id, _, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    let db = state.database.lock().await;
    match db.list_user_contacts(user_id) {
        Ok(contacts) => {
            let api_contacts: Vec<Contact> = contacts
                .into_iter()
                .map(|(id, addr, name)| Contact {
                    id: id.to_string(),
                    address: addr,
                    name,
                    last_message: None,
                })
                .collect();
            (StatusCode::OK, Json(ApiResponse::ok(api_contacts)))
        }
        Err(e) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(format!("Failed to list contacts: {}", e)),
                }),
            )
        }
    }
}

/// Add a contact for current user
pub async fn add_contact(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(request): Json<AddContactRequest>,
) -> (StatusCode, Json<ApiResponse<Contact>>) {
    // Validate onion address
    if let Err(e) = validate_onion_address(&request.address) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(e.to_string()),
            }),
        );
    }

    let (user_id, my_identity, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    // Can't add yourself
    if request.address == my_identity.onion_address().to_string() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Cannot add yourself as a contact".to_string()),
            }),
        );
    }

    let db = state.database.lock().await;
    match db.add_user_contact(user_id, &request.address, request.name.as_deref()) {
        Ok(contact_id) => {
            info!(user_id, contact_id, address = %request.address, "Contact added");

            let contact = Contact {
                id: contact_id.to_string(),
                address: request.address,
                name: request.name,
                last_message: None,
            };
            (StatusCode::CREATED, Json(ApiResponse::ok(contact)))
        }
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("UNIQUE constraint") {
                (
                    StatusCode::CONFLICT,
                    Json(ApiResponse {
                        success: false,
                        data: None,
                        error: Some("Contact already exists".to_string()),
                    }),
                )
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse {
                        success: false,
                        data: None,
                        error: Some(format!("Failed to add contact: {}", e)),
                    }),
                )
            }
        }
    }
}

/// Delete a contact
pub async fn delete_contact(
    headers: HeaderMap,
    Path(contact_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    let (user_id, _, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, _json)) => {
            return (
                status,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Unauthorized".to_string()),
                }),
            );
        }
    };

    let contact_db_id: i64 = match contact_id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid contact ID".to_string()),
                }),
            );
        }
    };

    let db = state.database.lock().await;
    match db.delete_user_contact(user_id, contact_db_id) {
        Ok(true) => {
            info!(user_id, contact_id = contact_db_id, "Contact deleted");
            (StatusCode::OK, Json(ApiResponse::ok("Contact deleted".to_string())))
        }
        Ok(false) => {
            (
                StatusCode::NOT_FOUND,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Contact not found".to_string()),
                }),
            )
        }
        Err(e) => {
            warn!(user_id, error = %e, "Failed to delete contact");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(format!("Failed to delete contact: {}", e)),
                }),
            )
        }
    }
}

/// Delete a group completely (removes all data)
pub async fn delete_group(
    headers: HeaderMap,
    Path(group_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    let session_token = match extract_session_token(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("No session token".to_string()),
                }),
            );
        }
    };

    let db = state.database.lock().await;
    let (user_id, _identity, _display_name) = match db.get_user_by_session(&session_token) {
        Ok(Some(user)) => user,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid session".to_string()),
                }),
            );
        }
    };

    let group_id_bytes = match hex::decode(&group_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid group ID format".to_string()),
                }),
            );
        }
    };

    // Remove group from database
    match db.delete_group(&group_id_bytes) {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Group not found".to_string()),
                }),
            );
        }
        Err(e) => {
            warn!(user_id, error = %e, "Failed to delete group from database");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(format!("Failed to delete group: {}", e)),
                }),
            );
        }
    }
    drop(db);

    // Also remove from daemon's in-memory group sessions
    let daemons = state.daemons.lock().await;
    if let Some(daemon) = daemons.get(&user_id) {
        use torchat_core::messaging::DaemonCommand;
        let _ = daemon.command_sender().send(DaemonCommand::LeaveGroup {
            group_id: group_id_bytes,
        }).await;
    }
    drop(daemons);

    info!(group_id, user_id, "Group deleted");

    (
        StatusCode::OK,
        Json(ApiResponse::ok("Group deleted".to_string())),
    )
}

/// Get messages with a contact
pub async fn get_messages(
    headers: HeaderMap,
    Path(contact_address): Path<String>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<Vec<Message>>>) {
    let (user_id, _, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    let db = state.database.lock().await;

    // Lazily clean up expired disappearing messages
    let _ = db.cleanup_expired_messages();

    // Get messages for this contact from the simple_messages table
    match db.get_simple_messages_by_address(user_id, &contact_address, 100) {
        Ok(messages) => {
            let api_messages: Vec<Message> = messages
                .into_iter()
                .map(|m| Message {
                    id: m.id.to_string(),
                    content: m.content,
                    timestamp: m.timestamp,
                    is_outgoing: m.is_outgoing,
                    status: if m.is_outgoing { "sent".to_string() } else { "received".to_string() },
                    disappear_after: m.disappear_after,
                })
                .collect();
            (StatusCode::OK, Json(ApiResponse::ok(api_messages)))
        }
        Err(e) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(format!("Failed to get messages: {}", e)),
                }),
            )
        }
    }
}

/// Search messages in a P2P conversation
pub async fn search_messages(
    headers: HeaderMap,
    Path(contact_address): Path<String>,
    Query(query): Query<SearchQuery>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<Vec<Message>>>) {
    let (user_id, _, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    if query.q.trim().is_empty() {
        return (StatusCode::OK, Json(ApiResponse::ok(vec![])));
    }

    let db = state.database.lock().await;

    match db.search_messages_by_address(user_id, &contact_address, &query.q, 50) {
        Ok(messages) => {
            let api_messages: Vec<Message> = messages
                .into_iter()
                .map(|m| Message {
                    id: m.id.to_string(),
                    content: m.content,
                    timestamp: m.timestamp,
                    is_outgoing: m.is_outgoing,
                    status: if m.is_outgoing { "sent".to_string() } else { "received".to_string() },
                    disappear_after: m.disappear_after,
                })
                .collect();
            (StatusCode::OK, Json(ApiResponse::ok(api_messages)))
        }
        Err(e) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(format!("Search failed: {}", e)),
                }),
            )
        }
    }
}

/// Search messages in a group conversation
pub async fn search_group_messages_endpoint(
    headers: HeaderMap,
    Path(group_id): Path<String>,
    Query(query): Query<SearchQuery>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<Vec<GroupMessageInfo>>>) {
    let session_token = match extract_session_token(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("No session token".to_string()),
                }),
            );
        }
    };

    let db = state.database.lock().await;
    let (_user_id, identity, _display_name) = match db.get_user_by_session(&session_token) {
        Ok(Some(user)) => user,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid session".to_string()),
                }),
            );
        }
    };

    let group_id_bytes = match hex::decode(&group_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid group ID format".to_string()),
                }),
            );
        }
    };

    if query.q.trim().is_empty() {
        return (StatusCode::OK, Json(ApiResponse::ok(vec![])));
    }

    let our_pubkey = identity.public_key().to_bytes();
    let our_member_id = torchat_core::crypto::generate_member_id(&group_id_bytes, &our_pubkey);

    match db.search_group_messages(&group_id_bytes, &query.q, 50) {
        Ok(messages) => {
            let message_infos: Vec<GroupMessageInfo> = messages
                .into_iter()
                .map(|msg| {
                    let is_outgoing = msg.sender_id == our_member_id;
                    GroupMessageInfo {
                        message_id: hex::encode(msg.id),
                        sender_id: hex::encode(msg.sender_id),
                        content: msg.content,
                        timestamp: msg.timestamp,
                        outgoing: is_outgoing,
                        disappear_after: msg.disappear_after,
                    }
                })
                .collect();
            (StatusCode::OK, Json(ApiResponse::ok(message_infos)))
        }
        Err(e) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(format!("Search failed: {}", e)),
                }),
            )
        }
    }
}

/// Send a message to a contact
pub async fn send_message(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(request): Json<SendMessageRequest>,
) -> (StatusCode, Json<ApiResponse<Message>>) {
    let (user_id, my_identity, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    let my_address = my_identity.onion_address().to_string();
    let timestamp = chrono::Utc::now().timestamp();
    let msg_id: i64;

    // Store message in database
    {
        let db = state.database.lock().await;
        match db.store_simple_message_by_address(user_id, &request.to, &request.content, true, request.disappear_after) {
            Ok(id) => msg_id = id,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiResponse {
                        success: false,
                        data: None,
                        error: Some(format!("Failed to store message: {}", e)),
                    }),
                );
            }
        }
    }

    // Ensure daemon is running (auto-start if needed)
    if let Err(e) = ensure_daemon_running(&state, user_id, &my_identity).await {
        warn!(user_id, error = %e, "Failed to start daemon for message delivery");
        // Still return success since message is stored, but log the issue
    }

    // Send via daemon
    {
        let daemons = state.daemons.lock().await;
        if let Some(daemon) = daemons.get(&user_id) {
            // Generate message ID
            let mut message_id = [0u8; 16];
            use rand::Rng;
            rand::thread_rng().fill(&mut message_id);

            // Queue message for sending
            let cmd_tx = daemon.command_sender();
            match cmd_tx.try_send(torchat_core::messaging::DaemonCommand::SendMessage {
                to: request.to.clone(),
                content: request.content.clone(),
                message_id,
            }) {
                Ok(_) => info!(from = %my_address, to = %request.to, "Message queued for P2P delivery"),
                Err(e) => warn!(from = %my_address, to = %request.to, error = %e, "Failed to queue message"),
            }
        }
    }

    let message = Message {
        id: msg_id.to_string(),
        content: request.content,
        timestamp,
        is_outgoing: true,
        status: "sending".to_string(),
        disappear_after: request.disappear_after,
    };

    (StatusCode::CREATED, Json(ApiResponse::ok(message)))
}

/// Daemon status response
#[derive(Debug, Serialize)]
pub struct DaemonStatusResponse {
    pub running: bool,
    pub onion_address: Option<String>,
    pub message: String,
}

/// Start the messaging daemon for current user
pub async fn start_daemon(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<DaemonStatusResponse>>) {
    let (user_id, identity, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    let onion_addr = identity.onion_address().to_string();

    // Check if already running
    {
        let daemons = state.daemons.lock().await;
        if daemons.contains_key(&user_id) {
            return (
                StatusCode::OK,
                Json(ApiResponse::ok(DaemonStatusResponse {
                    running: true,
                    onion_address: Some(onion_addr),
                    message: "Daemon already running".to_string(),
                })),
            );
        }
    }

    info!(user_id, onion = %onion_addr, "Starting daemon");

    // Use the shared server database so messages are stored in the same place as the API
    use torchat_core::messaging::MessagingDaemon;
    let daemon = Arc::new(MessagingDaemon::new(identity.clone(), state.database.clone(), user_id));

    // Start the daemon with onion service
    use torchat_core::tor::OnionServiceConfig;
    let service_config = OnionServiceConfig {
        local_port: 11009 + (user_id as u16 % 1000), // Different port per user
        ..Default::default()
    };

    match daemon.start(service_config).await {
        Ok(()) => {
            // Subscribe to daemon events for file transfer notifications
            let mut event_rx = daemon.subscribe();
            let state_clone = state.clone();
            let user_id_clone = user_id;

            tokio::spawn(async move {
                use torchat_core::messaging::DaemonEvent;
                while let Ok(event) = event_rx.recv().await {
                    match event {
                        DaemonEvent::FileTransferCompleted { transfer_id, output_path, filename, from, size } => {
                            info!(
                                user_id = user_id_clone,
                                filename = %filename,
                                from = %from,
                                "File received, adding to list"
                            );
                            add_received_file(
                                &state_clone,
                                user_id_clone,
                                hex::encode(transfer_id),
                                filename,
                                size,
                                from,
                                output_path,
                            ).await;
                        }
                        DaemonEvent::GroupInviteReceived { invite } => {
                            info!(
                                user_id = user_id_clone,
                                group_id = ?invite.group_id,
                                bootstrap_peer = %invite.bootstrap_peer,
                                "Group invite received"
                            );
                            // Parse group name from encrypted metadata (format: "name|policy")
                            let group_name = String::from_utf8(invite.encrypted_metadata.clone())
                                .ok()
                                .and_then(|s| s.split('|').next().map(|n| n.to_string()));

                            // Store the invite in the database
                            let db = state_clone.database.lock().await;
                            if let Err(e) = db.store_pending_invite(user_id_clone, &invite, group_name.as_deref()) {
                                warn!(user_id = user_id_clone, error = %e, "Failed to store pending invite");
                            }
                        }
                        DaemonEvent::Stopped => {
                            info!(user_id = user_id_clone, "Daemon event listener stopped");
                            break;
                        }
                        _ => {}
                    }
                }
            });

            // Store daemon
            let mut daemons = state.daemons.lock().await;
            daemons.insert(user_id, daemon);

            info!(user_id, onion = %onion_addr, "Daemon started");

            (
                StatusCode::OK,
                Json(ApiResponse::ok(DaemonStatusResponse {
                    running: true,
                    onion_address: Some(onion_addr),
                    message: "Daemon started successfully".to_string(),
                })),
            )
        }
        Err(e) => {
            warn!(user_id, error = %e, "Failed to start daemon");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(format!("Failed to start daemon: {}", e)),
                }),
            )
        }
    }
}

/// Stop the messaging daemon for current user
pub async fn stop_daemon(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<DaemonStatusResponse>>) {
    let (user_id, identity, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    let mut daemons = state.daemons.lock().await;
    if let Some(daemon) = daemons.remove(&user_id) {
        let cmd_tx = daemon.command_sender();
        let _ = cmd_tx.try_send(torchat_core::messaging::DaemonCommand::Stop);

        info!(user_id, "Daemon stopped");
        (
            StatusCode::OK,
            Json(ApiResponse::ok(DaemonStatusResponse {
                running: false,
                onion_address: Some(identity.onion_address().to_string()),
                message: "Daemon stopped".to_string(),
            })),
        )
    } else {
        (
            StatusCode::OK,
            Json(ApiResponse::ok(DaemonStatusResponse {
                running: false,
                onion_address: Some(identity.onion_address().to_string()),
                message: "Daemon was not running".to_string(),
            })),
        )
    }
}

/// Get daemon status for current user
pub async fn daemon_status(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<DaemonStatusResponse>>) {
    let (user_id, identity, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    let daemons = state.daemons.lock().await;
    let running = daemons.contains_key(&user_id);

    (
        StatusCode::OK,
        Json(ApiResponse::ok(DaemonStatusResponse {
            running,
            onion_address: Some(identity.onion_address().to_string()),
            message: if running { "Daemon is running".to_string() } else { "Daemon is not running".to_string() },
        })),
    )
}

/// List all registered users (for debugging/admin)
pub async fn list_users(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<Vec<UserInfo>>>) {
    let db = state.database.lock().await;

    match db.list_all_users() {
        Ok(users) => {
            (StatusCode::OK, Json(ApiResponse::ok(users)))
        }
        Err(e) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(format!("Failed to list users: {}", e)),
                }),
            )
        }
    }
}

// ==================== File Transfer API ====================

/// Maximum file size for transfers (5GB).
const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024 * 1024;

/// Request to send a file
#[derive(Debug, serde::Deserialize)]
pub struct SendFileRequest {
    /// Recipient's onion address
    pub to: String,
    /// Base64-encoded file content
    pub file_data: String,
    /// Filename
    pub filename: String,
}

/// File transfer status response
#[derive(Debug, serde::Serialize)]
pub struct FileTransferResponse {
    pub transfer_id: String,
    pub filename: String,
    pub size: u64,
    pub status: String,
    pub progress: f32,
}

/// Send a file to a contact using TCP stream over Tor
pub async fn send_file(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(request): Json<SendFileRequest>,
) -> (StatusCode, Json<ApiResponse<FileTransferResponse>>) {
    let (user_id, identity, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    // Verify daemon is running (for Tor config)
    let daemons = state.daemons.lock().await;
    if !daemons.contains_key(&user_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some("P2P daemon not running. Start daemon first.".to_string()),
            }),
        );
    }
    drop(daemons);

    // Decode file data from base64
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    let file_data = match BASE64.decode(&request.file_data) {
        Ok(data) => data,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(format!("Invalid base64 file data: {}", e)),
                }),
            );
        }
    };

    // Check file size limit (5GB max)
    if file_data.len() as u64 > MAX_FILE_SIZE {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!(
                    "File size {} bytes exceeds maximum allowed size of {} bytes (5GB)",
                    file_data.len(), MAX_FILE_SIZE
                )),
            }),
        );
    }

    // Save to temp file
    let temp_dir = std::env::temp_dir();
    let temp_filename = format!("torchat_upload_{}", uuid::Uuid::new_v4());
    let temp_path = temp_dir.join(&temp_filename);

    if let Err(e) = std::fs::write(&temp_path, &file_data) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to save file: {}", e)),
            }),
        );
    }

    let file_size = file_data.len() as u64;
    let filename = request.filename.clone();
    let filename_for_response = filename.clone();
    let to_address = request.to.clone();
    let sender_address = identity.onion_address().to_string();

    // Generate transfer ID for tracking
    let transfer_id: [u8; 16] = torchat_core::crypto::random_bytes();
    let transfer_id_hex = hex::encode(transfer_id);

    // Store initial transfer status
    {
        let mut transfers = state.outgoing_transfers.lock().await;
        transfers.insert(transfer_id_hex.clone(), crate::models::OutgoingTransferStatus {
            transfer_id: transfer_id_hex.clone(),
            filename: filename.clone(),
            to: to_address.clone(),
            size: file_size,
            status: "connecting".to_string(),
            error: None,
            timestamp: chrono::Utc::now().timestamp(),
        });
    }

    // Get Tor config
    let tor_config = torchat_core::tor::TorConnectionConfig::default();

    // Spawn task to send file via TCP stream
    let temp_path_clone = temp_path.clone();
    let state_clone = state.clone();
    let transfer_id_hex_clone = transfer_id_hex.clone();
    let to_address_clone = to_address.clone();
    let filename_clone = filename.clone();

    tokio::spawn(async move {
        info!(
            to = %to_address,
            filename = %filename,
            size = file_size,
            transfer_id = %transfer_id_hex_clone,
            "Starting TCP stream file transfer"
        );

        // Update status to transferring
        {
            let mut transfers = state_clone.outgoing_transfers.lock().await;
            if let Some(status) = transfers.get_mut(&transfer_id_hex_clone) {
                status.status = "transferring".to_string();
            }
        }

        let result = torchat_core::messaging::send_file_stream(
            temp_path_clone.clone(),
            &to_address,
            &sender_address,
            &tor_config,
        ).await;

        // Update final status
        {
            let mut transfers = state_clone.outgoing_transfers.lock().await;
            if let Some(status) = transfers.get_mut(&transfer_id_hex_clone) {
                match &result {
                    Ok(r) if r.success => {
                        status.status = "completed".to_string();
                        info!(
                            transfer_id = %transfer_id_hex_clone,
                            to = %to_address_clone,
                            filename = %filename_clone,
                            "File transfer completed successfully"
                        );
                    }
                    Ok(r) => {
                        status.status = "failed".to_string();
                        status.error = r.error.clone();
                        warn!(
                            transfer_id = %transfer_id_hex_clone,
                            to = %to_address_clone,
                            error = ?r.error,
                            "File transfer failed"
                        );
                    }
                    Err(e) => {
                        status.status = "failed".to_string();
                        status.error = Some(e.to_string());
                        warn!(
                            transfer_id = %transfer_id_hex_clone,
                            to = %to_address_clone,
                            error = %e,
                            "File transfer error"
                        );
                    }
                }
            }
        }

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_path_clone);
    });

    (
        StatusCode::OK,
        Json(ApiResponse::ok(FileTransferResponse {
            transfer_id: transfer_id_hex,
            filename: filename_for_response,
            size: file_size,
            status: "transferring".to_string(),
            progress: 0.0,
        })),
    )
}

/// Send a file using multipart/form-data (more efficient for large files)
pub async fn send_file_multipart(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> (StatusCode, Json<ApiResponse<FileTransferResponse>>) {
    let (user_id, identity, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    // Verify daemon is running (for Tor config)
    let daemons = state.daemons.lock().await;
    if !daemons.contains_key(&user_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some("P2P daemon not running. Start daemon first.".to_string()),
            }),
        );
    }
    drop(daemons);

    let mut to_address: Option<String> = None;
    let mut filename: Option<String> = None;
    let mut file_data: Option<Vec<u8>> = None;

    // Process multipart fields
    while let Ok(Some(field)) = multipart.next_field().await {
        let field_name: String = field.name().unwrap_or("").to_string();

        match field_name.as_str() {
            "to" => {
                if let Ok(value) = field.text().await {
                    to_address = Some(value);
                }
            }
            "filename" => {
                if let Ok(value) = field.text().await {
                    filename = Some(value);
                }
            }
            "file" => {
                // Get filename from the field if not already set
                if filename.is_none() {
                    filename = field.file_name().map(|s: &str| s.to_string());
                }
                // Read file data
                match field.bytes().await {
                    Ok(bytes) => {
                        let data: Vec<u8> = bytes.to_vec();
                        file_data = Some(data);
                    }
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(ApiResponse {
                                success: false,
                                data: None,
                                error: Some(format!("Failed to read file data: {}", e)),
                            }),
                        );
                    }
                }
            }
            _ => {
                // Ignore unknown fields
            }
        }
    }

    // Validate required fields
    let to_address = match to_address {
        Some(addr) => addr,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Missing 'to' field (recipient address)".to_string()),
                }),
            );
        }
    };

    let filename = match filename {
        Some(name) => name,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Missing filename".to_string()),
                }),
            );
        }
    };

    let file_data = match file_data {
        Some(data) => data,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Missing 'file' field".to_string()),
                }),
            );
        }
    };

    // Check file size limit (5GB max)
    if file_data.len() as u64 > MAX_FILE_SIZE {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!(
                    "File size {} bytes exceeds maximum allowed size of {} bytes (5GB)",
                    file_data.len(), MAX_FILE_SIZE
                )),
            }),
        );
    }

    let file_size = file_data.len() as u64;

    // Save to temp file
    let temp_dir = std::env::temp_dir();
    let temp_filename = format!("torchat_upload_{}", uuid::Uuid::new_v4());
    let temp_path = temp_dir.join(&temp_filename);

    if let Err(e) = std::fs::write(&temp_path, &file_data) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to save file: {}", e)),
            }),
        );
    }

    let filename_for_response = filename.clone();
    let sender_address = identity.onion_address().to_string();

    // Generate transfer ID for tracking
    let transfer_id: [u8; 16] = torchat_core::crypto::random_bytes();
    let transfer_id_hex = hex::encode(transfer_id);

    // Store initial transfer status
    {
        let mut transfers = state.outgoing_transfers.lock().await;
        transfers.insert(transfer_id_hex.clone(), crate::models::OutgoingTransferStatus {
            transfer_id: transfer_id_hex.clone(),
            filename: filename.clone(),
            to: to_address.clone(),
            size: file_size,
            status: "connecting".to_string(),
            error: None,
            timestamp: chrono::Utc::now().timestamp(),
        });
    }

    // Get Tor config
    let tor_config = torchat_core::tor::TorConnectionConfig::default();

    // Spawn task to send file via TCP stream
    let temp_path_clone = temp_path.clone();
    let state_clone = state.clone();
    let transfer_id_hex_clone = transfer_id_hex.clone();
    let to_address_clone = to_address.clone();
    let filename_clone = filename.clone();

    tokio::spawn(async move {
        info!(
            to = %to_address,
            filename = %filename,
            size = file_size,
            transfer_id = %transfer_id_hex_clone,
            "Starting TCP stream file transfer (multipart upload)"
        );

        // Update status to transferring
        {
            let mut transfers = state_clone.outgoing_transfers.lock().await;
            if let Some(status) = transfers.get_mut(&transfer_id_hex_clone) {
                status.status = "transferring".to_string();
            }
        }

        let result = torchat_core::messaging::send_file_stream(
            temp_path_clone.clone(),
            &to_address,
            &sender_address,
            &tor_config,
        ).await;

        // Update final status
        {
            let mut transfers = state_clone.outgoing_transfers.lock().await;
            if let Some(status) = transfers.get_mut(&transfer_id_hex_clone) {
                match &result {
                    Ok(r) if r.success => {
                        status.status = "completed".to_string();
                        info!(
                            transfer_id = %transfer_id_hex_clone,
                            to = %to_address_clone,
                            filename = %filename_clone,
                            "File transfer completed successfully"
                        );
                    }
                    Ok(r) => {
                        status.status = "failed".to_string();
                        status.error = r.error.clone();
                        warn!(
                            transfer_id = %transfer_id_hex_clone,
                            to = %to_address_clone,
                            error = ?r.error,
                            "File transfer failed"
                        );
                    }
                    Err(e) => {
                        status.status = "failed".to_string();
                        status.error = Some(e.to_string());
                        warn!(
                            transfer_id = %transfer_id_hex_clone,
                            to = %to_address_clone,
                            error = %e,
                            "File transfer error"
                        );
                    }
                }
            }
        }

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_path_clone);
    });

    (
        StatusCode::OK,
        Json(ApiResponse::ok(FileTransferResponse {
            transfer_id: transfer_id_hex,
            filename: filename_for_response,
            size: file_size,
            status: "transferring".to_string(),
            progress: 0.0,
        })),
    )
}

/// Get file transfer status
pub async fn file_transfer_status(
    headers: HeaderMap,
    Path(transfer_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<FileTransferResponse>>) {
    let (_user_id, _, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    // Get transfer status from our tracking
    let transfers = state.outgoing_transfers.lock().await;
    match transfers.get(&transfer_id) {
        Some(status) => {
            (
                StatusCode::OK,
                Json(ApiResponse::ok(FileTransferResponse {
                    transfer_id: status.transfer_id.clone(),
                    filename: status.filename.clone(),
                    size: status.size,
                    status: status.status.clone(),
                    progress: if status.status == "completed" { 100.0 } else { 0.0 },
                })),
            )
        }
        None => {
            (
                StatusCode::OK,
                Json(ApiResponse::ok(FileTransferResponse {
                    transfer_id,
                    filename: "unknown".to_string(),
                    size: 0,
                    status: "not_found".to_string(),
                    progress: 0.0,
                })),
            )
        }
    }
}

/// List received files for a specific contact
pub async fn list_received_files(
    headers: HeaderMap,
    Path(contact_address): Path<String>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<Vec<crate::models::ReceivedFile>>>) {
    let (user_id, _, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    let received_files = state.received_files.lock().await;
    let user_files = received_files.get(&user_id).cloned().unwrap_or_default();

    // Filter by contact address
    let filtered: Vec<_> = user_files
        .into_iter()
        .filter(|f| f.from == contact_address)
        .collect();

    (StatusCode::OK, Json(ApiResponse::ok(filtered)))
}

/// Download a received file by transfer ID
pub async fn download_file(
    headers: HeaderMap,
    Path(transfer_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Response {
    // Authenticate user
    let user_id = match get_current_user(&headers, &state).await {
        Ok((id, _, _)) => id,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                "Not authenticated",
            ).into_response();
        }
    };

    // Find the file in user's received files
    let received_files = state.received_files.lock().await;
    let user_files = received_files.get(&user_id);

    let file_info = user_files.and_then(|files| {
        files.iter().find(|f| f.transfer_id == transfer_id)
    });

    let file_info = match file_info {
        Some(f) => f.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                "File not found",
            ).into_response();
        }
    };
    drop(received_files);

    // Read the file
    let file_path = std::path::Path::new(&file_info.output_path);
    if !file_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            "File no longer exists on disk",
        ).into_response();
    }

    let file_content = match tokio::fs::read(&file_path).await {
        Ok(content) => content,
        Err(e) => {
            warn!(error = %e, path = %file_info.output_path, "Failed to read file");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to read file",
            ).into_response();
        }
    };

    // Determine content type based on file extension
    let content_type = get_content_type(&file_info.filename);

    // Build response with proper headers for download
    let filename_encoded = urlencoding::encode(&file_info.filename);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"; filename*=UTF-8''{}",
                file_info.filename, filename_encoded)
        )
        .header(header::CONTENT_LENGTH, file_content.len())
        .body(Body::from(file_content))
        .unwrap()
}

/// Get content type from filename extension
fn get_content_type(filename: &str) -> &'static str {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        // Images
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        // Videos
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "avi" => "video/x-msvideo",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        // Audio
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "flac" => "audio/flac",
        "m4a" => "audio/mp4",
        // Documents
        "pdf" => "application/pdf",
        "doc" | "docx" => "application/msword",
        "xls" | "xlsx" => "application/vnd.ms-excel",
        "ppt" | "pptx" => "application/vnd.ms-powerpoint",
        "txt" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        // Archives
        "zip" => "application/zip",
        "tar" => "application/x-tar",
        "gz" | "gzip" => "application/gzip",
        "rar" => "application/vnd.rar",
        "7z" => "application/x-7z-compressed",
        // Default
        _ => "application/octet-stream",
    }
}

/// Add a received file to the list (called internally when file is received)
pub async fn add_received_file(
    state: &Arc<AppState>,
    user_id: i64,
    transfer_id: String,
    filename: String,
    size: u64,
    from: String,
    output_path: String,
) {
    let mut received_files = state.received_files.lock().await;
    let user_files = received_files.entry(user_id).or_insert_with(Vec::new);

    user_files.push(crate::models::ReceivedFile {
        transfer_id,
        filename,
        size,
        from,
        output_path,
        timestamp: chrono::Utc::now().timestamp(),
    });
}

/// List all outgoing transfers for current user
pub async fn list_outgoing_transfers(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<Vec<crate::models::OutgoingTransferStatus>>>) {
    let (_user_id, _, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    let transfers = state.outgoing_transfers.lock().await;
    let all_transfers: Vec<_> = transfers.values().cloned().collect();

    (StatusCode::OK, Json(ApiResponse::ok(all_transfers)))
}

// ==================== Voice Call API ====================

/// Request to start a call
#[derive(Debug, serde::Deserialize)]
pub struct StartCallRequest {
    /// Recipient's onion address
    pub to: String,
}

/// Request to answer/hangup a call
#[derive(Debug, serde::Deserialize)]
pub struct CallActionRequest {
    /// Call ID
    pub call_id: String,
}

/// Call status response
#[derive(Debug, serde::Serialize)]
pub struct CallResponse {
    pub call_id: String,
    pub peer_address: String,
    pub status: String,
}

/// Start a voice call
pub async fn start_call(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(request): Json<StartCallRequest>,
) -> (StatusCode, Json<ApiResponse<CallResponse>>) {
    use torchat_core::protocol::CallSignalType;
    use torchat_core::messaging::DaemonCommand;

    let (user_id, _identity, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    // Get daemon
    let daemons = state.daemons.lock().await;
    let daemon = match daemons.get(&user_id) {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("P2P daemon not running. Start daemon first.".to_string()),
                }),
            );
        }
    };
    drop(daemons);

    // Generate call ID
    let call_id: [u8; 16] = torchat_core::crypto::random_bytes();
    let call_id_hex = hex::encode(call_id);

    // Create call offer data
    let offer_data = b"call_offer".to_vec(); // Simplified - real implementation would have capabilities

    // Send call signal via daemon
    let cmd = DaemonCommand::SendCallSignal {
        to: request.to.clone(),
        call_id,
        signal_type: CallSignalType::Offer,
        data: offer_data,
    };

    if let Err(e) = daemon.command_sender().send(cmd).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to send call signal: {}", e)),
            }),
        );
    }

    info!(call_id = %call_id_hex, to = %request.to, "Call initiated");

    (
        StatusCode::OK,
        Json(ApiResponse::ok(CallResponse {
            call_id: call_id_hex,
            peer_address: request.to,
            status: "calling".to_string(),
        })),
    )
}

/// Answer an incoming call
pub async fn answer_call(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(request): Json<CallActionRequest>,
) -> (StatusCode, Json<ApiResponse<CallResponse>>) {
    let (user_id, _, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    // Parse call ID
    let _call_id: [u8; 16] = match hex::decode(&request.call_id) {
        Ok(bytes) if bytes.len() == 16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid call ID".to_string()),
                }),
            );
        }
    };

    // Get daemon
    let daemons = state.daemons.lock().await;
    let _daemon = match daemons.get(&user_id) {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("P2P daemon not running".to_string()),
                }),
            );
        }
    };
    drop(daemons);

    // TODO: Look up caller address from pending calls
    // For now, return success
    info!(call_id = %request.call_id, "Call answered");

    (
        StatusCode::OK,
        Json(ApiResponse::ok(CallResponse {
            call_id: request.call_id,
            peer_address: "unknown".to_string(),
            status: "connected".to_string(),
        })),
    )
}

/// Hang up a call
pub async fn hangup_call(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(request): Json<CallActionRequest>,
) -> (StatusCode, Json<ApiResponse<CallResponse>>) {
    let (_user_id, _, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    info!(call_id = %request.call_id, "Call ended");

    (
        StatusCode::OK,
        Json(ApiResponse::ok(CallResponse {
            call_id: request.call_id,
            peer_address: "unknown".to_string(),
            status: "ended".to_string(),
        })),
    )
}

// ==================== Diagnostic API ====================

/// Request to test connectivity
#[derive(Debug, serde::Deserialize)]
pub struct TestConnectivityRequest {
    /// Target onion address to test
    pub address: String,
}

/// Connectivity test result
#[derive(Debug, serde::Serialize)]
pub struct ConnectivityResult {
    pub address: String,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// Test connectivity to an onion address via Tor
pub async fn test_connectivity(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(request): Json<TestConnectivityRequest>,
) -> (StatusCode, Json<ApiResponse<ConnectivityResult>>) {
    let (user_id, _, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    info!(user_id, address = %request.address, "Testing connectivity to peer");

    // Parse and validate address
    let peer_addr = match torchat_core::identity::OnionAddress::from_string(&request.address) {
        Ok(addr) => addr,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::ok(ConnectivityResult {
                    address: request.address,
                    reachable: false,
                    latency_ms: None,
                    error: Some("Invalid onion address format".to_string()),
                })),
            );
        }
    };

    // Try to connect via Tor
    let tor_config = torchat_core::tor::TorConnectionConfig::default();
    let start = std::time::Instant::now();

    match tokio::time::timeout(
        std::time::Duration::from_secs(60),
        torchat_core::tor::TorConnection::connect(&tor_config, &peer_addr)
    ).await {
        Ok(Ok(_conn)) => {
            let latency = start.elapsed().as_millis() as u64;
            info!(address = %request.address, latency_ms = latency, "Connectivity test successful");
            (
                StatusCode::OK,
                Json(ApiResponse::ok(ConnectivityResult {
                    address: request.address,
                    reachable: true,
                    latency_ms: Some(latency),
                    error: None,
                })),
            )
        }
        Ok(Err(e)) => {
            warn!(address = %request.address, error = %e, "Connectivity test failed");
            (
                StatusCode::OK,
                Json(ApiResponse::ok(ConnectivityResult {
                    address: request.address,
                    reachable: false,
                    latency_ms: None,
                    error: Some(format!("Connection failed: {}", e)),
                })),
            )
        }
        Err(_) => {
            warn!(address = %request.address, "Connectivity test timed out");
            (
                StatusCode::OK,
                Json(ApiResponse::ok(ConnectivityResult {
                    address: request.address,
                    reachable: false,
                    latency_ms: None,
                    error: Some("Connection timed out (60s)".to_string()),
                })),
            )
        }
    }
}

// ========================================
// Group Chat API Endpoints
// ========================================

/// Create a new group
pub async fn create_group(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateGroupRequest>,
) -> (StatusCode, Json<ApiResponse<GroupInfo>>) {
    let session_token = match extract_session_token(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("No session token".to_string()),
                }),
            );
        }
    };

    let db = state.database.lock().await;
    let (user_id, identity, _display_name) = match db.get_user_by_session(&session_token) {
        Ok(Some(user)) => user,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid session".to_string()),
                }),
            );
        }
    };
    drop(db);

    let daemons = state.daemons.lock().await;
    let daemon = match daemons.get(&user_id) {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Daemon not running".to_string()),
                }),
            );
        }
    };
    drop(daemons);

    let policy = torchat_core::protocol::GroupPolicy {
        blind_membership: request.blind_membership.unwrap_or(false),
        max_size: request.max_size.unwrap_or(50),
        allow_member_invite: false,
        key_rotation_interval: 86400,
        address_rotation_enabled: false,
    };

    use torchat_core::messaging::DaemonCommand;
    if let Err(e) = daemon.command_sender().send(DaemonCommand::CreateGroup {
        name: request.name.clone(),
        policy: policy.clone(),
    }).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to create group: {}", e)),
            }),
        );
    }

    let group_id_bytes = torchat_core::crypto::generate_group_id(
        &request.name,
        &identity.public_key().to_bytes(),
    );

    info!(name = %request.name, user_id, "Created group");

    (
        StatusCode::OK,
        Json(ApiResponse::ok(GroupInfo {
            group_id: hex::encode(group_id_bytes),
            name: request.name,
            member_count: 1,
            state: "Active".to_string(),
            is_founder: true,
            role: "founder".to_string(),
        })),
    )
}

/// Send group invite
pub async fn send_group_invite(
    headers: HeaderMap,
    Path(group_id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(request): Json<SendInviteRequest>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    let session_token = match extract_session_token(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("No session token".to_string()),
                }),
            );
        }
    };

    let db = state.database.lock().await;
    let (user_id, identity, _display_name) = match db.get_user_by_session(&session_token) {
        Ok(Some(user)) => user,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid session".to_string()),
                }),
            );
        }
    };

    if let Err(e) = validate_onion_address(&request.invitee_onion) {
        drop(db);
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Invalid onion address: {}", e)),
            }),
        );
    }

    let group_id_bytes = match hex::decode(&group_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            drop(db);
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid group ID format".to_string()),
                }),
            );
        }
    };

    // Check if the current user is the founder or an admin
    let our_pubkey = identity.public_key().to_bytes();
    let our_member_id = torchat_core::crypto::generate_member_id(&group_id_bytes, &our_pubkey);

    let is_founder = db.load_group_metadata(&group_id_bytes)
        .ok()
        .flatten()
        .map(|(_, fp, _, _, _, _, _)| fp == our_pubkey)
        .unwrap_or(false);

    let is_admin = db.load_group_members(&group_id_bytes)
        .unwrap_or_default()
        .iter()
        .any(|m| m.member_id == our_member_id && m.is_admin);

    if !is_founder && !is_admin {
        drop(db);
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Only the founder or admins can invite members".to_string()),
            }),
        );
    }

    drop(db);

    let daemons = state.daemons.lock().await;
    let daemon = match daemons.get(&user_id) {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Daemon not running".to_string()),
                }),
            );
        }
    };
    drop(daemons);

    use torchat_core::messaging::DaemonCommand;
    if let Err(e) = daemon.command_sender().send(DaemonCommand::SendGroupInvite {
        group_id: group_id_bytes,
        invitee_onion: request.invitee_onion.clone(),
        expires_at: chrono::Utc::now().timestamp() + 86400, // 24 hours
    }).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to send invite: {}", e)),
            }),
        );
    }

    info!(group_id, invitee = %request.invitee_onion, "Sent group invite");

    (
        StatusCode::OK,
        Json(ApiResponse::ok("Invite sent successfully".to_string())),
    )
}

/// Join a group via invite
pub async fn join_group(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(request): Json<JoinGroupRequest>,
) -> (StatusCode, Json<ApiResponse<GroupInfo>>) {
    let session_token = match extract_session_token(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("No session token".to_string()),
                }),
            );
        }
    };

    let db = state.database.lock().await;
    let (user_id, _identity, _display_name) = match db.get_user_by_session(&session_token) {
        Ok(Some(user)) => user,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid session".to_string()),
                }),
            );
        }
    };
    drop(db);

    let invite_bytes = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &request.invite_token,
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(format!("Invalid invite token: {}", e)),
                }),
            );
        }
    };

    let invite: torchat_core::protocol::GroupInvitePayload = match bincode::deserialize(&invite_bytes) {
        Ok(inv) => inv,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some(format!("Invalid invite format: {}", e)),
                }),
            );
        }
    };

    let daemons = state.daemons.lock().await;
    let daemon = match daemons.get(&user_id) {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Daemon not running".to_string()),
                }),
            );
        }
    };
    drop(daemons);

    use torchat_core::messaging::DaemonCommand;
    if let Err(e) = daemon.command_sender().send(DaemonCommand::JoinGroup {
        invite: invite.clone(),
    }).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to join group: {}", e)),
            }),
        );
    }

    info!(group_id = ?invite.group_id, "Joined group");

    (
        StatusCode::OK,
        Json(ApiResponse::ok(GroupInfo {
            group_id: hex::encode(invite.group_id),
            name: "Group".to_string(),
            member_count: 0,
            state: "Active".to_string(),
            is_founder: false,
            role: "member".to_string(),
        })),
    )
}

/// List user's groups
pub async fn list_groups(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<Vec<GroupInfo>>>) {
    let session_token = match extract_session_token(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("No session token".to_string()),
                }),
            );
        }
    };

    let db = state.database.lock().await;
    let (user_id, identity, _display_name) = match db.get_user_by_session(&session_token) {
        Ok(Some(user)) => user,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid session".to_string()),
                }),
            );
        }
    };

    let our_pubkey = identity.public_key().to_bytes();

    let groups = match db.list_groups() {
        Ok(groups) => groups,
        Err(e) => {
            warn!(user_id, error = %e, "Failed to list groups");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Failed to list groups".to_string()),
                }),
            );
        }
    };

    let group_infos: Vec<GroupInfo> = groups
        .into_iter()
        .map(|(group_id, name, founder_pubkey, state)| {
            let state_str = match state {
                torchat_core::messaging::GroupState::Active => "Active",
                torchat_core::messaging::GroupState::Archived => "Archived",
            };

            let member_count = db.count_group_members(&group_id).unwrap_or(0);
            // Ensure at least 1 member (the founder) even if members table is empty
            let member_count = if member_count == 0 { 1 } else { member_count };

            let is_founder = our_pubkey == founder_pubkey;

            // Determine role: check if we're founder, admin, or regular member
            let our_member_id = torchat_core::crypto::generate_member_id(&group_id, &our_pubkey);
            let members = db.load_group_members(&group_id).unwrap_or_default();
            let is_admin = members.iter().any(|m| m.member_id == our_member_id && m.is_admin);

            let role = if is_founder {
                "founder".to_string()
            } else if is_admin {
                "admin".to_string()
            } else {
                "member".to_string()
            };

            GroupInfo {
                group_id: hex::encode(group_id),
                name,
                member_count,
                state: state_str.to_string(),
                is_founder,
                role,
            }
        })
        .collect();

    (StatusCode::OK, Json(ApiResponse::ok(group_infos)))
}

/// Send message to group
pub async fn send_group_message(
    headers: HeaderMap,
    Path(group_id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(request): Json<SendGroupMessageRequest>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    let session_token = match extract_session_token(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("No session token".to_string()),
                }),
            );
        }
    };

    let db = state.database.lock().await;
    let (user_id, _identity, _display_name) = match db.get_user_by_session(&session_token) {
        Ok(Some(user)) => user,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid session".to_string()),
                }),
            );
        }
    };
    drop(db);

    let group_id_bytes = match hex::decode(&group_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid group ID format".to_string()),
                }),
            );
        }
    };

    let daemons = state.daemons.lock().await;
    let daemon = match daemons.get(&user_id) {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Daemon not running".to_string()),
                }),
            );
        }
    };
    drop(daemons);

    use torchat_core::messaging::DaemonCommand;
    if let Err(e) = daemon.command_sender().send(DaemonCommand::SendGroupMessage {
        group_id: group_id_bytes,
        content: request.content.clone(),
        disappear_after: request.disappear_after,
    }).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to send message: {}", e)),
            }),
        );
    }

    info!(group_id, user_id, "Sent group message");

    (
        StatusCode::OK,
        Json(ApiResponse::ok("Message sent".to_string())),
    )
}

/// Get group messages
pub async fn get_group_messages(
    headers: HeaderMap,
    Path(group_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<Vec<GroupMessageInfo>>>) {
    let session_token = match extract_session_token(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("No session token".to_string()),
                }),
            );
        }
    };

    let db = state.database.lock().await;
    let (user_id, identity, _display_name) = match db.get_user_by_session(&session_token) {
        Ok(Some(user)) => user,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid session".to_string()),
                }),
            );
        }
    };

    let group_id_bytes = match hex::decode(&group_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid group ID format".to_string()),
                }),
            );
        }
    };

    // Compute our member_id to determine which messages are outgoing
    let our_pubkey = identity.public_key().to_bytes();
    let our_member_id = torchat_core::crypto::generate_member_id(&group_id_bytes, &our_pubkey);

    let messages = match db.load_group_messages(&group_id_bytes, 100) {
        Ok(msgs) => msgs,
        Err(e) => {
            warn!(user_id, group_id, error = %e, "Failed to load group messages");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Failed to load messages".to_string()),
                }),
            );
        }
    };

    let message_infos: Vec<GroupMessageInfo> = messages
        .into_iter()
        .map(|msg| {
            let is_outgoing = msg.sender_id == our_member_id;
            GroupMessageInfo {
                message_id: hex::encode(msg.id),
                sender_id: hex::encode(msg.sender_id),
                content: msg.content,
                timestamp: msg.timestamp,
                outgoing: is_outgoing,
                disappear_after: msg.disappear_after,
            }
        })
        .collect();

    (StatusCode::OK, Json(ApiResponse::ok(message_infos)))
}

/// Leave a group
pub async fn leave_group(
    headers: HeaderMap,
    Path(group_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    let session_token = match extract_session_token(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("No session token".to_string()),
                }),
            );
        }
    };

    let db = state.database.lock().await;
    let (user_id, _identity, _display_name) = match db.get_user_by_session(&session_token) {
        Ok(Some(user)) => user,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid session".to_string()),
                }),
            );
        }
    };
    drop(db);

    let group_id_bytes = match hex::decode(&group_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid group ID format".to_string()),
                }),
            );
        }
    };

    let daemons = state.daemons.lock().await;
    let daemon = match daemons.get(&user_id) {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Daemon not running".to_string()),
                }),
            );
        }
    };
    drop(daemons);

    use torchat_core::messaging::DaemonCommand;
    if let Err(e) = daemon.command_sender().send(DaemonCommand::LeaveGroup {
        group_id: group_id_bytes,
    }).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to leave group: {}", e)),
            }),
        );
    }

    info!(group_id, user_id, "Left group");

    (
        StatusCode::OK,
        Json(ApiResponse::ok("Left group successfully".to_string())),
    )
}

// ============================================================================
// Pending Group Invites
// ============================================================================

/// List pending group invites for the current user
pub async fn list_pending_invites(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<Vec<PendingInviteInfo>>>) {
    let session_token = match extract_session_token(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("No session token".to_string()),
                }),
            );
        }
    };

    let db = state.database.lock().await;
    let (user_id, _identity, _display_name) = match db.get_user_by_session(&session_token) {
        Ok(Some(user)) => user,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid session".to_string()),
                }),
            );
        }
    };

    let invites = match db.list_pending_invites(user_id) {
        Ok(invites) => invites,
        Err(e) => {
            warn!(user_id, error = %e, "Failed to list pending invites");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Failed to list pending invites".to_string()),
                }),
            );
        }
    };

    let invite_infos: Vec<PendingInviteInfo> = invites
        .into_iter()
        .map(|inv| PendingInviteInfo {
            id: inv.id,
            group_id: hex::encode(&inv.group_id),
            group_name: inv.group_name,
            inviter_pubkey: hex::encode(&inv.inviter_pubkey),
            bootstrap_peer: inv.bootstrap_peer,
            expires_at: inv.expires_at,
            received_at: inv.received_at,
        })
        .collect();

    info!(user_id, count = invite_infos.len(), "Listed pending invites");

    (StatusCode::OK, Json(ApiResponse::ok(invite_infos)))
}

/// Accept a pending group invite
pub async fn accept_pending_invite(
    headers: HeaderMap,
    Path(invite_id): Path<i64>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<GroupInfo>>) {
    let session_token = match extract_session_token(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("No session token".to_string()),
                }),
            );
        }
    };

    let db = state.database.lock().await;
    let (user_id, identity, _display_name) = match db.get_user_by_session(&session_token) {
        Ok(Some(user)) => user,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid session".to_string()),
                }),
            );
        }
    };

    // Get the pending invite
    let pending_invite = match db.get_pending_invite(invite_id) {
        Ok(Some(inv)) => inv,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invite not found".to_string()),
                }),
            );
        }
        Err(e) => {
            warn!(user_id, invite_id, error = %e, "Failed to get pending invite");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Failed to get invite".to_string()),
                }),
            );
        }
    };

    // Check if invite has expired
    let now = chrono::Utc::now().timestamp();
    if now > pending_invite.expires_at {
        // Mark as expired
        let _ = db.update_pending_invite_status(invite_id, "expired");
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invite has expired".to_string()),
            }),
        );
    }

    // Deserialize the invite payload
    let invite: torchat_core::protocol::GroupInvitePayload = match bincode::deserialize(&pending_invite.invite_payload) {
        Ok(inv) => inv,
        Err(e) => {
            warn!(user_id, invite_id, error = %e, "Failed to deserialize invite payload");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid invite data".to_string()),
                }),
            );
        }
    };

    let group_name = pending_invite.group_name.unwrap_or_else(|| "Group".to_string());

    // Store a preliminary group record so it appears in the groups list immediately
    let our_pubkey = identity.public_key().to_bytes();
    let our_member_id = torchat_core::crypto::generate_member_id(&invite.group_id, &our_pubkey);

    // Check if this member has been banned from the group
    match db.is_member_banned(&invite.group_id, &our_member_id) {
        Ok(true) => {
            return (
                StatusCode::FORBIDDEN,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("You have been banned from this group".to_string()),
                }),
            );
        }
        Err(e) => {
            warn!(user_id, invite_id, error = %e, "Failed to check ban status");
            // Continue anyway - don't block join on check failure
        }
        _ => {}
    }

    if let Err(e) = db.store_preliminary_group(&invite.group_id, &group_name, &invite.inviter_pubkey, &our_member_id) {
        warn!(user_id, invite_id, error = %e, "Failed to store preliminary group record");
    }

    // Store ourselves as a member
    let our_member = torchat_core::protocol::GroupMember {
        member_id: our_member_id,
        onion_address: Some(identity.onion_address().to_string()),
        pubkey: our_pubkey,
        is_admin: false,
        joined_at: now,
    };
    if let Err(e) = db.store_group_member(&invite.group_id, &our_member) {
        warn!(user_id, invite_id, error = %e, "Failed to store self as group member");
    }

    // Store the founder/inviter as a member
    let founder_member_id = torchat_core::crypto::generate_member_id(&invite.group_id, &invite.inviter_pubkey);
    let founder_member = torchat_core::protocol::GroupMember {
        member_id: founder_member_id,
        onion_address: Some(invite.bootstrap_peer.clone()),
        pubkey: invite.inviter_pubkey,
        is_admin: true,
        joined_at: now,
    };
    if let Err(e) = db.store_group_member(&invite.group_id, &founder_member) {
        warn!(user_id, invite_id, error = %e, "Failed to store founder as group member");
    }

    drop(db); // Release the database lock before sending command

    // Get the daemon
    let daemons = state.daemons.lock().await;
    let daemon = match daemons.get(&user_id) {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Daemon not running".to_string()),
                }),
            );
        }
    };
    drop(daemons);

    // Send JoinGroup command to daemon
    use torchat_core::messaging::DaemonCommand;
    if let Err(e) = daemon.command_sender().send(DaemonCommand::JoinGroup {
        invite: invite.clone(),
    }).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to join group: {}", e)),
            }),
        );
    }

    // Mark the invite as accepted
    let db = state.database.lock().await;
    if let Err(e) = db.update_pending_invite_status(invite_id, "accepted") {
        warn!(user_id, invite_id, error = %e, "Failed to update invite status");
    }

    info!(user_id, invite_id, group_id = ?invite.group_id, "Accepted group invite");

    (
        StatusCode::OK,
        Json(ApiResponse::ok(GroupInfo {
            group_id: hex::encode(invite.group_id),
            name: group_name,
            member_count: 2,
            state: "Active".to_string(),
            is_founder: false,
            role: "member".to_string(),
        })),
    )
}

/// Decline a pending group invite
pub async fn decline_pending_invite(
    headers: HeaderMap,
    Path(invite_id): Path<i64>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    let session_token = match extract_session_token(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("No session token".to_string()),
                }),
            );
        }
    };

    let db = state.database.lock().await;
    let (user_id, _identity, _display_name) = match db.get_user_by_session(&session_token) {
        Ok(Some(user)) => user,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid session".to_string()),
                }),
            );
        }
    };

    // Get the pending invite to verify it exists
    match db.get_pending_invite(invite_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invite not found".to_string()),
                }),
            );
        }
        Err(e) => {
            warn!(user_id, invite_id, error = %e, "Failed to get pending invite");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Failed to get invite".to_string()),
                }),
            );
        }
    };

    // Mark as declined
    if let Err(e) = db.update_pending_invite_status(invite_id, "declined") {
        warn!(user_id, invite_id, error = %e, "Failed to decline invite");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Failed to decline invite".to_string()),
            }),
        );
    }

    info!(user_id, invite_id, "Declined group invite");

    (
        StatusCode::OK,
        Json(ApiResponse::ok("Invite declined".to_string())),
    )
}

// ==========================================
// Group Member Management Endpoints
// ==========================================

/// List members of a group
pub async fn list_group_members(
    headers: HeaderMap,
    Path(group_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<Vec<GroupMemberInfo>>>) {
    let session_token = match extract_session_token(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("No session token".to_string()),
                }),
            );
        }
    };

    let db = state.database.lock().await;
    let (user_id, _identity, _display_name) = match db.get_user_by_session(&session_token) {
        Ok(Some(user)) => user,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid session".to_string()),
                }),
            );
        }
    };

    let group_id_bytes = match hex::decode(&group_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid group ID format".to_string()),
                }),
            );
        }
    };

    let members = match db.load_group_members(&group_id_bytes) {
        Ok(members) => members,
        Err(e) => {
            warn!(user_id, error = %e, "Failed to list group members");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Failed to list group members".to_string()),
                }),
            );
        }
    };

    // Also get the founder pubkey to determine who is the founder
    let founder_pubkey = db.load_group_metadata(&group_id_bytes)
        .ok()
        .flatten()
        .map(|(_, fp, _, _, _, _, _)| fp);

    let member_infos: Vec<GroupMemberInfo> = members
        .into_iter()
        .map(|m| {
            let is_founder = founder_pubkey
                .as_ref()
                .map(|fp| *fp == m.pubkey)
                .unwrap_or(false);

            let role = if is_founder {
                "founder".to_string()
            } else if m.is_admin {
                "admin".to_string()
            } else {
                "member".to_string()
            };

            GroupMemberInfo {
                member_id: hex::encode(m.member_id),
                onion_address: m.onion_address,
                is_admin: m.is_admin,
                joined_at: m.joined_at,
                role,
            }
        })
        .collect();

    (StatusCode::OK, Json(ApiResponse::ok(member_infos)))
}

/// Promote a group member to admin (founder only)
pub async fn promote_member(
    headers: HeaderMap,
    Path(group_id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(request): Json<PromoteMemberRequest>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    let session_token = match extract_session_token(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("No session token".to_string()),
                }),
            );
        }
    };

    let db = state.database.lock().await;
    let (user_id, identity, _display_name) = match db.get_user_by_session(&session_token) {
        Ok(Some(user)) => user,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid session".to_string()),
                }),
            );
        }
    };

    let group_id_bytes = match hex::decode(&group_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid group ID format".to_string()),
                }),
            );
        }
    };

    let member_id_bytes = match hex::decode(&request.member_id) {
        Ok(bytes) if bytes.len() == 16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid member ID format".to_string()),
                }),
            );
        }
    };

    // Verify the current user is the founder
    let our_pubkey = identity.public_key().to_bytes();
    let group_meta = match db.load_group_metadata(&group_id_bytes) {
        Ok(Some(meta)) => meta,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Group not found".to_string()),
                }),
            );
        }
        Err(e) => {
            warn!(user_id, error = %e, "Failed to load group metadata");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Failed to load group".to_string()),
                }),
            );
        }
    };

    let founder_pubkey = group_meta.1; // founder_pubkey is the second element
    if our_pubkey != founder_pubkey {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Only the group founder can promote members to admin".to_string()),
            }),
        );
    }

    drop(db);

    // Send promote command to daemon
    let daemons = state.daemons.lock().await;
    let daemon = match daemons.get(&user_id) {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Daemon not running".to_string()),
                }),
            );
        }
    };
    drop(daemons);

    use torchat_core::messaging::DaemonCommand;
    if let Err(e) = daemon.command_sender().send(DaemonCommand::PromoteToAdmin {
        group_id: group_id_bytes,
        member_id: member_id_bytes,
    }).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to promote member: {}", e)),
            }),
        );
    }

    info!(group_id, member_id = %request.member_id, "Promoted member to admin");

    (
        StatusCode::OK,
        Json(ApiResponse::ok("Member promoted to admin".to_string())),
    )
}

/// Remove or ban a member from a group
pub async fn remove_member(
    headers: HeaderMap,
    Path(group_id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(request): Json<RemoveMemberRequest>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    let session_token = match extract_session_token(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("No session token".to_string()),
                }),
            );
        }
    };

    let db = state.database.lock().await;
    let (user_id, identity, _display_name) = match db.get_user_by_session(&session_token) {
        Ok(Some(user)) => user,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid session".to_string()),
                }),
            );
        }
    };

    let group_id_bytes = match hex::decode(&group_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid group ID format".to_string()),
                }),
            );
        }
    };

    let target_member_id = match hex::decode(&request.member_id) {
        Ok(bytes) if bytes.len() == 16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid member ID format".to_string()),
                }),
            );
        }
    };

    // Permission checks
    let our_pubkey = identity.public_key().to_bytes();
    let group_meta = match db.load_group_metadata(&group_id_bytes) {
        Ok(Some(meta)) => meta,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Group not found".to_string()),
                }),
            );
        }
        Err(e) => {
            warn!(user_id, error = %e, "Failed to load group metadata");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Failed to load group".to_string()),
                }),
            );
        }
    };

    let founder_pubkey = group_meta.1;
    let is_founder = our_pubkey == founder_pubkey;
    let our_member_id = torchat_core::crypto::generate_member_id(&group_id_bytes, &our_pubkey);

    // Cannot remove yourself - use leave instead
    if target_member_id == our_member_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Cannot remove yourself. Use 'Leave Group' instead.".to_string()),
            }),
        );
    }

    // Check caller permissions
    let is_admin = db.load_group_members(&group_id_bytes)
        .unwrap_or_default()
        .iter()
        .any(|m| m.member_id == our_member_id && m.is_admin);

    if !is_founder && !is_admin {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Only founders and admins can remove members".to_string()),
            }),
        );
    }

    // Admins cannot remove other admins or the founder
    if !is_founder {
        let target_is_founder = {
            let founder_member_id = torchat_core::crypto::generate_member_id(&group_id_bytes, &founder_pubkey);
            target_member_id == founder_member_id
        };
        let target_is_admin = db.load_group_members(&group_id_bytes)
            .unwrap_or_default()
            .iter()
            .any(|m| m.member_id == target_member_id && m.is_admin);

        if target_is_founder || target_is_admin {
            return (
                StatusCode::FORBIDDEN,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Admins can only remove regular members".to_string()),
                }),
            );
        }
    }

    drop(db);

    // Send command to daemon
    let daemons = state.daemons.lock().await;
    let daemon = match daemons.get(&user_id) {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Daemon not running".to_string()),
                }),
            );
        }
    };
    drop(daemons);

    use torchat_core::messaging::DaemonCommand;
    let is_ban = request.ban.unwrap_or(false);

    let cmd = if is_ban {
        DaemonCommand::BanMember {
            group_id: group_id_bytes,
            member_id: target_member_id,
            reason: request.reason.clone(),
        }
    } else {
        DaemonCommand::RemoveMember {
            group_id: group_id_bytes,
            member_id: target_member_id,
        }
    };

    if let Err(e) = daemon.command_sender().send(cmd).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to remove member: {}", e)),
            }),
        );
    }

    let msg = if is_ban { "Member banned" } else { "Member removed" };
    info!(group_id, member_id = %request.member_id, action = msg, "Member action completed");

    (StatusCode::OK, Json(ApiResponse::ok(msg.to_string())))
}

/// List banned members for a group
pub async fn list_group_bans(
    headers: HeaderMap,
    Path(group_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<Vec<BanInfo>>>) {
    let session_token = match extract_session_token(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("No session token".to_string()),
                }),
            );
        }
    };

    let db = state.database.lock().await;
    let (_user_id, identity, _display_name) = match db.get_user_by_session(&session_token) {
        Ok(Some(user)) => user,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid session".to_string()),
                }),
            );
        }
    };

    let group_id_bytes = match hex::decode(&group_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid group ID format".to_string()),
                }),
            );
        }
    };

    // Check caller is founder or admin
    let our_pubkey = identity.public_key().to_bytes();
    let our_member_id = torchat_core::crypto::generate_member_id(&group_id_bytes, &our_pubkey);
    let group_meta = match db.load_group_metadata(&group_id_bytes) {
        Ok(Some(meta)) => meta,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse { success: false, data: None, error: Some("Group not found".to_string()) }),
            );
        }
    };
    let is_founder = our_pubkey == group_meta.1;
    let is_admin = db.load_group_members(&group_id_bytes)
        .unwrap_or_default()
        .iter()
        .any(|m| m.member_id == our_member_id && m.is_admin);

    if !is_founder && !is_admin {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse { success: false, data: None, error: Some("Only founders and admins can view bans".to_string()) }),
        );
    }

    match db.list_group_bans(&group_id_bytes) {
        Ok(bans) => {
            let ban_infos: Vec<BanInfo> = bans
                .into_iter()
                .map(|b| BanInfo {
                    member_id: hex::encode(b.member_id),
                    reason: b.reason,
                    banned_at: b.banned_at,
                })
                .collect();
            (StatusCode::OK, Json(ApiResponse::ok(ban_infos)))
        }
        Err(e) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse { success: false, data: None, error: Some(format!("Failed to list bans: {}", e)) }),
            )
        }
    }
}

/// Unban a member from a group
pub async fn unban_member(
    headers: HeaderMap,
    Path(group_id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(request): Json<UnbanMemberRequest>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    let session_token = match extract_session_token(&headers) {
        Some(token) => token,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse { success: false, data: None, error: Some("No session token".to_string()) }),
            );
        }
    };

    let db = state.database.lock().await;
    let (_user_id, identity, _display_name) = match db.get_user_by_session(&session_token) {
        Ok(Some(user)) => user,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse { success: false, data: None, error: Some("Invalid session".to_string()) }),
            );
        }
    };

    let group_id_bytes = match hex::decode(&group_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse { success: false, data: None, error: Some("Invalid group ID format".to_string()) }),
            );
        }
    };

    let member_id_bytes = match hex::decode(&request.member_id) {
        Ok(bytes) if bytes.len() == 16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse { success: false, data: None, error: Some("Invalid member ID format".to_string()) }),
            );
        }
    };

    // Only founder can unban
    let our_pubkey = identity.public_key().to_bytes();
    let group_meta = match db.load_group_metadata(&group_id_bytes) {
        Ok(Some(meta)) => meta,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse { success: false, data: None, error: Some("Group not found".to_string()) }),
            );
        }
    };

    if our_pubkey != group_meta.1 {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse { success: false, data: None, error: Some("Only the founder can unban members".to_string()) }),
        );
    }

    match db.unban_group_member(&group_id_bytes, &member_id_bytes) {
        Ok(()) => {
            info!(group_id, member_id = %request.member_id, "Unbanned member");
            (StatusCode::OK, Json(ApiResponse::ok("Member unbanned".to_string())))
        }
        Err(e) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse { success: false, data: None, error: Some(format!("Failed to unban: {}", e)) }),
            )
        }
    }
}

// ==========================================
// Group File Transfer Endpoints
// ==========================================

/// Upload and share a file in a group chat
pub async fn send_group_file_multipart(
    headers: HeaderMap,
    Path(group_id): Path<String>,
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> (StatusCode, Json<ApiResponse<FileTransferResponse>>) {
    let (user_id, _identity, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    // Parse group_id
    let group_id_bytes = match hex::decode(&group_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid group ID".to_string()),
                }),
            );
        }
    };

    // Get daemon
    let daemons = state.daemons.lock().await;
    let daemon = match daemons.get(&user_id) {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Daemon not running".to_string()),
                }),
            );
        }
    };
    drop(daemons);

    let mut filename: Option<String> = None;
    let mut file_data: Option<Vec<u8>> = None;

    // Process multipart fields
    while let Ok(Some(field)) = multipart.next_field().await {
        let field_name: String = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "filename" => {
                if let Ok(value) = field.text().await {
                    filename = Some(value);
                }
            }
            "file" => {
                if filename.is_none() {
                    filename = field.file_name().map(|s: &str| s.to_string());
                }
                match field.bytes().await {
                    Ok(bytes) => {
                        file_data = Some(bytes.to_vec());
                    }
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(ApiResponse {
                                success: false,
                                data: None,
                                error: Some(format!("Failed to read file data: {}", e)),
                            }),
                        );
                    }
                }
            }
            _ => {}
        }
    }

    let filename = match filename {
        Some(name) => name,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Missing filename".to_string()),
                }),
            );
        }
    };

    let file_data = match file_data {
        Some(data) => data,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Missing file data".to_string()),
                }),
            );
        }
    };

    if file_data.len() as u64 > MAX_FILE_SIZE {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some("File size exceeds 5GB limit".to_string()),
            }),
        );
    }

    let file_size = file_data.len() as u64;

    // Save to temp file
    let temp_dir = std::env::temp_dir();
    let temp_filename = format!("torchat_group_upload_{}", uuid::Uuid::new_v4());
    let temp_path = temp_dir.join(&temp_filename);

    if let Err(e) = std::fs::write(&temp_path, &file_data) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to save file: {}", e)),
            }),
        );
    }

    // Send command to daemon
    use torchat_core::messaging::DaemonCommand;
    if let Err(e) = daemon.command_sender().send(DaemonCommand::SendGroupFile {
        group_id: group_id_bytes,
        file_path: temp_path,
        filename: filename.clone(),
    }).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to share file: {}", e)),
            }),
        );
    }

    info!(user_id, group_id = %group_id, filename = %filename, size = file_size, "Group file upload initiated");

    (
        StatusCode::OK,
        Json(ApiResponse::ok(FileTransferResponse {
            transfer_id: "group_upload".to_string(),
            filename,
            size: file_size,
            status: "sharing".to_string(),
            progress: 0.0,
        })),
    )
}

/// List files shared in a group
pub async fn list_group_files(
    headers: HeaderMap,
    Path(group_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<Vec<GroupFileInfo>>>) {
    let (user_id, identity, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    // Parse group_id
    let group_id_bytes = match hex::decode(&group_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid group ID".to_string()),
                }),
            );
        }
    };

    let db = state.database.lock().await;
    let files = match db.load_group_files(&group_id_bytes, 100) {
        Ok(f) => f,
        Err(e) => {
            warn!(user_id, error = %e, "Failed to load group files");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Failed to load files".to_string()),
                }),
            );
        }
    };

    let our_onion = identity.onion_address().to_string();
    let file_infos: Vec<GroupFileInfo> = files.iter().map(|f| {
        GroupFileInfo {
            file_id: f.file_id.clone(),
            filename: f.filename.clone(),
            size: f.file_size,
            sender_id: hex::encode(f.sender_anon_id),
            sender_onion: f.sender_onion.clone(),
            status: f.status.clone(),
            shared_at: f.shared_at,
            is_ours: f.sender_onion == our_onion,
        }
    }).collect();

    (StatusCode::OK, Json(ApiResponse::ok(file_infos)))
}

/// Request download of a group file
pub async fn download_group_file(
    headers: HeaderMap,
    Path((group_id, file_id)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    let (user_id, _identity, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err((status, json)) => {
            return (status, Json(ApiResponse {
                success: false,
                data: None,
                error: json.0.error,
            }));
        }
    };

    let group_id_bytes = match hex::decode(&group_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Invalid group ID".to_string()),
                }),
            );
        }
    };

    // Look up file in database
    let db = state.database.lock().await;
    let file_record = match db.get_group_file(&file_id) {
        Ok(Some(f)) => f,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("File not found".to_string()),
                }),
            );
        }
        Err(e) => {
            warn!(user_id, error = %e, "Failed to get group file");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Database error".to_string()),
                }),
            );
        }
    };
    drop(db);

    // If already downloaded, return the local path
    if file_record.status == "downloaded" {
        if let Some(ref path) = file_record.local_path {
            if std::path::Path::new(path).exists() {
                return (
                    StatusCode::OK,
                    Json(ApiResponse::ok(format!("already_downloaded:{}", path))),
                );
            }
        }
    }

    // Get daemon to send download command
    let daemons = state.daemons.lock().await;
    let daemon = match daemons.get(&user_id) {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Daemon not running".to_string()),
                }),
            );
        }
    };
    drop(daemons);

    use torchat_core::messaging::DaemonCommand;
    if let Err(e) = daemon.command_sender().send(DaemonCommand::DownloadGroupFile {
        group_id: group_id_bytes,
        file_id: file_id.clone(),
        sender_onion: file_record.sender_onion.clone(),
    }).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to start download: {}", e)),
            }),
        );
    }

    info!(user_id, file_id = %file_id, "Group file download initiated");

    (
        StatusCode::OK,
        Json(ApiResponse::ok("Download started".to_string())),
    )
}

/// Serve a downloaded group file
pub async fn serve_group_file(
    headers: HeaderMap,
    Path((_group_id, file_id)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
) -> Response {
    let (_user_id, _identity, _) = match get_current_user(&headers, &state).await {
        Ok(user) => user,
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        }
    };

    // Look up file in database
    let db = state.database.lock().await;
    let file_record = match db.get_group_file(&file_id) {
        Ok(Some(f)) => f,
        _ => {
            return (StatusCode::NOT_FOUND, "File not found").into_response();
        }
    };
    drop(db);

    // Check if we have the file locally
    let local_path = match file_record.local_path {
        Some(ref p) if std::path::Path::new(p).exists() => p.clone(),
        _ => {
            return (StatusCode::NOT_FOUND, "File not available locally").into_response();
        }
    };

    // Read file and serve it
    let file_bytes = match tokio::fs::read(&local_path).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read file").into_response();
        }
    };

    // Determine content type from extension
    let content_type = match std::path::Path::new(&file_record.filename)
        .extension()
        .and_then(|ext| ext.to_str())
    {
        Some("pdf") => "application/pdf",
        Some("txt") => "text/plain",
        Some("html") | Some("htm") => "text/html",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("mp3") => "audio/mpeg",
        Some("wav") => "audio/wav",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        _ => "application/octet-stream",
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", file_record.filename),
        )
        .header(header::CONTENT_LENGTH, file_bytes.len().to_string())
        .body(Body::from(file_bytes))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Server error").into_response())
}

// ========================================
// WebSocket Real-Time Push
// ========================================

/// Query params for WebSocket authentication
#[derive(Debug, Deserialize)]
pub struct WsAuthParams {
    pub token: String,
}

/// WebSocket upgrade handler.
/// Authenticates via `?token=<session_token>` query parameter,
/// then subscribes to the user's daemon events and pushes JSON messages.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<WsAuthParams>,
    State(state): State<Arc<AppState>>,
) -> Response {
    // Authenticate the session token before upgrading
    let db = state.database.lock().await;
    let user_info = db.get_user_by_session(&params.token);
    drop(db);

    let (user_id, _identity, _display_name) = match user_info {
        Ok(Some(user)) => user,
        _ => {
            return (StatusCode::UNAUTHORIZED, "Invalid session token").into_response();
        }
    };

    ws.on_upgrade(move |socket| handle_ws_connection(socket, user_id, state))
}

/// Handle an established WebSocket connection.
/// Subscribes to the user's daemon broadcast channel and forwards events.
async fn handle_ws_connection(
    socket: WebSocket,
    user_id: i64,
    state: Arc<AppState>,
) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    // Try to get the daemon's event subscription
    let event_rx = {
        let daemons = state.daemons.lock().await;
        daemons.get(&user_id).map(|d| d.subscribe())
    };

    let mut event_rx = match event_rx {
        Some(rx) => rx,
        None => {
            // Daemon not running -- send an error event and close
            let error_event = WsEvent {
                event_type: "error".to_string(),
                data: serde_json::json!({ "message": "Daemon not running" }),
            };
            let _ = ws_tx.send(WsMessage::Text(
                serde_json::to_string(&error_event).unwrap_or_default().into(),
            )).await;
            let _ = ws_tx.close().await;
            return;
        }
    };

    // Send a "connected" event to confirm the WebSocket is live
    let connected_event = WsEvent {
        event_type: "connected".to_string(),
        data: serde_json::json!({ "user_id": user_id }),
    };
    if ws_tx.send(WsMessage::Text(
        serde_json::to_string(&connected_event).unwrap_or_default().into(),
    )).await.is_err() {
        return;
    }

    // Spawn a task to read from the client (handles close frames)
    let mut read_handle = tokio::spawn(async move {
        while let Some(msg) = ws_rx.next().await {
            match msg {
                Ok(WsMessage::Close(_)) | Err(_) => break,
                _ => {
                    // Client-to-server messages not used yet
                }
            }
        }
    });

    // Main loop: receive daemon events and push to WebSocket
    loop {
        tokio::select! {
            event_result = event_rx.recv() => {
                match event_result {
                    Ok(event) => {
                        if let Some(ws_event) = daemon_event_to_ws_event(event) {
                            let json = match serde_json::to_string(&ws_event) {
                                Ok(j) => j,
                                Err(_) => continue,
                            };
                            if ws_tx.send(WsMessage::Text(json.into())).await.is_err() {
                                break; // Client disconnected
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        // We fell behind; notify client to do a full refresh
                        let lag_event = WsEvent {
                            event_type: "lagged".to_string(),
                            data: serde_json::json!({ "missed": n }),
                        };
                        let _ = ws_tx.send(WsMessage::Text(
                            serde_json::to_string(&lag_event).unwrap_or_default().into(),
                        )).await;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        // Daemon stopped
                        let stopped = WsEvent {
                            event_type: "daemon_stopped".to_string(),
                            data: serde_json::json!({}),
                        };
                        let _ = ws_tx.send(WsMessage::Text(
                            serde_json::to_string(&stopped).unwrap_or_default().into(),
                        )).await;
                        break;
                    }
                }
            }
            _ = &mut read_handle => {
                // Client disconnected (read task finished)
                break;
            }
        }
    }

    let _ = ws_tx.close().await;
}

/// Convert a DaemonEvent to a WsEvent suitable for the browser.
/// Returns None for internal-only events that the frontend does not need.
fn daemon_event_to_ws_event(event: torchat_core::messaging::DaemonEvent) -> Option<WsEvent> {
    use torchat_core::messaging::DaemonEvent;

    match event {
        DaemonEvent::MessageReceived { from, message_id, content, timestamp } => Some(WsEvent {
            event_type: "message_received".to_string(),
            data: serde_json::json!({
                "from": from,
                "message_id": hex::encode(message_id),
                "content": content,
                "timestamp": timestamp,
            }),
        }),
        DaemonEvent::MessageDelivered { message_id } => Some(WsEvent {
            event_type: "message_delivered".to_string(),
            data: serde_json::json!({
                "message_id": hex::encode(message_id),
            }),
        }),
        DaemonEvent::MessageFailed { message_id, error } => Some(WsEvent {
            event_type: "message_failed".to_string(),
            data: serde_json::json!({
                "message_id": hex::encode(message_id),
                "error": error,
            }),
        }),
        DaemonEvent::GroupMessageReceived { group_id, sender_id, content, timestamp } => Some(WsEvent {
            event_type: "group_message_received".to_string(),
            data: serde_json::json!({
                "group_id": hex::encode(group_id),
                "sender_id": hex::encode(sender_id),
                "content": content,
                "timestamp": timestamp,
            }),
        }),
        DaemonEvent::GroupJoined { group_id, name } => Some(WsEvent {
            event_type: "group_joined".to_string(),
            data: serde_json::json!({
                "group_id": hex::encode(group_id),
                "name": name,
            }),
        }),
        DaemonEvent::GroupMemberJoined { group_id, member_id } => Some(WsEvent {
            event_type: "group_member_joined".to_string(),
            data: serde_json::json!({
                "group_id": hex::encode(group_id),
                "member_id": hex::encode(member_id),
            }),
        }),
        DaemonEvent::GroupMemberLeft { group_id, member_id } => Some(WsEvent {
            event_type: "group_member_left".to_string(),
            data: serde_json::json!({
                "group_id": hex::encode(group_id),
                "member_id": hex::encode(member_id),
            }),
        }),
        DaemonEvent::GroupInviteReceived { invite } => {
            let group_name = String::from_utf8(invite.encrypted_metadata.clone())
                .ok()
                .and_then(|s| s.split('|').next().map(|n| n.to_string()));
            Some(WsEvent {
                event_type: "group_invite_received".to_string(),
                data: serde_json::json!({
                    "group_id": hex::encode(invite.group_id),
                    "group_name": group_name,
                }),
            })
        },
        DaemonEvent::FileTransferCompleted { transfer_id, filename, from, size, .. } => Some(WsEvent {
            event_type: "file_received".to_string(),
            data: serde_json::json!({
                "transfer_id": hex::encode(transfer_id),
                "filename": filename,
                "from": from,
                "size": size,
            }),
        }),
        DaemonEvent::FileTransferFailed { transfer_id, error } => Some(WsEvent {
            event_type: "file_transfer_failed".to_string(),
            data: serde_json::json!({
                "transfer_id": hex::encode(transfer_id),
                "error": error,
            }),
        }),
        DaemonEvent::GroupFileShared { group_id, file_id, filename, size, sender_onion } => Some(WsEvent {
            event_type: "group_file_shared".to_string(),
            data: serde_json::json!({
                "group_id": hex::encode(group_id),
                "file_id": file_id,
                "filename": filename,
                "size": size,
                "sender_onion": sender_onion,
            }),
        }),
        DaemonEvent::GroupFileDownloaded { group_id, file_id, .. } => Some(WsEvent {
            event_type: "group_file_downloaded".to_string(),
            data: serde_json::json!({
                "group_id": hex::encode(group_id),
                "file_id": file_id,
            }),
        }),
        DaemonEvent::GroupFileDownloadFailed { group_id, file_id, error } => Some(WsEvent {
            event_type: "group_file_download_failed".to_string(),
            data: serde_json::json!({
                "group_id": hex::encode(group_id),
                "file_id": file_id,
                "error": error,
            }),
        }),
        DaemonEvent::PeerConnected { address } => Some(WsEvent {
            event_type: "peer_connected".to_string(),
            data: serde_json::json!({ "address": address }),
        }),
        DaemonEvent::PeerDisconnected { address } => Some(WsEvent {
            event_type: "peer_disconnected".to_string(),
            data: serde_json::json!({ "address": address }),
        }),
        DaemonEvent::Started { onion_address } => Some(WsEvent {
            event_type: "daemon_started".to_string(),
            data: serde_json::json!({ "onion_address": onion_address }),
        }),
        DaemonEvent::Stopped => Some(WsEvent {
            event_type: "daemon_stopped".to_string(),
            data: serde_json::json!({}),
        }),
        DaemonEvent::GroupCreated { group_id, name } => Some(WsEvent {
            event_type: "group_created".to_string(),
            data: serde_json::json!({
                "group_id": hex::encode(group_id),
                "name": name,
            }),
        }),
        // Internal events not relevant to the frontend
        DaemonEvent::AckReceived { .. }
        | DaemonEvent::Error { .. }
        | DaemonEvent::FileChunkReceived { .. }
        | DaemonEvent::FileOfferReceived { .. }
        | DaemonEvent::FileTransferStarted { .. }
        | DaemonEvent::CallSignalReceived { .. }
        | DaemonEvent::GroupInviteGenerated { .. }
        | DaemonEvent::GroupInviteSent { .. }
        | DaemonEvent::GroupKeyRotated { .. }
        | DaemonEvent::GroupJoinAcceptReady { .. }
        | DaemonEvent::GroupJoinAcceptReceived { .. } => None,
    }
}
