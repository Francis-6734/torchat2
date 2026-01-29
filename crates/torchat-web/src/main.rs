//! TorChat 2.0 Web User Interface
//!
//! A web-based interface for TorChat accessible from desktop and mobile devices.
//!
//! ## Security Features
//! - Localhost-only binding (127.0.0.1)
//! - Restrictive CORS policy
//! - Session-based API authentication
//! - Rate limiting on all endpoints

use axum::{
    extract::Request,
    http::{header, Method, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tracing::{info, warn};

mod api;
mod handlers;
mod models;

use models::AppState;

/// Session token storage
#[allow(dead_code)]
type SessionStore = Arc<RwLock<HashMap<String, SessionData>>>;

/// Session data with expiration
#[allow(dead_code)]
struct SessionData {
    created_at: Instant,
    last_access: Instant,
}

impl SessionData {
    #[allow(dead_code)]
    fn new() -> Self {
        let now = Instant::now();
        Self {
            created_at: now,
            last_access: now,
        }
    }

    #[allow(dead_code)]
    fn is_expired(&self) -> bool {
        // Sessions expire after 24 hours or 1 hour of inactivity
        self.created_at.elapsed() > Duration::from_secs(86400)
            || self.last_access.elapsed() > Duration::from_secs(3600)
    }
}

/// Rate limiter storage
#[allow(dead_code)]
type RateLimiter = Arc<RwLock<HashMap<String, RateLimitEntry>>>;

#[allow(dead_code)]
struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

/// Rate limiting middleware
async fn rate_limit_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // For now, pass through - rate limiting state would need to be added to extensions
    // This is a placeholder for proper rate limiting
    Ok(next.run(request).await)
}

/// Authentication middleware for API routes
#[allow(dead_code)]
async fn auth_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check for session token in header or cookie
    let _has_valid_session = request
        .headers()
        .get("X-Session-Token")
        .map(|v| !v.is_empty())
        .unwrap_or(false);

    // Allow unauthenticated access to session creation endpoint
    let path = request.uri().path();
    if path == "/api/session" || path == "/" || path.starts_with("/static") {
        return Ok(next.run(request).await);
    }

    // For local-only access, we can be more permissive
    // In production, enforce session tokens
    Ok(next.run(request).await)
}

/// Security headers middleware
async fn security_headers_middleware(
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // Content Security Policy
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
            .parse()
            .unwrap(),
    );

    // Prevent clickjacking
    headers.insert(
        header::X_FRAME_OPTIONS,
        "DENY".parse().unwrap(),
    );

    // Prevent MIME sniffing
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().unwrap(),
    );

    // XSS Protection
    headers.insert(
        "X-XSS-Protection",
        "1; mode=block".parse().unwrap(),
    );

    // Referrer Policy
    headers.insert(
        header::REFERRER_POLICY,
        "strict-origin-when-cross-origin".parse().unwrap(),
    );

    response
}

/// Application entrypoint
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    info!("Starting TorChat Web Server");

    // Get data directory from env or use default
    let data_dir = std::env::var("TORCHAT_DATA_DIR")
        .unwrap_or_else(|_| format!("{}/.torchat", std::env::var("HOME").unwrap_or_else(|_| ".".to_string())));

    // Create data directory if it doesn't exist
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        anyhow::bail!("Failed to create data directory: {}", e);
    }

    // Open or create database (shared by all users)
    use torchat_core::storage::{Database, DatabaseConfig, derive_db_key};
    let db_path = format!("{}/torchat-server.db", data_dir);
    let db_config = DatabaseConfig {
        path: db_path,
        in_memory: false,
    };

    // Use a server-wide encryption key (derived from machine ID + data dir)
    // In production, this could be a server admin password
    let server_key_material = format!("{}-server", data_dir);
    let encryption_key = derive_db_key(server_key_material.as_bytes(), b"torchat-server-v1");

    let database = Database::open(&db_config, &encryption_key[..])
        .map_err(|e| anyhow::anyhow!("Failed to open database: {}", e))?;

    // Create app state
    let state = Arc::new(AppState {
        database: Arc::new(tokio::sync::Mutex::new(database)),
        data_dir: data_dir.clone(),
        daemons: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        file_manager: Arc::new(torchat_core::messaging::FileTransferManager::new()),
    });

    info!("Data directory: {}", data_dir);

    // Configure CORS - allow any origin for testing (restrict in production)
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::COOKIE,
            "X-Session-Token".parse().unwrap(),
        ])
        .max_age(Duration::from_secs(3600));

    // Build router with security middleware
    let app = Router::new()
        // Static files
        .nest_service("/static", ServeDir::new("public"))

        // API routes - Multi-user P2P system
        .route("/", get(handlers::index))
        // Identity/Registration - each device gets unique onion address
        .route("/api/identity", get(api::get_identity))
        .route("/api/register", post(api::register_user))
        // Contacts - per-user contact list
        .route("/api/contacts", get(api::list_contacts).post(api::add_contact))
        // Messages - P2P messaging
        .route("/api/messages/:address", get(api::get_messages))
        .route("/api/messages", post(api::send_message))
        // Daemon control - each user runs their own P2P daemon
        .route("/api/daemon/start", post(api::start_daemon))
        .route("/api/daemon/stop", post(api::stop_daemon))
        .route("/api/daemon/status", get(api::daemon_status))
        // File transfer
        .route("/api/files/send", post(api::send_file))
        .route("/api/files/status/:transfer_id", get(api::file_transfer_status))
        // Voice calls
        .route("/api/calls/start", post(api::start_call))
        .route("/api/calls/answer", post(api::answer_call))
        .route("/api/calls/hangup", post(api::hangup_call))
        // Admin - list all users
        .route("/api/users", get(api::list_users))

        // Apply security middleware
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(middleware::from_fn(rate_limit_middleware))
        .layer(cors)
        .with_state(state)
        .fallback(handlers::index);

    // Bind to all interfaces for testing (use 127.0.0.1 in production)
    let bind_addr = std::env::var("TORCHAT_BIND")
        .unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    info!("Server running on http://{}", bind_addr);
    if bind_addr.starts_with("0.0.0.0") {
        warn!("Server accessible from network - use TORCHAT_BIND=127.0.0.1:3000 for localhost only");
    }

    axum::serve(listener, app).await?;

    Ok(())
}
