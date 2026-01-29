//! Database schema definitions.

/// Schema version for migrations.
pub const SCHEMA_VERSION: u32 = 2;

/// SQL to create the database schema.
pub const CREATE_SCHEMA: &str = r#"
-- Users table (supports multiple identities on same server)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_token TEXT NOT NULL UNIQUE,
    onion_address TEXT NOT NULL UNIQUE,
    secret_key BLOB NOT NULL,
    display_name TEXT,
    last_active INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_session ON users(session_token);
CREATE INDEX IF NOT EXISTS idx_users_onion ON users(onion_address);

-- Legacy identity table for backward compatibility
CREATE TABLE IF NOT EXISTS identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    secret_key BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

-- Contacts table (now linked to specific users)
CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    onion_address TEXT NOT NULL,
    identity_key BLOB,
    display_name TEXT,
    verified INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(user_id, onion_address)
);

CREATE INDEX IF NOT EXISTS idx_contacts_user ON contacts(user_id);
CREATE INDEX IF NOT EXISTS idx_contacts_onion ON contacts(onion_address);

-- Sessions table (ratchet state)
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    session_id BLOB NOT NULL UNIQUE,
    ratchet_state BLOB NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_contact ON sessions(contact_id);
CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id);

-- Messages table
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    message_id BLOB NOT NULL UNIQUE,
    content BLOB NOT NULL,
    timestamp INTEGER NOT NULL,
    outgoing INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'sending',
    disappear_after INTEGER,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_messages_message_id ON messages(message_id);

-- Prekeys table (for X3DH)
CREATE TABLE IF NOT EXISTS prekeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key BLOB NOT NULL,
    secret_key BLOB NOT NULL,
    signature BLOB NOT NULL,
    one_time INTEGER NOT NULL DEFAULT 0,
    used INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

-- Settings table
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

-- Schema version
INSERT OR REPLACE INTO settings (key, value) VALUES ('schema_version', ?);
"#;

/// SQL to check if tables exist.
#[allow(dead_code)]
pub const CHECK_TABLES: &str = r#"
SELECT COUNT(*) FROM sqlite_master
WHERE type='table' AND name IN ('identity', 'contacts', 'sessions', 'messages', 'prekeys', 'settings');
"#;
