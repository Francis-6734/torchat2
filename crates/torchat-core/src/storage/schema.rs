//! Database schema definitions.

/// Schema version for migrations.
pub const SCHEMA_VERSION: u32 = 5;

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

-- Groups table (decentralized group chat)
CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id BLOB NOT NULL UNIQUE,
    group_name TEXT NOT NULL,
    founder_pubkey BLOB NOT NULL,
    our_member_id BLOB NOT NULL,
    current_epoch_number INTEGER NOT NULL DEFAULT 0,
    current_epoch_key BLOB NOT NULL,
    epoch_key_updated_at INTEGER NOT NULL,
    policy_blob BLOB NOT NULL,
    state TEXT NOT NULL DEFAULT 'active',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_groups_id ON groups(group_id);

-- Group members table
CREATE TABLE IF NOT EXISTS group_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_db_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    member_id BLOB NOT NULL,
    onion_address TEXT,
    pubkey BLOB,
    is_admin INTEGER NOT NULL DEFAULT 0,
    is_neighbor INTEGER NOT NULL DEFAULT 0,
    joined_at INTEGER NOT NULL,
    last_seen INTEGER,
    UNIQUE(group_db_id, member_id)
);

CREATE INDEX IF NOT EXISTS idx_group_members_group ON group_members(group_db_id);
CREATE INDEX IF NOT EXISTS idx_group_members_id ON group_members(member_id);

-- Group messages table (gossip history)
CREATE TABLE IF NOT EXISTS group_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_db_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    msg_id BLOB NOT NULL UNIQUE,
    sender_anon_id BLOB NOT NULL,
    epoch_number INTEGER NOT NULL,
    content BLOB NOT NULL,
    timestamp INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    hop_count INTEGER NOT NULL,
    is_delivered INTEGER NOT NULL DEFAULT 1,
    disappear_after INTEGER,
    UNIQUE(group_db_id, msg_id)
);

CREATE INDEX IF NOT EXISTS idx_group_messages_group ON group_messages(group_db_id);
CREATE INDEX IF NOT EXISTS idx_group_messages_timestamp ON group_messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_group_messages_msg_id ON group_messages(msg_id);

-- Gossip deduplication table
CREATE TABLE IF NOT EXISTS group_gossip_seen (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_db_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    msg_id BLOB NOT NULL,
    seen_at INTEGER NOT NULL,
    UNIQUE(group_db_id, msg_id)
);

CREATE INDEX IF NOT EXISTS idx_gossip_seen_group ON group_gossip_seen(group_db_id);
CREATE INDEX IF NOT EXISTS idx_gossip_seen_msg ON group_gossip_seen(msg_id);

-- Group invites table
CREATE TABLE IF NOT EXISTS group_invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_db_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    invite_id BLOB NOT NULL UNIQUE,
    invitee_onion TEXT,
    issued_by BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_group_invites_group ON group_invites(group_db_id);

-- Group epoch keys table (key history for decrypting old messages)
CREATE TABLE IF NOT EXISTS group_epoch_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_db_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    epoch_number INTEGER NOT NULL,
    epoch_key BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(group_db_id, epoch_number)
);

CREATE INDEX IF NOT EXISTS idx_epoch_keys_group ON group_epoch_keys(group_db_id);

-- Pending received group invites (invites we received from others)
CREATE TABLE IF NOT EXISTS pending_group_invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id BLOB NOT NULL,
    group_name TEXT,
    inviter_pubkey BLOB NOT NULL,
    bootstrap_peer TEXT NOT NULL,
    invite_id BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    invite_payload BLOB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    received_at INTEGER NOT NULL,
    UNIQUE(user_id, group_id, invite_id)
);

CREATE INDEX IF NOT EXISTS idx_pending_invites_user ON pending_group_invites(user_id);
CREATE INDEX IF NOT EXISTS idx_pending_invites_status ON pending_group_invites(status);

-- Group shared files table
CREATE TABLE IF NOT EXISTS group_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_db_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    file_id TEXT NOT NULL UNIQUE,
    filename TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    file_hash BLOB NOT NULL,
    sender_anon_id BLOB NOT NULL,
    sender_onion TEXT NOT NULL,
    local_path TEXT,
    status TEXT NOT NULL DEFAULT 'available',
    shared_at INTEGER NOT NULL,
    downloaded_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_group_files_group ON group_files(group_db_id);
CREATE INDEX IF NOT EXISTS idx_group_files_file_id ON group_files(file_id);

-- Group ban list
CREATE TABLE IF NOT EXISTS group_bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_db_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    member_id BLOB NOT NULL,
    banned_by BLOB,
    reason TEXT,
    banned_at INTEGER NOT NULL,
    UNIQUE(group_db_id, member_id)
);

CREATE INDEX IF NOT EXISTS idx_group_bans_group ON group_bans(group_db_id);

-- Schema version
INSERT OR REPLACE INTO settings (key, value) VALUES ('schema_version', ?);
"#;

/// SQL to check if tables exist.
#[allow(dead_code)]
pub const CHECK_TABLES: &str = r#"
SELECT COUNT(*) FROM sqlite_master
WHERE type='table' AND name IN ('identity', 'contacts', 'sessions', 'messages', 'prekeys', 'settings');
"#;
