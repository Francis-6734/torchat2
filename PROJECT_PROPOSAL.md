# TorChat 2.0 — Project Proposal

## 1. Executive Summary

TorChat 2.0 is a decentralized, end-to-end encrypted messaging platform that routes all traffic exclusively through Tor onion services. Every user's identity is a cryptographic keypair — there are no usernames, phone numbers, or central servers. Messages travel peer-to-peer over Tor, encrypted with the Double Ratchet protocol (Signal's algorithm), and stored locally in SQLCipher-encrypted databases. The system supports 1:1 messaging, decentralized group chats, encrypted voice calls, and file transfers up to 5 GB.

The platform is implemented as a Rust workspace of five crates totaling ~25,500 lines of Rust and ~3,700 lines of frontend JavaScript/HTML, with an Android app in Kotlin. It compiles to standalone binaries for Linux, Windows, and macOS, and serves a responsive web UI accessible from any browser on the local network.

### Core Principles

| Principle | Implementation |
|-----------|----------------|
| **Identity = Key** | Ed25519 keypair generates a v3 .onion address. No registration, no phone number, no email. |
| **Network = Tor** | All connections are onion-to-onion. IP addresses are never exposed. |
| **No Server** | Peer-to-peer architecture. An optional relay stores encrypted blobs for offline delivery — it cannot decrypt anything. |

---

## 2. Problem Statement

### Centralized Messengers Are Fundamentally Compromised

Every mainstream messaging platform — WhatsApp, Telegram, Signal, iMessage — depends on central infrastructure that creates exploitable single points of failure:

| Threat | Centralized Impact | TorChat 2.0 Mitigation |
|--------|-------------------|------------------------|
| Server seizure | All metadata exposed — who talks to whom, when, how often | No server exists. Metadata never leaves the endpoints. |
| Legal compulsion | Provider forced to hand over data or install backdoors | No provider to compel. Code is open-source and auditable. |
| Phone number requirement | Links real identity to account; enables SIM-swap attacks | Identity is a cryptographic key. No phone number involved. |
| IP address logging | Server sees every connection's origin IP | All traffic is Tor onion-to-onion. Origin IP never exposed. |
| Metadata analysis | Connection patterns reveal social graph even with E2E encryption | Tor hides connection endpoints. Group gossip obscures membership. |

### Existing Alternatives Fall Short

- **Signal**: Requires a phone number. Runs on centralized servers. Metadata is visible to the operator.
- **Briar**: Tor-based and decentralized, but lacks voice calls, has limited group support, and no web UI.
- **Session**: Removes phone numbers but uses a custom onion-routing network (Lokinet) with unproven security properties and a cryptocurrency dependency.
- **Ricochet Refresh**: Tor-based 1:1 chat only. No groups, no voice, no file transfer, no mobile.

TorChat 2.0 combines Tor's proven anonymity network with modern cryptographic protocols, a complete feature set (groups, voice, files), and cross-platform support (web, CLI, Android).

---

## 3. System Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Clients                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  Web Browser  │  │  CLI (tty)   │  │  Android App     │   │
│  │  (index.html) │  │  (torchat)   │  │  (Kotlin + JNI)  │   │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘   │
│         │ HTTP/WS         │ direct              │ JNI         │
│         ▼                 ▼                     ▼             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ torchat-web  │  │ torchat-cli  │  │  torchat-jni     │   │
│  │ (axum 0.7)   │  │ (clap 4)     │  │  (JNI bindings)  │   │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘   │
│         │                 │                     │             │
│         └─────────────────┼─────────────────────┘             │
│                           ▼                                   │
│              ┌────────────────────────┐                       │
│              │    torchat-core        │                       │
│              │  ┌──────────────────┐  │                       │
│              │  │ MessagingDaemon  │  │                       │
│              │  │  (event loop)    │  │                       │
│              │  └───────┬──────┬──┘  │                       │
│              │          │      │     │                        │
│              │    ┌─────┘      └──────┐                      │
│              │    ▼                   ▼                       │
│              │  ┌──────────┐  ┌────────────┐                 │
│              │  │ Sessions │  │   Groups   │                 │
│              │  │ (1:1)    │  │ (gossip +  │                 │
│              │  │ Double   │  │  mesh)     │                 │
│              │  │ Ratchet  │  └────────────┘                 │
│              │  └──────────┘                                 │
│              │          │                                     │
│              │    ┌─────┴─────────┐                          │
│              │    ▼               ▼                           │
│              │  ┌──────────┐  ┌──────────┐                   │
│              │  │ Crypto   │  │ Storage  │                   │
│              │  │ (AEAD,   │  │ (SQLCipher│                  │
│              │  │  KDF,    │  │  encrypted│                  │
│              │  │  keys)   │  │  SQLite)  │                  │
│              │  └──────────┘  └──────────┘                   │
│              └──────────┬─────────────────┘                  │
│                         │                                     │
│                         ▼                                     │
│              ┌────────────────────────┐                       │
│              │    Tor Network         │                       │
│              │  (SOCKS5 + Control)    │                       │
│              └───────────┬────────────┘                       │
│                          │                                    │
└──────────────────────────┼────────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              │   torchat-relay         │
              │  (optional, store-and-  │
              │   forward for offline   │
              │   delivery; encrypted   │
              │   blobs only)           │
              └─────────────────────────┘
```

### 3.1 Crate Breakdown

| Crate | Purpose | Lines | Key Dependencies |
|-------|---------|-------|------------------|
| `torchat-core` | Cryptography, identity, messaging, storage, Tor, protocol, voice | ~18,000 | ed25519-dalek, x25519-dalek, chacha20poly1305, arti-client, rusqlite |
| `torchat-web` | Axum web server, REST API, WebSocket, static file serving | ~4,500 | axum 0.7 (ws), tower-http, axum-extra (multipart) |
| `torchat-cli` | Terminal interface with clap subcommands | ~1,500 | clap 4 |
| `torchat-relay` | Optional offline message relay with proof-of-work | ~500 | tokio, torchat-core |
| `torchat-jni` | Android JNI bindings | ~800 | jni 0.21, android_logger |

---

## 4. Core Features

### 4.1 Identity Management

Each user's identity is an Ed25519 keypair. The public key deterministically maps to a v3 Tor onion address (56-character `.onion`). This address is the user's permanent, self-authenticating identity.

| Feature | Detail |
|---------|--------|
| Key generation | Ed25519 via `ed25519-dalek` with OS CSPRNG |
| Onion address | Derived from public key per Tor v3 spec (SHA-3 + checksum) |
| Fingerprint | SHA-256 of public key, formatted as `XXXX:XXXX:XXXX:...` |
| Persistence | Stored in SQLCipher-encrypted database |
| Auto-init | Identity generated automatically on first run |
| Export/Import | Backup and restore identity keypairs |

### 4.2 End-to-End Encrypted Messaging (1:1)

Messages between two users are encrypted with the Double Ratchet protocol, providing both perfect forward secrecy and post-compromise security.

**Encryption Flow:**

```
Alice                                                 Bob
  │                                                    │
  ├── Generate ephemeral X25519 keypair ──────────────►│
  │                           SESSION_INIT (prekey bundle)
  │◄──────────────────────────────────────────────────┤
  │                                                    │
  ├── DH agreement → root key → chain keys            │
  │   Each message gets a unique message key           │
  │   Keys are ratcheted forward after each use        │
  │   Old keys are deleted (forward secrecy)           │
  │                                                    │
  ├── MESSAGE (ChaCha20-Poly1305) ───────────────────►│
  │◄────────────────────────────── ACK ────────────────┤
  │                                                    │
```

| Feature | Detail |
|---------|--------|
| Key exchange | X25519 ECDH |
| Ratchet | Double Ratchet with symmetric + DH ratcheting |
| Cipher | ChaCha20-Poly1305 (AEAD, 256-bit keys) |
| Forward secrecy | Message keys deleted after use |
| Post-compromise security | DH ratchet step restores security after key compromise |
| Skipped messages | Stores up to 1,000 out-of-order message keys |
| Delivery receipts | ACK packets with delivery/read status |
| Offline delivery | Messages queued locally and retried with exponential backoff |
| Message reactions | Emoji reactions via REACTION packet type |
| Message deletion | DELETE packet for removing messages |

### 4.3 Decentralized Group Messaging

Groups are fully decentralized — there is no group server. Messages propagate through an epidemic gossip protocol over a mesh topology.

**Group Architecture:**

```
                    ┌─────────┐
                    │ Alice   │ (Founder)
                    │ Gossip  │
                    └─┬───┬───┘
                      │   │
            ┌─────────┘   └─────────┐
            ▼                       ▼
      ┌──────────┐           ┌──────────┐
      │   Bob    │◄─────────►│  Carol   │ (Admin)
      │  Gossip  │           │  Gossip  │
      └────┬─────┘           └────┬─────┘
           │                      │
           ▼                      ▼
      ┌──────────┐           ┌──────────┐
      │   Dave   │           │   Eve    │
      │  Gossip  │◄─────────►│  Gossip  │
      └──────────┘           └──────────┘

      Each node maintains 5-7 mesh neighbors.
      Messages flood via gossip with TTL=10 and deduplication.
```

| Feature | Detail |
|---------|--------|
| Topology | Random mesh with 5-7 neighbors per node, periodic rotation |
| Message propagation | Epidemic gossip with TTL=10, hop counting |
| Deduplication | LRU cache (1,000 entries) of seen message IDs |
| Encryption | Shared epoch key, rotated every 24h (HKDF-derived) |
| Roles | Founder (creator), Admin (can invite), Member (chat only) |
| Invites | Cryptographic tokens signed by Ed25519, 24h expiration |
| Blind membership | Nodes see neighbors but not full group membership |
| File sharing | Group file upload/download with metadata tracking |
| Member management | Promote to admin, remove members, ban/unban |

### 4.4 Encrypted Voice Calls

Voice calls are encrypted per-frame and routed over Tor, providing anonymous real-time communication.

| Feature | Detail |
|---------|--------|
| Codec | Opus (48 kHz mono, 20 ms frames via `audiopus`) |
| Encryption | Per-frame ChaCha20-Poly1305 with unique nonce per frame |
| Jitter buffer | 10-frame capacity for smoothing network variance |
| Signaling | Call signals (offer, answer, ICE candidates) over Tor |
| States | Idle → Calling → Ringing → Connected → Ending |
| Statistics | Real-time latency, jitter, and packet loss tracking |

### 4.5 File Transfer

| Feature | Detail |
|---------|--------|
| Max size | 5 GB per file |
| Chunking | 32 KB chunks for reliable delivery |
| Integrity | SHA-256 hash verification on completion |
| Progress | Real-time progress tracking per transfer |
| Upload methods | Multipart form upload or base64-encoded JSON |
| Group files | Shared files visible to all group members |
| MIME detection | Automatic MIME type identification |

### 4.6 Real-Time WebSocket Push

The web UI receives real-time event notifications via WebSocket, eliminating the need for polling.

| Feature | Detail |
|---------|--------|
| Transport | WebSocket at `/api/ws` with session token authentication |
| Events | 20+ event types: messages, groups, files, calls, peer status |
| Fallback | Automatic polling restoration when WebSocket disconnects |
| Reconnection | Exponential backoff (1s → 30s cap) |
| Multi-tab | Each browser tab gets independent event stream |
| Internal filtering | Infrastructure events (ACK, key rotation) are not forwarded |

**Event Types:**

| Category | Events |
|----------|--------|
| Messages | `message_received`, `message_delivered`, `message_failed` |
| Groups | `group_message_received`, `group_joined`, `group_created`, `group_member_joined`, `group_member_left`, `group_invite_received` |
| Files | `file_received`, `file_transfer_failed`, `group_file_shared`, `group_file_downloaded`, `group_file_download_failed` |
| Connectivity | `peer_connected`, `peer_disconnected`, `daemon_started`, `daemon_stopped` |
| System | `connected`, `lagged`, `error` |

---

## 5. Security Model

### 5.1 Threat Model

| Threat Actor | Attack Vector | Mitigation |
|-------------|---------------|------------|
| Network observer (ISP, nation-state) | Traffic analysis, connection logging | All traffic is Tor onion-to-onion. No clearnet connections. |
| Server operator | Metadata collection, content interception | No central server. Relay stores only encrypted blobs. |
| Compromised device (past) | Read old messages from stolen keys | Perfect forward secrecy — old message keys are deleted. |
| Compromised device (future) | Read future messages with current keys | Post-compromise security — DH ratchet step rotates keys. |
| Social graph analysis | Correlation of who talks to whom | Tor hides endpoints. Group gossip uses blind membership. |
| Spam / DoS | Flooding relay with junk messages | Proof-of-work required for relay submission. Rate limiting. |
| Replay attacks | Resending captured packets | Message ID deduplication. Nonce tracking on relay. |
| Database theft | Offline access to local data | SQLCipher AES-256 encryption. PBKDF2 key derivation (100k iterations). |

### 5.2 Cryptographic Primitives

| Purpose | Algorithm | Crate | Rationale |
|---------|-----------|-------|-----------|
| Identity signing | Ed25519 | `ed25519-dalek 2.x` | Compact signatures, deterministic, constant-time |
| Key exchange | X25519 ECDH | `x25519-dalek 2.x` | Curve25519, widely reviewed |
| Symmetric encryption | ChaCha20-Poly1305 | `chacha20poly1305 0.10` | AEAD, no padding oracle, constant-time |
| Hashing | SHA-256, SHA-3-256 | `sha2`, `sha3` | SHA-256 for KDF, SHA-3 for identity fingerprints |
| Key derivation | HKDF-SHA256 | `hkdf 0.12` | Standard extract-and-expand KDF |
| Password KDF | PBKDF2-SHA256 | `pbkdf2 0.12` | 100,000 iterations for database encryption key |
| Memory safety | Zeroizing | `zeroize 1.x` | All key material overwritten on drop |
| Database | SQLCipher | `rusqlite 0.31` | AES-256 full-database encryption |

### 5.3 Security Properties

- **`#![forbid(unsafe_code)]`** in `torchat-core` — no raw pointer operations in the core library
- **Constant-time comparisons** for authentication tags and key material
- **Zeroizing wrappers** on all cryptographic secrets — keys are overwritten in memory when dropped
- **WAL mode disabled** in SQLite to prevent plaintext leakage in write-ahead log
- **`secure_delete=ON`** — deleted data is overwritten with zeros
- **`auto_vacuum=FULL`** — freed pages are immediately reclaimed
- **`temp_store=MEMORY`** — temporary tables never touch disk
- **Localhost-only binding** recommended for web UI (`TORCHAT_BIND=127.0.0.1:3000`)
- **Security headers** on all HTTP responses: CSP, X-Frame-Options DENY, X-Content-Type-Options nosniff, X-XSS-Protection

---

## 6. Protocol Specification

### 6.1 Wire Format

Every packet follows a fixed 6-byte header + variable payload structure:

```
┌─────────┬──────────┬────────────────┬──────────────────────────┐
│ Version │  Type    │  Payload Len   │       Payload            │
│ (1 byte)│ (1 byte) │  (4 bytes LE)  │  (0..65535 bytes)        │
└─────────┴──────────┴────────────────┴──────────────────────────┘
```

- **Version**: Protocol version (currently `0x01`)
- **Type**: Packet type identifier (see below)
- **Payload Length**: Little-endian u32, max 65,535 bytes
- **Payload**: Bincode-serialized data, encrypted where applicable

### 6.2 Packet Types

| Code | Name | Direction | Description |
|------|------|-----------|-------------|
| `0x01` | `HELLO` | Bidirectional | Identity exchange, onion address + public key |
| `0x02` | `SESSION_INIT` | Initiator → Responder | Prekey bundle for Double Ratchet initialization |
| `0x03` | `MESSAGE` | Bidirectional | Encrypted message payload |
| `0x04` | `ACK` | Responder → Sender | Delivery or read acknowledgment |
| `0x05` | `REACTION` | Bidirectional | Emoji reaction to a message |
| `0x06` | `DELETE` | Bidirectional | Request to delete a message |
| `0x07` | `CALL_SIGNAL` | Bidirectional | Voice call signaling (offer, answer, ICE) |
| `0x08` | `FILE_CHUNK` | Sender → Receiver | 32 KB file data chunk |
| `0x09` | `FILE_OFFER` | Sender → Receiver | File transfer metadata (name, size, hash) |
| `0x0A` | `GROUP_MESSAGE` | Member → Mesh | Gossip-forwarded group message |
| `0x0B` | `GROUP_INVITE` | Admin → Invitee | Signed invitation token |
| `0x0C` | `GROUP_JOIN` | Invitee → Group | Join request with signed token |
| `0x0D` | `GROUP_LEAVE` | Member → Group | Leave notification |
| `0x0E` | `GROUP_KEY_ROTATE` | Founder → Group | New epoch key distribution |
| `0x0F` | `GROUP_MEMBER_SYNC` | Member → Neighbor | Membership state synchronization |
| `0x10` | `GROUP_MESH_REQUEST` | Node → Node | Request new mesh neighbors |
| `0x11` | `GROUP_MESH_RESPONSE` | Node → Node | Provide neighbor addresses |
| `0x12` | `GROUP_FILE_SHARE` | Member → Group | File metadata announcement |
| `0x13` | `GROUP_FILE_REQUEST` | Member → Member | Request file data from peer |

### 6.3 Connection Handshake

```
Alice                                                     Bob
  │                                                        │
  ├──── TCP connect via Tor SOCKS5 ──────────────────────►│
  │                                                        │
  ├──── HELLO { onion_addr, public_key } ────────────────►│
  │◄──── HELLO { onion_addr, public_key } ────────────────┤
  │                                                        │
  │     (Both verify each other's onion address            │
  │      matches the public key. Reject if mismatch.)      │
  │                                                        │
  ├──── SESSION_INIT { prekey_bundle } ──────────────────►│
  │◄──── SESSION_INIT { prekey_bundle } ──────────────────┤
  │                                                        │
  │     (Double Ratchet initialized. All subsequent        │
  │      MESSAGE packets are encrypted.)                   │
  │                                                        │
  ├──── MESSAGE { ciphertext } ──────────────────────────►│
  │◄──── ACK { message_id, delivered } ──────────────────┤
  │                                                        │
```

---

## 7. Storage Layer

### 7.1 Database Schema (15 Tables)

| Table | Purpose |
|-------|---------|
| `users` | Multi-user support — each device user gets a row |
| `identity` | Ed25519 keypair storage (encrypted) |
| `contacts` | Per-user contact list with names and onion addresses |
| `sessions` | Double Ratchet session state per contact |
| `messages` | 1:1 message history with status tracking |
| `simple_messages` | Lightweight message records for quick lookup |
| `prekeys` | Pre-key bundles for session initialization |
| `settings` | Per-user application settings |
| `groups` | Group metadata (ID, name, founder, state) |
| `group_members` | Group membership with roles (founder/admin/member) |
| `group_messages` | Group message history |
| `group_gossip_seen` | Deduplication cache for gossip messages |
| `group_mesh_neighbors` | Mesh topology state per group |
| `group_invites` | Pending group invitation records |
| `file_transfers` | File transfer tracking (progress, status, metadata) |

### 7.2 Encryption Configuration

```sql
PRAGMA key = '<256-bit key derived from user password via PBKDF2>';
PRAGMA journal_mode = DELETE;     -- No WAL file with plaintext
PRAGMA secure_delete = ON;        -- Overwrite deleted data
PRAGMA auto_vacuum = FULL;        -- Reclaim freed pages immediately
PRAGMA temp_store = MEMORY;       -- Temp tables never touch disk
```

---

## 8. REST API Reference

The web server exposes 46 endpoints organized by domain:

### 8.1 Identity and Registration

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/register` | Create a new identity (generates Ed25519 keypair + onion address) |
| `GET` | `/api/identity` | Get the current user's identity and onion address |

### 8.2 Contacts

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/contacts` | List all contacts for the current user |
| `POST` | `/api/contacts` | Add a contact by onion address |
| `POST` | `/api/contacts/:contact_id/delete` | Remove a contact |

### 8.3 Messages

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/messages/:address` | Get message history with a contact |
| `GET` | `/api/messages/:address/search` | Search messages with a contact |
| `POST` | `/api/messages` | Send a message to a contact |

### 8.4 Daemon Control

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/daemon/start` | Start the P2P messaging daemon |
| `POST` | `/api/daemon/stop` | Stop the daemon |
| `GET` | `/api/daemon/status` | Check daemon running status |

### 8.5 File Transfer

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/files/send` | Send a file (base64-encoded JSON body) |
| `POST` | `/api/files/upload` | Send a file (multipart form upload) |
| `GET` | `/api/files/status/:transfer_id` | Check transfer progress |
| `GET` | `/api/files/outgoing` | List outgoing transfers |
| `GET` | `/api/files/received/:contact_address` | List received files from a contact |
| `GET` | `/api/files/download/:transfer_id` | Download a received file |

### 8.6 Voice Calls

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/calls/start` | Initiate a voice call |
| `POST` | `/api/calls/answer` | Answer an incoming call |
| `POST` | `/api/calls/hangup` | End a call |

### 8.7 Groups

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/groups` | List all groups |
| `POST` | `/api/groups` | Create a new group |
| `POST` | `/api/groups/join` | Join a group via invite token |
| `POST` | `/api/groups/:group_id/invite` | Generate an invite for a contact |
| `GET` | `/api/groups/:group_id/messages` | Get group message history |
| `POST` | `/api/groups/:group_id/messages` | Send a message to a group |
| `GET` | `/api/groups/:group_id/messages/search` | Search group messages |
| `POST` | `/api/groups/:group_id/leave` | Leave a group |
| `POST` | `/api/groups/:group_id/delete` | Delete a group locally |
| `GET` | `/api/groups/:group_id/members` | List group members |
| `POST` | `/api/groups/:group_id/promote` | Promote a member to admin |
| `POST` | `/api/groups/:group_id/remove` | Remove a member from the group |
| `GET` | `/api/groups/:group_id/bans` | List banned members |
| `POST` | `/api/groups/:group_id/unban` | Unban a member |

### 8.8 Group Files

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/groups/:group_id/files/upload` | Upload a file to a group |
| `GET` | `/api/groups/:group_id/files` | List files shared in a group |
| `POST` | `/api/groups/:group_id/files/:file_id/download` | Download a group file |
| `GET` | `/api/groups/:group_id/files/:file_id/serve` | Serve a group file to the browser |

### 8.9 Invites

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/invites` | List pending group invites |
| `POST` | `/api/invites/:invite_id/accept` | Accept a pending invite |
| `POST` | `/api/invites/:invite_id/decline` | Decline a pending invite |

### 8.10 System

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/users` | List all registered users |
| `POST` | `/api/diagnostic/connectivity` | Test Tor connectivity |
| `GET` | `/api/ws` | WebSocket endpoint for real-time events |

---

## 9. Web Frontend

The web UI is a single-page application (~2,800 lines HTML/CSS/JS + ~950 lines groups.js) served as static files by the axum server. It communicates with the backend via REST API and WebSocket.

### 9.1 Interface Layout

```
┌─────────────────────────────────────────────────────────┐
│  Header: TorChat 2.0  │  Identity  │  Settings  │  ●   │
├────────────┬────────────────────────────────────────────┤
│            │                                            │
│  Sidebar   │            Chat Area                      │
│            │                                            │
│  [Chats]   │  ┌────────────────────────────────────┐   │
│  [Groups]  │  │  Contact / Group Name              │   │
│            │  ├────────────────────────────────────┤   │
│  ──────    │  │                                    │   │
│  Contact 1 │  │  Message bubbles                   │   │
│  Contact 2 │  │  (sent = right, received = left)   │   │
│  Contact 3 │  │                                    │   │
│            │  │                                    │   │
│  ──────    │  ├────────────────────────────────────┤   │
│  Group A   │  │  [📎] [Input field...] [Send] [📞] │   │
│  Group B   │  └────────────────────────────────────┘   │
│            │                                            │
├────────────┴────────────────────────────────────────────┤
│  Toast Notifications                                    │
└─────────────────────────────────────────────────────────┘
```

### 9.2 Features

- **Responsive design** — works on desktop and mobile browsers
- **Tab navigation** — switch between Chats (1:1) and Groups
- **Real-time updates** — WebSocket push with polling fallback
- **Contact management** — add, search, delete contacts
- **Group management** — create, join via invite, leave, delete, promote members
- **File sharing** — drag-and-drop or button upload, download with progress
- **Voice calls** — start/answer/hangup from the chat interface
- **Toast notifications** — success, error, and info messages
- **Desktop notifications** — browser notification API for background messages
- **Onion address copy** — one-click copy to clipboard

---

## 10. Platform Support

### 10.1 Web UI (`torchat-web`)

- **Platforms**: Any OS with Rust toolchain and Tor
- **Access**: Browser at `http://localhost:3000`
- **Requirements**: Tor running with SocksPort 9050 and ControlPort 9051
- **Binary size**: ~15 MB (release, stripped)

### 10.2 CLI (`torchat-cli`)

- **Platforms**: Linux, Windows, macOS
- **Subcommands**: `init`, `identity`, `start`, `add`, `contacts`, `send`, `history`, `call`, `export`, `import`

### 10.3 Android (`torchat-jni` + Kotlin app)

- **Architecture**: Kotlin UI → JNI → torchat-core (Rust)
- **Features**: Chat, voice calls, notifications, background service
- **Structure**: 17 Kotlin source files under `android/app/src/`

### 10.4 Relay Server (`torchat-relay`)

- **Purpose**: Optional store-and-forward for offline message delivery
- **Security**: Encrypted blobs only — relay cannot decrypt content
- **Anti-spam**: Proof-of-work (configurable difficulty)
- **Anti-replay**: Nonce tracking
- **Rate limiting**: Per-recipient limits (default 1,000 messages)
- **TTL**: Messages expire after 168 hours (7 days)

---

## 11. Technology Stack

| Layer | Technology | Version | Rationale |
|-------|-----------|---------|-----------|
| Language | Rust | 1.75+ (edition 2021) | Memory safety without GC, fearless concurrency |
| Async runtime | Tokio | 1.x (full) | Industry-standard async runtime for Rust |
| Web framework | Axum | 0.7 | Type-safe, tower-based, WebSocket support |
| HTTP middleware | tower-http | 0.5 | CORS, tracing, static files, body limits |
| Tor client | arti-client | 0.11 | Rust-native Tor implementation (no C dependency) |
| Database | rusqlite + SQLCipher | 0.31 | Encrypted SQLite, bundled (no system deps) |
| Crypto: signing | ed25519-dalek | 2.x | Audited Ed25519 implementation |
| Crypto: key exchange | x25519-dalek | 2.x | Audited X25519 ECDH |
| Crypto: AEAD | chacha20poly1305 | 0.10 | Audited ChaCha20-Poly1305 |
| Crypto: hashing | sha2, sha3 | 0.10 | SHA-256 and SHA-3 |
| Crypto: KDF | hkdf, pbkdf2 | 0.12 | HKDF-SHA256 and PBKDF2-SHA256 |
| Crypto: memory | zeroize | 1.x | Secure key material cleanup |
| Audio codec | audiopus | 0.3.0-rc.0 | Opus codec bindings |
| Serialization | serde + bincode | 1.x | Wire format (bincode) and API (JSON) |
| CLI framework | clap | 4.x | Derive-based argument parsing |
| Android bindings | jni | 0.21 | JNI interop for Kotlin/Java |
| Frontend | Vanilla JS + HTML5 | — | No framework dependencies, minimal attack surface |

### Build Configuration

```toml
[profile.release]
lto = true          # Link-time optimization — smaller, faster binary
codegen-units = 1   # Single codegen unit — better optimization
panic = "abort"     # No unwinding — smaller binary
strip = true        # Strip debug symbols
```

---

## 12. Test Coverage

### 12.1 Test Summary

| Test Suite | Tests | Duration | Location |
|------------|-------|----------|----------|
| Core unit tests | 99 | ~24s | `torchat-core/src/**` (inline `#[cfg(test)]`) |
| Core integration tests | 14 | ~0.1s | `torchat-core/tests/integration_tests.rs` |
| Onion self-test | 2 | ~43s | `torchat-core/tests/onion_self_test.rs` |
| P2P diagnostic | 8 | ~210s | `torchat-core/tests/p2p_diagnostic.rs` |
| WebSocket integration | 45 | ~0.3s | `torchat-web/tests/websocket_tests.rs` |
| **Total** | **168** | — | — |

### 12.2 Coverage by Subsystem

| Subsystem | Coverage | Notes |
|-----------|----------|-------|
| Cryptography (AEAD, ratchet, keys, group crypto, rotation) | Comprehensive | All primitives tested with edge cases |
| Identity (generation, onion derivation, fingerprint, persistence) | Comprehensive | — |
| Storage (database CRUD, encryption, key derivation) | Comprehensive | In-memory SQLite for fast tests |
| Protocol (packet framing, serialization, validation) | Good | Header roundtrip, payload limits |
| Messaging (sessions, message flow, acknowledgments) | Good | E2E flows, out-of-order delivery |
| Group messaging (gossip, mesh, deduplication) | Good | Cache stats, forwarding rules |
| Voice (codec, encryption, jitter buffer, call states) | Good | Separate test file |
| WebSocket (lifecycle, events, auth, multi-client, filtering) | Comprehensive | 45 integration tests with real TCP |
| Tor integration | Limited | Requires live Tor daemon |

---

## 13. Development Roadmap

### Phase 1 — Core Platform (Complete)

- [x] Ed25519 identity generation and onion address derivation
- [x] Double Ratchet protocol implementation
- [x] ChaCha20-Poly1305 AEAD encryption
- [x] SQLCipher encrypted local storage
- [x] Tor integration (SOCKS5 proxy + control port + onion services)
- [x] Binary wire protocol (20 packet types)
- [x] P2P messaging daemon with event loop
- [x] 1:1 encrypted sessions with delivery receipts
- [x] Offline message queuing with retry backoff
- [x] Web UI with REST API (46 endpoints)

### Phase 2 — Group Chat and Media (Complete)

- [x] Decentralized group creation with cryptographic invites
- [x] Gossip protocol for group message propagation
- [x] Mesh topology with neighbor rotation
- [x] Role-based access control (founder, admin, member)
- [x] Epoch key rotation for group forward secrecy
- [x] Encrypted voice calls with Opus codec
- [x] Chunked file transfer (up to 5 GB)
- [x] Group file sharing
- [x] Member management (promote, remove, ban/unban)
- [x] Relay server for offline delivery

### Phase 3 — Hardening and Polish (In Progress)

- [x] WebSocket push for real-time message delivery
- [x] WebSocket integration test suite (45 tests)
- [ ] Full-text message search with indexing
- [ ] Contact verification ceremony (QR code or emoji comparison)
- [ ] Disappearing messages with configurable TTL
- [ ] UI enhancements: dark mode, notification sounds, desktop notifications
- [ ] Message search in conversations and groups
- [ ] Additional integration tests for REST API endpoints
- [ ] Encrypt group file metadata in gossip protocol
- [ ] Complete CLI command implementations (contacts list, send, history, call)

### Phase 4 — Mobile and Distribution (Planned)

- [ ] Complete Android app UI and navigation
- [ ] iOS app (Swift wrapper around torchat-core via C FFI)
- [ ] Reproducible builds for binary verification
- [ ] Package distribution: Flatpak (Linux), APK (Android), Homebrew (macOS)
- [ ] Tor Browser Bundle integration
- [ ] Automated relay discovery via onion service directory

### Phase 5 — Advanced Features (Future)

- [ ] Multi-device synchronization (sync ratchet state across devices)
- [ ] Offline group key ratcheting (MLS-inspired protocol)
- [ ] Steganographic transport (hide traffic inside innocuous protocols)
- [ ] Decentralized relay federation (relays discover each other)
- [ ] Post-quantum key exchange (ML-KEM hybrid with X25519)
- [ ] Bridging to other networks (Matrix, XMPP) via plugins

---

## 14. Performance Characteristics

| Operation | Measured | Notes |
|-----------|----------|-------|
| Identity generation | <100 ms | Ed25519 keypair + onion address derivation |
| Database operations | <50 ms | SQLCipher with bundled SQLite |
| API response time | <10 ms | Axum on localhost |
| Double Ratchet encrypt/decrypt | <1 ms | ChaCha20-Poly1305 is hardware-accelerable |
| File transfer throughput | ~2 MB/s | Limited by Tor circuit bandwidth |
| Voice latency | 200-600 ms | Tor onion routing overhead (3 hops each way) |
| WebSocket event delivery | <5 ms | Local broadcast channel to WebSocket |
| Test suite (unit + integration) | ~25s | 99 unit tests, excludes Tor-dependent tests |
| WebSocket test suite | ~0.3s | 45 tests with real TCP connections |
| Release binary size | ~15 MB | LTO + strip enabled |

### Scalability Properties

- **Users per instance**: Unlimited (each user runs their own daemon)
- **Group size**: Tested up to 100 members; mesh topology scales logarithmically
- **Concurrent connections**: Limited by Tor circuit establishment (~10-30 active peers)
- **Database size**: Grows linearly with message history; full-text search planned
- **Relay capacity**: Configurable per-recipient limits; TTL-based expiration prevents unbounded growth

---

## 15. Risk Analysis

| Risk | Severity | Likelihood | Mitigation |
|------|----------|------------|------------|
| Tor network congestion | High | Medium | Retry with exponential backoff; relay for offline delivery |
| Tor exit node compromise | N/A | N/A | Not applicable — all traffic is onion-to-onion (no exit nodes) |
| Onion service discovery latency | Medium | High | 30-60s propagation time; UI shows "connecting" status |
| SQLCipher key brute-force | High | Low | PBKDF2 with 100k iterations; user-chosen password strength |
| Group epoch key compromise | Medium | Low | 24h automatic key rotation; manual rotation on member removal |
| Gossip amplification | Medium | Low | TTL limits and deduplication prevent unbounded flooding |
| JNI memory safety | Medium | Low | Careful Rust ↔ Java boundary management; no unsafe in core |
| Dependency supply chain | Medium | Low | All crypto crates are audited; Cargo.lock pinned; reproducible builds planned |
| Tor protocol changes | Low | Low | Using `arti-client` (actively maintained Rust Tor implementation) |

---

## 16. Project Structure

```
torchat2/
├── Cargo.toml                       # Workspace configuration
├── Cargo.lock                       # Pinned dependency versions
├── PROJECT_PROPOSAL.md              # This document
├── SETUP.md                         # Installation and setup guide
├── INTEGRATION_COMPLETE.md          # Integration status document
├── README.md                        # Project overview
│
├── crates/
│   ├── torchat-core/                # Core library (~18,000 lines)
│   │   ├── src/
│   │   │   ├── lib.rs               # Crate root, #![forbid(unsafe_code)]
│   │   │   ├── crypto/              # Cryptographic primitives
│   │   │   │   ├── aead.rs          #   ChaCha20-Poly1305 AEAD
│   │   │   │   ├── ratchet.rs       #   Double Ratchet protocol
│   │   │   │   ├── keys.rs          #   X25519 key exchange
│   │   │   │   ├── group_crypto.rs  #   Group encryption + invite signing
│   │   │   │   └── rotation.rs      #   Key rotation for forward secrecy
│   │   │   ├── identity/            # Identity management
│   │   │   │   ├── onion.rs         #   V3 onion address generation
│   │   │   │   └── auto.rs          #   Auto-initialization
│   │   │   ├── messaging/           # Messaging subsystem
│   │   │   │   ├── daemon.rs        #   P2P daemon event loop
│   │   │   │   ├── session.rs       #   1:1 encrypted sessions
│   │   │   │   ├── message.rs       #   Message types and status
│   │   │   │   ├── file_transfer.rs #   Chunked file transfer
│   │   │   │   ├── stream_transfer.rs # Streaming file transfer
│   │   │   │   ├── group_session.rs #   Group chat sessions
│   │   │   │   ├── group_gossip.rs  #   Epidemic gossip protocol
│   │   │   │   ├── group_mesh.rs    #   Mesh topology management
│   │   │   │   └── relay.rs         #   Relay protocol
│   │   │   ├── protocol/            # Wire protocol
│   │   │   │   ├── packet.rs        #   Packet framing
│   │   │   │   └── types.rs         #   20 packet type definitions
│   │   │   ├── storage/             # Encrypted local storage
│   │   │   │   ├── database.rs      #   SQLCipher operations
│   │   │   │   ├── schema.rs        #   15-table schema
│   │   │   │   └── offline_queue.rs #   Offline message queue
│   │   │   ├── tor/                 # Tor integration
│   │   │   │   ├── service.rs       #   Onion service management
│   │   │   │   ├── controller.rs    #   Tor control protocol
│   │   │   │   └── connection.rs    #   P2P over Tor
│   │   │   ├── voice/               # Voice calling
│   │   │   │   └── mod.rs           #   Opus codec + jitter buffer
│   │   │   └── logging/             # Secure logging (redaction)
│   │   └── tests/                   # Integration tests
│   │       ├── integration_tests.rs #   Core E2E tests (14 tests)
│   │       ├── onion_self_test.rs   #   Onion address tests (2 tests)
│   │       ├── p2p_diagnostic.rs    #   P2P connectivity tests (8 tests)
│   │       └── voice_tests.rs       #   Voice subsystem tests
│   │
│   ├── torchat-web/                 # Web server (~4,500 lines)
│   │   ├── src/
│   │   │   ├── main.rs             #   Server startup, routing, middleware
│   │   │   ├── api.rs              #   46 REST + WebSocket handlers
│   │   │   ├── handlers.rs         #   Static file serving
│   │   │   ├── models.rs           #   Request/response models
│   │   │   └── lib.rs              #   Library exports for testing
│   │   ├── public/
│   │   │   ├── index.html          #   Web UI SPA (~2,800 lines)
│   │   │   └── groups.js           #   Group management (~950 lines)
│   │   └── tests/
│   │       └── websocket_tests.rs  #   WebSocket integration tests (45 tests)
│   │
│   ├── torchat-cli/                 # CLI interface (~1,500 lines)
│   │   └── src/
│   │       ├── main.rs             #   Entry point
│   │       └── commands.rs         #   Subcommand implementations
│   │
│   ├── torchat-relay/               # Relay server (~500 lines)
│   │   └── src/
│   │       └── main.rs             #   PoW verification, rate limiting
│   │
│   └── torchat-jni/                 # Android JNI bindings (~800 lines)
│       └── src/
│           └── lib.rs              #   JNI exports
│
└── android/                         # Android app (Kotlin)
    └── app/src/
        └── main/
            ├── java/com/torchat/   #   17 Kotlin source files
            └── res/                #   Android resources
```

---

## 17. License

Dual-licensed under MIT and Apache 2.0. Users may choose either license at their option.

```
SPDX-License-Identifier: MIT OR Apache-2.0
```

---

## 18. Getting Started

### Quick Start (Linux)

```bash
# Install dependencies
sudo apt install -y build-essential pkg-config tor git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Configure Tor (ensure SocksPort 9050 and ControlPort 9051 in /etc/tor/torrc)
sudo systemctl enable --now tor

# Build and run
git clone <repository-url>
cd torchat2
cargo build --release -p torchat-web
TORCHAT_BIND=127.0.0.1:3000 ./target/release/torchat-web
```

Open `http://localhost:3000`, create an identity, and start chatting.

See [SETUP.md](SETUP.md) for detailed instructions on all platforms (Linux, Windows, macOS).

---

*TorChat 2.0 — Private messaging without compromise.*
