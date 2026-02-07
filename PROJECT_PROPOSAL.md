# TorChat 2.0 — Project Proposal

**Decentralized, End-to-End Encrypted Messaging Over Tor**

Version 1.0 | February 2026

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Proposed Solution](#3-proposed-solution)
4. [System Architecture](#4-system-architecture)
5. [Core Features](#5-core-features)
6. [Security Model](#6-security-model)
7. [Protocol Specification](#7-protocol-specification)
8. [Platform Support](#8-platform-support)
9. [Technology Stack](#9-technology-stack)
10. [Project Structure](#10-project-structure)
11. [API Reference](#11-api-reference)
12. [Performance & Scalability](#12-performance--scalability)
13. [Development Roadmap](#13-development-roadmap)
14. [Risk Analysis](#14-risk-analysis)
15. [License](#15-license)

---

## 1. Executive Summary

TorChat 2.0 is a fully decentralized, peer-to-peer encrypted messaging platform where all communication is routed exclusively through Tor onion services. There are no central servers, no accounts, no phone numbers, and no metadata leaks. Each user is identified solely by a cryptographic onion address derived from their Ed25519 keypair.

The system supports one-to-one messaging with Signal-grade Double Ratchet encryption, decentralized group chats with mesh-based gossip propagation, encrypted file transfers up to 5 GB, and voice calling over Tor with Opus-encoded audio. A built-in relay server enables asynchronous message delivery for offline recipients.

TorChat 2.0 is implemented in Rust for memory safety and performance, with a browser-based web interface, a terminal CLI, and Android JNI bindings for mobile deployment.

---

## 2. Problem Statement

### 2.1 Centralized Messaging Is Structurally Compromised

Mainstream encrypted messengers (Signal, WhatsApp, Telegram) require phone numbers or email addresses for registration, creating a permanent link between identity and communication. Even with end-to-end encryption, these platforms:

- **Collect metadata**: who talks to whom, when, how often, and from where
- **Depend on central infrastructure**: servers that can be seized, subpoenaed, or shut down
- **Require trust in a single entity**: the operator controls account access, key distribution, and message routing
- **Expose IP addresses**: connections reveal geographic location to the service provider and network observers

### 2.2 Existing Decentralized Alternatives Fall Short

Matrix, XMPP, and Briar each address parts of the problem but introduce their own trade-offs:

| Platform | Weakness |
|----------|----------|
| Matrix | Federated servers still collect metadata; room history stored on servers |
| XMPP + OMEMO | Relies on server federation; inconsistent client support; no built-in anonymity |
| Briar | Bluetooth/Wi-Fi only for local peers; limited to Android; no desktop support |
| Session | Uses a blockchain-based routing layer with its own trust assumptions |

### 2.3 The Gap

No existing messenger simultaneously provides:

- Zero metadata collection
- No registration identity (no phone, email, or username)
- Full network anonymity (Tor-level)
- Group chat without a central coordinator
- Cross-platform support (desktop, mobile, browser)
- Voice calling over anonymized channels

TorChat 2.0 fills this gap.

---

## 3. Proposed Solution

TorChat 2.0 is a messaging system built on three principles:

1. **Identity is a key.** Your onion address *is* your identity. No registration, no accounts, no recovery. If you lose your key, you generate a new one. There is nothing to subpoena.

2. **The network is Tor.** Every byte of communication travels through Tor onion services. Neither the sender's IP nor the receiver's IP is ever exposed to anyone — not to each other, not to observers, not to us.

3. **There is no server.** Messages travel peer-to-peer. Group messages propagate through a gossip mesh. An optional relay stores encrypted blobs for offline delivery, but it cannot read them, identify senders, or correlate traffic.

### 3.1 How It Works

```
Alice                          Tor Network                          Bob
  |                                                                  |
  |--- [Encrypted Message] ---> Onion Route (3 hops) ---> .onion -->|
  |                                                                  |
  |<-- [Encrypted Reply] <--- Onion Route (3 hops) <--- .onion ----|
```

- Alice and Bob each run a Tor onion service on their device
- They exchange onion addresses out-of-band (in person, via another channel)
- A Double Ratchet session is established on first contact
- All subsequent messages have perfect forward secrecy
- Neither party ever learns the other's IP address

---

## 4. System Architecture

### 4.1 High-Level Overview

```
+------------------+     +------------------+     +------------------+
|   torchat-web    |     |   torchat-cli    |     |   torchat-jni    |
|  (Browser UI)    |     |  (Terminal UI)   |     |  (Android App)   |
+--------+---------+     +--------+---------+     +--------+---------+
         |                        |                        |
         +------------------------+------------------------+
                                  |
                        +---------+---------+
                        |   torchat-core    |
                        |                   |
                        |  +-------------+  |
                        |  | Identity     |  |
                        |  | Crypto       |  |
                        |  | Protocol     |  |
                        |  | Messaging    |  |
                        |  | Storage      |  |
                        |  | Tor          |  |
                        |  | Voice        |  |
                        |  +-------------+  |
                        +---------+---------+
                                  |
                        +---------+---------+
                        |   Tor Network     |
                        |  (Onion Services) |
                        +-------------------+

                        +---------+---------+
                        |  torchat-relay    |
                        | (Offline Storage) |
                        +-------------------+
```

### 4.2 Component Breakdown

| Crate | Role | Type |
|-------|------|------|
| `torchat-core` | Cryptography, protocol, messaging engine, storage, Tor integration | Library |
| `torchat-web` | REST API + browser UI served by Axum | Binary |
| `torchat-cli` | Terminal interface with Clap argument parsing | Binary |
| `torchat-jni` | Java/Kotlin FFI bindings for Android | Library (cdylib) |
| `torchat-relay` | Store-and-forward server for offline message delivery | Binary |

### 4.3 Data Flow

**Sending a message (1:1):**
1. User types message in web UI or CLI
2. API handler passes message to the messaging daemon
3. Daemon encrypts with Double Ratchet session keys
4. Daemon serializes into a `Packet` (type `MESSAGE`)
5. Packet is sent through Tor to the recipient's onion service
6. Recipient's daemon decrypts and stores the message
7. Recipient's daemon sends an `ACK` packet back
8. Both sides update their ratchet state

**Sending a group message:**
1. User sends message to group
2. Daemon encrypts with the group's current epoch key
3. Gossip manager wraps it with a TTL and message ID
4. Message is forwarded to all mesh neighbors
5. Each neighbor deduplicates, decrements TTL, and forwards to *their* neighbors
6. Message propagates to all group members in O(log n) hops

---

## 5. Core Features

### 5.1 One-to-One Messaging

| Feature | Description |
|---------|-------------|
| Real-time chat | Encrypted P2P messages with delivery acknowledgments |
| Message status | Sent, Delivered, Read indicators |
| Message reactions | Emoji reactions on individual messages |
| Message deletion | Bidirectional delete requests |
| File transfer | End-to-end encrypted, up to 5 GB, chunked at 32 KB |
| Voice calling | Opus-encoded audio over Tor with per-frame encryption |
| Offline delivery | Messages queued at relay for later retrieval |
| Message history | Encrypted local storage with configurable retention |

### 5.2 Group Messaging

| Feature | Description |
|---------|-------------|
| Decentralized groups | No central server; messages propagate via gossip mesh |
| Role-based access | Founder, Admin, Member roles with distinct permissions |
| Cryptographic invites | Signed tokens with 24-hour expiration |
| Epoch key rotation | Periodic re-keying for forward secrecy (default: 24 hours) |
| Blind membership | Optional mode where members only see their direct neighbors |
| Mesh topology | Automatic 5-7 neighbor selection with periodic rotation |
| Group file sharing | Share files with all group members |
| Member sync | Automatic member list propagation |

### 5.3 Voice Calling

| Feature | Description |
|---------|-------------|
| Codec | Opus at 48 kHz mono |
| Frame size | 20 ms audio frames |
| Encryption | ChaCha20-Poly1305 per audio frame |
| Jitter buffer | 10-frame buffer for packet reordering |
| Call states | Idle, Calling, Ringing, Connected, Ending |
| Statistics | Real-time latency, jitter, and packet loss tracking |

### 5.4 File Transfer

| Feature | Description |
|---------|-------------|
| Max size | 5 GB per file |
| Chunking | 32 KB chunks with index tracking |
| Integrity | SHA-256 hash verification on completion |
| Encryption | Same session keys as text messages |
| Upload methods | Multipart form or base64 JSON |
| Progress | Real-time transfer progress tracking |

### 5.5 Identity & Contacts

| Feature | Description |
|---------|-------------|
| Identity | Ed25519 keypair; V3 onion address (56 characters) |
| Fingerprint | SHA-256 formatted for verbal verification |
| Contacts | Named contact list stored locally |
| Export/Import | Backup and restore identity keypairs |
| Auto-init | Identity generated automatically on first run |
| No registration | No phone number, email, username, or server account |

---

## 6. Security Model

### 6.1 Threat Model

TorChat 2.0 is designed to resist the following adversaries:

| Adversary | Mitigation |
|-----------|------------|
| **Network observer** (ISP, nation-state) | All traffic through Tor; no clearnet connections |
| **Server compromise** | No server to compromise; relay stores opaque encrypted blobs |
| **Key compromise (past)** | Double Ratchet provides perfect forward secrecy |
| **Key compromise (future)** | Post-compromise security via ratchet advancement |
| **Metadata analysis** | Tor onion routing; timestamp jitter; blind group membership |
| **Replay attacks** | Message ID deduplication; relay nonce tracking |
| **Spam / DoS** | Proof-of-work on relay submissions; rate limiting on API |

### 6.2 Cryptographic Primitives

| Purpose | Algorithm | Key Size |
|---------|-----------|----------|
| Identity signing | Ed25519 | 256-bit |
| Key exchange | X25519 (ECDH) | 256-bit |
| Symmetric encryption | ChaCha20-Poly1305 (AEAD) | 256-bit key, 96-bit nonce |
| Key derivation | HKDF-SHA256 | Variable |
| Password-based KDF | PBKDF2-SHA256 | 100,000 iterations |
| Hashing | SHA-256 / SHA-3 | 256-bit |
| Database encryption | SQLCipher (AES-256) | 256-bit |

### 6.3 Double Ratchet Protocol

Each 1:1 session uses a Signal-style Double Ratchet:

```
Session Initialization:
  Alice -> Bob:  identity_key_A, ephemeral_key_A
  Bob -> Alice:  identity_key_B, signed_prekey_B, one_time_prekey_B

  Both derive: root_key = HKDF(DH(eph_A, spk_B) || DH(id_A, spk_B) || DH(eph_A, id_B))

Message Encryption:
  For each message:
    1. DH ratchet step (if new prekey received)
    2. Symmetric chain key advancement: CK_new = HMAC(CK_old, 0x02)
    3. Message key derivation: MK = HMAC(CK_old, 0x01)
    4. Encrypt: ciphertext = ChaCha20-Poly1305(MK, nonce, plaintext)
    5. Attach ratchet header (public key, chain index, previous chain length)
```

Properties:
- **Forward secrecy**: Compromising current keys cannot decrypt past messages
- **Post-compromise security**: After key compromise, security is restored within one round-trip
- **Out-of-order tolerance**: Up to 100 skipped message keys are cached for late-arriving messages

### 6.4 Group Encryption

Groups use symmetric epoch keys distributed by the founder:

```
Group Key Lifecycle:
  1. Founder generates initial group key: random 256-bit key
  2. Epoch key derived: epoch_key = HKDF(group_key, epoch_number)
  3. Messages encrypted: ChaCha20-Poly1305(epoch_key, nonce, plaintext)
  4. Key rotation: founder distributes new epoch key to all members
  5. Old epoch keys are zeroized after rotation grace period
```

### 6.5 Memory Safety

- All key material uses `Zeroizing<>` wrappers — keys are overwritten on drop
- Rust's ownership system prevents use-after-free and buffer overflows
- No unsafe code in cryptographic paths
- Constant-time comparison for authentication tags

---

## 7. Protocol Specification

### 7.1 Wire Format

```
+----------+----------+----------+---------+----------+
| Version  |  Type    |  Flags   | Length  | Payload  |
| (1 byte) | (1 byte) | (2 bytes)| (4 bytes)| (variable)|
+----------+----------+----------+---------+----------+
```

- **Version**: Protocol version (currently `1`)
- **Type**: Packet type identifier (see below)
- **Flags**: Feature flags bitmask for capability negotiation
- **Length**: Payload length in bytes (max 65,536)
- **Payload**: Bincode-serialized packet data

### 7.2 Packet Types

| Code | Type | Direction | Purpose |
|------|------|-----------|---------|
| 0x01 | HELLO | Bidirectional | Identity exchange and handshake |
| 0x02 | SESSION_INIT | Responder | Prekey bundle and ratchet initialization |
| 0x03 | MESSAGE | Bidirectional | Encrypted text message |
| 0x04 | ACK | Bidirectional | Delivery/read receipt |
| 0x05 | FILE_OFFER | Sender | File metadata announcement |
| 0x06 | FILE_CHUNK | Sender | Encrypted file data chunk |
| 0x07 | CALL_SIGNAL | Bidirectional | Voice call signaling |
| 0x10 | GROUP_INVITE | Inviter | Signed invite token |
| 0x11 | GROUP_JOIN_REQUEST | Joiner | Join request with invite proof |
| 0x12 | GROUP_JOIN_ACCEPT | Founder | Epoch key and member list |
| 0x13 | GROUP_MESSAGE | Member | Gossip-replicated group message |
| 0x14 | GROUP_MEMBER_SYNC | Any | Member list synchronization |
| 0x15 | GROUP_KEY_ROTATION | Founder | New epoch key distribution |
| 0x16 | GROUP_MEMBER_LEAVE | Member | Departure notification |
| 0x17 | GROUP_NEIGHBOR_REQUEST | Member | Neighbor discovery (blind mode) |
| 0x18 | GROUP_ADMIN_HANDOVER | Founder | Admin role transfer |
| 0x19 | REACTION | Bidirectional | Emoji reaction on a message |
| 0x1A | DELETE | Bidirectional | Message deletion request |

### 7.3 Handshake Flow (1:1)

```
Alice                                          Bob
  |                                              |
  |-- HELLO (id_key, eph_key, address) --------->|
  |                                              |
  |<- SESSION_INIT (id_key, spk, ratchet_hdr) --|
  |                                              |
  |-- MESSAGE (ratchet_hdr, ciphertext) -------->|
  |                                              |
  |<- ACK (message_id, type=delivered) ----------|
```

### 7.4 Group Join Flow

```
Inviter          Joiner           Founder
   |                |                |
   |-- INVITE ----->|                |
   |                |-- JOIN_REQ --->|
   |                |                |-- (verify invite token)
   |                |<- JOIN_ACCEPT -|  (epoch_key, members, neighbors)
   |                |                |
   |                |-- GROUP_MSG -->|  (first message, gossip propagated)
```

---

## 8. Platform Support

### 8.1 Interfaces

| Platform | Interface | Status |
|----------|-----------|--------|
| Linux | Web UI (browser) | Implemented |
| Linux | CLI (terminal) | Implemented |
| Windows | Web UI (browser) | Implemented |
| macOS | Web UI (browser) | Implemented |
| Android | JNI bindings | Bindings implemented |
| iOS | Not yet | Planned |

### 8.2 Multi-Device Model

Each device operates independently:

- Every browser/device generates its own onion address
- No cross-device message synchronization (by design — avoids metadata)
- Contact lists and message history are per-device
- Identity can be exported and imported for migration

---

## 9. Technology Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Language | Rust 2021 (MSRV 1.75) | Memory safety without GC; zero-cost abstractions |
| Async runtime | Tokio | Industry-standard Rust async runtime |
| Web framework | Axum 0.7 | Type-safe, performant HTTP framework |
| Database | SQLCipher (bundled) | Encrypted SQLite; no external dependencies |
| Encryption | ChaCha20-Poly1305 | IETF-standard AEAD; constant-time on all hardware |
| Signatures | Ed25519 (dalek) | Deterministic, fast, compact signatures |
| Key exchange | X25519 (dalek) | Standard ECDH over Curve25519 |
| Tor integration | arti-client 0.11 | Rust-native Tor implementation |
| Audio codec | Opus (audiopus) | Low-latency, high-quality speech codec |
| Serialization | Bincode / Serde JSON | Compact binary wire format; JSON for REST API |
| Frontend | Vanilla JS + HTML/CSS | Zero dependencies; no build step; works offline |

---

## 10. Project Structure

```
torchat2/
+-- Cargo.toml                  # Workspace manifest
+-- SETUP.md                    # User setup guide
+-- PROJECT_PROPOSAL.md         # This document
+-- crates/
|   +-- torchat-core/           # Core library
|   |   +-- src/
|   |       +-- crypto/         # AEAD, ratchet, key rotation, group crypto
|   |       +-- identity/       # Onion address, fingerprints, auto-init
|   |       +-- messaging/      # Daemon, sessions, groups, gossip, mesh, files
|   |       +-- protocol/       # Packet types, wire format, serialization
|   |       +-- storage/        # SQLCipher database, offline queue
|   |       +-- tor/            # Onion service, SOCKS5 proxy, control port
|   |       +-- voice/          # Opus codec, jitter buffer, call state
|   +-- torchat-web/            # Web server
|   |   +-- src/
|   |   |   +-- main.rs         # Server startup, routes, middleware
|   |   |   +-- api.rs          # REST API handlers
|   |   |   +-- models.rs       # Request/response JSON models
|   |   +-- public/             # Static frontend files
|   |       +-- index.html      # Main UI (single-page app)
|   |       +-- groups.js       # Group management logic
|   |       +-- styles.css      # UI styling
|   +-- torchat-cli/            # Terminal client
|   +-- torchat-jni/            # Android JNI bindings
|   +-- torchat-relay/          # Offline message relay
```

---

## 11. API Reference

### 11.1 Identity & Auth

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/register` | Create identity (generates onion address) |
| GET | `/api/identity` | Get current identity and onion address |

### 11.2 Contacts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/contacts` | List all contacts |
| POST | `/api/contacts` | Add contact by onion address |
| POST | `/api/contacts/:id/delete` | Remove a contact |

### 11.3 Messages

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/messages/:address` | Get message history with a contact |
| POST | `/api/messages` | Send a message |

### 11.4 Files

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/files/upload` | Upload and send file (multipart) |
| POST | `/api/files/send` | Send file (base64 JSON) |
| GET | `/api/files/received/:address` | List received files from contact |
| GET | `/api/files/download/:id` | Download a received file |
| GET | `/api/files/status/:id` | Check transfer progress |
| GET | `/api/files/outgoing` | List outgoing transfers |

### 11.5 Voice

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/calls/start` | Initiate voice call |
| POST | `/api/calls/answer` | Answer incoming call |
| POST | `/api/calls/hangup` | End active call |

### 11.6 Groups

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/groups` | List joined groups |
| POST | `/api/groups` | Create a new group |
| POST | `/api/groups/join` | Join via invite token |
| POST | `/api/groups/:id/invite` | Invite a contact |
| POST | `/api/groups/:id/leave` | Leave a group |
| POST | `/api/groups/:id/delete` | Delete group locally |
| GET | `/api/groups/:id/members` | List group members |
| POST | `/api/groups/:id/promote` | Promote member to admin |
| GET | `/api/groups/:id/messages` | Get group message history |
| POST | `/api/groups/:id/messages` | Send group message |
| POST | `/api/groups/:id/files/upload` | Share file with group |
| GET | `/api/groups/:id/files` | List group files |
| POST | `/api/groups/:id/files/:fid/download` | Download group file |
| GET | `/api/groups/:id/files/:fid/serve` | Serve file to browser |

### 11.7 Invites

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/invites` | List pending group invites |
| POST | `/api/invites/:id/accept` | Accept a group invite |
| POST | `/api/invites/:id/decline` | Decline a group invite |

### 11.8 Daemon

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/daemon/status` | Check daemon status |
| POST | `/api/daemon/start` | Start the P2P daemon |
| POST | `/api/daemon/stop` | Stop the P2P daemon |
| POST | `/api/diagnostic/connectivity` | Test Tor connectivity |

---

## 12. Performance & Scalability

### 12.1 Benchmarks (Measured)

| Operation | Time |
|-----------|------|
| Identity generation (Ed25519 + onion derivation) | < 100 ms |
| Database read/write (SQLCipher) | < 50 ms |
| API response (local) | < 10 ms |
| Double Ratchet encrypt/decrypt | < 1 ms |
| Message serialization (Bincode) | < 0.1 ms |

### 12.2 Scalability Properties

| Dimension | Approach |
|-----------|----------|
| Users per server | Each user runs an isolated daemon; horizontal by design |
| Group message delivery | O(log n) via gossip mesh propagation |
| File transfer | Streamed in 32 KB chunks; no full-file buffering |
| Database | Indexed on user_id, group_id, timestamp |
| Async I/O | Tokio runtime; non-blocking throughout |
| Request body limits | 10 MB for API, 7 GB for file uploads |

### 12.3 Resource Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 128 MB | 256 MB |
| Disk | 100 MB (binary + deps) | 500 MB (with message history) |
| CPU | 1 core | 2+ cores |
| Network | Tor-capable connection | Broadband for voice/files |

---

## 13. Development Roadmap

### Phase 1 — Core Platform (Complete)

- [x] Ed25519 identity and V3 onion address generation
- [x] Double Ratchet encrypted 1:1 messaging
- [x] Tor onion service integration
- [x] SQLCipher encrypted local storage
- [x] REST API with session management
- [x] Browser-based web UI
- [x] Contact management
- [x] Message history and acknowledgments

### Phase 2 — Group & Media (Complete)

- [x] Decentralized group creation and role management
- [x] Gossip mesh message propagation
- [x] Epoch key rotation for group forward secrecy
- [x] Blind membership mode
- [x] Encrypted file transfer (1:1 and group)
- [x] Voice calling with Opus codec
- [x] CLI interface
- [x] Store-and-forward relay server

### Phase 3 — Hardening & Polish (In Progress)

- [ ] WebSocket push for real-time message delivery (replace polling)
- [ ] Message search and full-text indexing
- [ ] Contact verification ceremony (QR code / emoji comparison)
- [ ] Group member removal and banning
- [ ] Disappearing messages with configurable TTL
- [ ] UI polish: dark mode, notification sounds, desktop notifications
- [ ] Comprehensive integration test suite

### Phase 4 — Mobile & Distribution (Planned)

- [ ] Android app using JNI bindings
- [ ] iOS app (Swift wrapper over core library)
- [ ] Reproducible builds for binary verification
- [ ] Package distribution (Flatpak, APK, Homebrew)
- [ ] Tor Browser Bundle integration
- [ ] Automated relay discovery

### Phase 5 — Advanced Features (Future)

- [ ] Multi-device message synchronization (encrypted sync protocol)
- [ ] Offline group key ratcheting (MLS-style tree-based key exchange)
- [ ] Steganographic transport (pluggable transports for censorship resistance)
- [ ] Decentralized relay federation (no single relay operator)
- [ ] Post-quantum key exchange (ML-KEM hybrid)

---

## 14. Risk Analysis

### 14.1 Technical Risks

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Tor network congestion | Increased latency for all operations | Medium | Relay fallback for offline delivery; adaptive timeouts |
| Onion service reachability | Peers cannot connect when NAT/firewall blocks Tor | Low | Relay-based message queuing; user guidance on Tor setup |
| Cryptographic implementation flaw | Loss of message confidentiality | Low | Use audited libraries (dalek, RustCrypto); avoid custom crypto |
| SQLCipher key compromise | Local database exposure | Low | PBKDF2 with 100k iterations; OS-level disk encryption recommended |
| Gossip message amplification | Network flooding in large groups | Medium | TTL limits (10 hops); message deduplication; rate limiting |

### 14.2 Operational Risks

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Tor Project policy changes | Onion service API breakage | Low | arti-client abstraction layer; version pinning |
| Dependency supply chain attack | Malicious code in Rust crates | Low | Cargo audit; lock file pinning; vendored critical deps |
| User key loss | Permanent loss of identity and message history | Medium | Export/import feature; clear user guidance |

### 14.3 Limitations (By Design)

These are intentional trade-offs, not bugs:

- **No account recovery**: There is no server to reset your password. If you lose your key, you start fresh. This is the cost of having no central authority.
- **No cross-device sync**: Each device is independent. Syncing would require a coordination point that leaks metadata.
- **Tor dependency**: The system does not work without Tor. This is the cost of network anonymity.
- **No offline group key ratchet**: Group key rotation requires the founder to be online. A future MLS-based protocol could address this.

---

## 15. License

TorChat 2.0 is dual-licensed under:

- **MIT License**
- **Apache License 2.0**

at your option.

---

*This proposal describes the TorChat 2.0 system as designed and implemented. For setup instructions, see [SETUP.md](SETUP.md).*
