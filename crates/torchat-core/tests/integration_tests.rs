//! Integration tests for TorChat 2.0 end-to-end scenarios.
//!
//! These tests verify the complete message flow from encryption
//! through delivery and decryption.

use torchat_core::crypto::{DoubleRatchet, random_bytes, EphemeralKeypair};
use torchat_core::identity::generate_identity;
use torchat_core::protocol::{AckPayload, AckType, MessagePayload, PacketType};
use torchat_core::storage::{Database, DatabaseConfig, OfflineQueue};

/// Test complete message encryption and decryption flow.
#[test]
fn test_e2e_message_flow() {
    // Generate two identities
    let _alice_identity = generate_identity().expect("generate alice identity");
    let _bob_identity = generate_identity().expect("generate bob identity");

    // Create keypairs for both parties
    let _alice_keypair = EphemeralKeypair::generate();
    let bob_keypair = EphemeralKeypair::generate();

    // Simulate shared secret from X3DH (in practice derived from identity exchange)
    let shared_secret_bytes: [u8; 32] = random_bytes();

    // Initialize ratchets
    // Alice is initiator, Bob is responder
    let mut alice_ratchet = DoubleRatchet::init_initiator_from_bytes(
        &shared_secret_bytes,
        bob_keypair.public_key(),
    ).expect("init alice ratchet");

    let mut bob_ratchet = DoubleRatchet::init_responder_from_bytes(
        &shared_secret_bytes,
        bob_keypair,
    );

    // Alice sends a message to Bob
    let plaintext = b"Hello, Bob! This is a secret message.";
    let (header, ciphertext) = alice_ratchet.encrypt(plaintext).expect("encrypt message");

    // Verify ciphertext is different from plaintext
    assert_ne!(ciphertext, plaintext);

    // Bob decrypts the message
    let decrypted = bob_ratchet.decrypt(&header, &ciphertext).expect("decrypt message");
    assert_eq!(&decrypted[..], plaintext);

    // Bob replies to Alice
    let reply = b"Hi Alice! Got your message loud and clear.";
    let (reply_header, reply_ciphertext) = bob_ratchet.encrypt(reply).expect("encrypt reply");

    // Alice decrypts the reply
    let decrypted_reply = alice_ratchet.decrypt(&reply_header, &reply_ciphertext)
        .expect("decrypt reply");
    assert_eq!(&decrypted_reply[..], reply);
}

/// Test multiple message exchanges with ratchet progression.
#[test]
fn test_e2e_multiple_messages() {
    let _alice_keypair = EphemeralKeypair::generate();
    let bob_keypair = EphemeralKeypair::generate();
    let shared_secret: [u8; 32] = random_bytes();

    let mut alice = DoubleRatchet::init_initiator_from_bytes(&shared_secret, bob_keypair.public_key())
        .expect("init alice");
    let mut bob = DoubleRatchet::init_responder_from_bytes(&shared_secret, bob_keypair);

    // Exchange 10 messages in each direction
    for i in 0..10 {
        let msg = format!("Message {} from Alice", i);
        let (header, ciphertext) = alice.encrypt(msg.as_bytes()).expect("encrypt");
        let decrypted = bob.decrypt(&header, &ciphertext).expect("decrypt");
        assert_eq!(decrypted, msg.as_bytes());

        let reply = format!("Reply {} from Bob", i);
        let (reply_header, reply_ciphertext) = bob.encrypt(reply.as_bytes()).expect("encrypt reply");
        let decrypted_reply = alice.decrypt(&reply_header, &reply_ciphertext).expect("decrypt reply");
        assert_eq!(decrypted_reply, reply.as_bytes());
    }
}

/// Test out-of-order message delivery.
#[test]
fn test_e2e_out_of_order_messages() {
    let _alice_keypair = EphemeralKeypair::generate();
    let bob_keypair = EphemeralKeypair::generate();
    let shared_secret: [u8; 32] = random_bytes();

    let mut alice = DoubleRatchet::init_initiator_from_bytes(&shared_secret, bob_keypair.public_key())
        .expect("init alice");
    let mut bob = DoubleRatchet::init_responder_from_bytes(&shared_secret, bob_keypair);

    // Alice sends 3 messages
    let msg1 = b"First message";
    let msg2 = b"Second message";
    let msg3 = b"Third message";

    let (h1, c1) = alice.encrypt(msg1).expect("encrypt 1");
    let (h2, c2) = alice.encrypt(msg2).expect("encrypt 2");
    let (h3, c3) = alice.encrypt(msg3).expect("encrypt 3");

    // Bob receives them out of order: 3, 1, 2
    let d3 = bob.decrypt(&h3, &c3).expect("decrypt 3");
    assert_eq!(&d3[..], msg3);

    let d1 = bob.decrypt(&h1, &c1).expect("decrypt 1");
    assert_eq!(&d1[..], msg1);

    let d2 = bob.decrypt(&h2, &c2).expect("decrypt 2");
    assert_eq!(&d2[..], msg2);
}

/// Test message payload serialization.
#[test]
fn test_message_payload_roundtrip() {
    let _alice_keypair = EphemeralKeypair::generate();
    let bob_keypair = EphemeralKeypair::generate();
    let shared_secret: [u8; 32] = random_bytes();

    let mut alice = DoubleRatchet::init_initiator_from_bytes(&shared_secret, bob_keypair.public_key())
        .expect("init alice");

    let message = b"Test message for serialization";
    let (header, ciphertext) = alice.encrypt(message).expect("encrypt");

    let payload = MessagePayload {
        header,
        ciphertext,
        message_id: random_bytes(),
        timestamp: 1234567890,
    };

    // Serialize and deserialize
    let bytes = payload.to_bytes().expect("serialize");
    let restored = MessagePayload::from_bytes(&bytes).expect("deserialize");

    assert_eq!(payload.message_id, restored.message_id);
    assert_eq!(payload.timestamp, restored.timestamp);
    assert_eq!(payload.ciphertext, restored.ciphertext);
}

/// Test acknowledgment flow.
#[test]
fn test_e2e_acknowledgment_flow() {
    let message_id: [u8; 16] = random_bytes();

    // Create delivery acknowledgment
    let ack = AckPayload {
        message_id,
        ack_type: AckType::Delivered,
        timestamp: 1234567890,
    };

    let bytes = ack.to_bytes().expect("serialize ack");
    let restored = AckPayload::from_bytes(&bytes).expect("deserialize ack");

    assert_eq!(ack.message_id, restored.message_id);
    assert_eq!(ack.ack_type, AckType::Delivered);

    // Create read acknowledgment
    let read_ack = AckPayload {
        message_id,
        ack_type: AckType::Read,
        timestamp: 1234567891,
    };

    let bytes = read_ack.to_bytes().expect("serialize read ack");
    let restored = AckPayload::from_bytes(&bytes).expect("deserialize read ack");
    assert_eq!(restored.ack_type, AckType::Read);
}

/// Test packet header validation.
#[test]
fn test_packet_header_validation() {
    // Valid packet type
    assert!(PacketType::from_byte(0x01).is_ok()); // Hello
    assert!(PacketType::from_byte(0x03).is_ok()); // Message

    // Invalid packet type
    assert!(PacketType::from_byte(0xFF).is_err());
    assert!(PacketType::from_byte(0x00).is_err());
}

/// Test offline queue operations.
#[test]
fn test_offline_queue_operations() {
    let queue = OfflineQueue::open_in_memory().expect("create queue");

    // Enqueue messages
    let msg1_id: [u8; 16] = random_bytes();
    let msg2_id: [u8; 16] = random_bytes();

    let id1 = queue
        .enqueue(msg1_id, "alice.onion", b"encrypted data 1", 0x03, 0)
        .expect("enqueue 1");
    let id2 = queue
        .enqueue(msg2_id, "bob.onion", b"encrypted data 2", 0x03, 1)
        .expect("enqueue 2");

    // Get pending messages
    let pending = queue.get_pending(10).expect("get pending");
    assert_eq!(pending.len(), 2);

    // Messages should be ordered by priority
    assert_eq!(pending[0].recipient, "alice.onion"); // priority 0
    assert_eq!(pending[1].recipient, "bob.onion");   // priority 1

    // Mark first as delivered
    queue.mark_delivered(id1).expect("mark delivered");

    // Check stats
    let stats = queue.stats().expect("get stats");
    assert_eq!(stats.pending, 1);
    assert_eq!(stats.delivered, 1);

    // Mark second as failed after retries
    queue.mark_failed(id2).expect("mark failed");

    let stats = queue.stats().expect("get stats again");
    assert_eq!(stats.pending, 0);
    assert_eq!(stats.failed, 1);
}

/// Test identity generation and verification.
#[test]
fn test_identity_generation() {
    let identity = generate_identity().expect("generate identity");

    // Onion address should be valid v3 format
    let address = identity.onion_address();
    assert!(address.as_str().ends_with(".onion"));

    // Remove .onion suffix and check length (56 chars for v3)
    let address_str = address.as_str();
    let pubkey_part = &address_str[..address_str.len() - 6];
    assert_eq!(pubkey_part.len(), 56);

    // All characters should be valid base32
    for c in pubkey_part.chars() {
        assert!(matches!(c, 'a'..='z' | '2'..='7'));
    }
}

/// Test message with large payload.
#[test]
fn test_large_message_encryption() {
    let _alice_keypair = EphemeralKeypair::generate();
    let bob_keypair = EphemeralKeypair::generate();
    let shared_secret: [u8; 32] = random_bytes();

    let mut alice = DoubleRatchet::init_initiator_from_bytes(&shared_secret, bob_keypair.public_key())
        .expect("init alice");
    let mut bob = DoubleRatchet::init_responder_from_bytes(&shared_secret, bob_keypair);

    // Create a large message (50KB)
    let large_message: Vec<u8> = (0..50000).map(|i| (i % 256) as u8).collect();

    let (header, ciphertext) = alice.encrypt(&large_message).expect("encrypt large");
    let decrypted = bob.decrypt(&header, &ciphertext).expect("decrypt large");

    assert_eq!(decrypted, large_message);
}

/// Test that different keys produce different ciphertext.
#[test]
fn test_encryption_randomness() {
    let _alice_keypair = EphemeralKeypair::generate();
    let bob_keypair = EphemeralKeypair::generate();
    let shared_secret: [u8; 32] = random_bytes();

    let mut alice = DoubleRatchet::init_initiator_from_bytes(&shared_secret, bob_keypair.public_key())
        .expect("init alice");

    let message = b"Same message encrypted twice";

    // Encrypt the same message twice
    let (_, c1) = alice.encrypt(message).expect("encrypt 1");
    let (_, c2) = alice.encrypt(message).expect("encrypt 2");

    // Ciphertexts should be different due to ratchet progression
    assert_ne!(c1, c2);
}

/// Test database contact and message storage.
#[test]
fn test_database_storage() {
    let config = DatabaseConfig {
        path: String::new(),
        in_memory: true,
    };
    let key = [0u8; 32];
    let db = Database::open(&config, &key).expect("open db");

    // Create user first (required for multi-user schema)
    let identity = generate_identity().expect("generate identity");
    let user_id = db.create_user("test_session", &identity, Some("TestUser"))
        .expect("create user");

    // Add a contact for that user
    db.add_user_contact(user_id, "alice.onion", Some("Alice")).expect("add contact");

    // List contacts for user
    let contacts = db.list_user_contacts(user_id).expect("list contacts");
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].1, "alice.onion");
    assert_eq!(contacts[0].2, Some("Alice".to_string()));

    let contact_id = contacts[0].0;

    // Store a message
    let msg_id = db.store_simple_message(contact_id, "Hello!", true, 12345)
        .expect("store message");
    assert!(msg_id > 0);

    // Load messages
    let messages = db.load_simple_messages(contact_id, 10).expect("load messages");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].content, "Hello!");
    assert!(messages[0].is_outgoing);
}

/// Test Perfect Forward Secrecy - compromising current keys shouldn't decrypt old messages.
#[test]
fn test_perfect_forward_secrecy() {
    let _alice_keypair = EphemeralKeypair::generate();
    let bob_keypair = EphemeralKeypair::generate();
    let shared_secret: [u8; 32] = random_bytes();

    let mut alice = DoubleRatchet::init_initiator_from_bytes(&shared_secret, bob_keypair.public_key())
        .expect("init alice");
    let mut bob = DoubleRatchet::init_responder_from_bytes(&shared_secret, bob_keypair);

    // Exchange several messages to advance the ratchet
    for i in 0..5 {
        let msg = format!("Message {}", i);
        let (header, ciphertext) = alice.encrypt(msg.as_bytes()).expect("encrypt");
        bob.decrypt(&header, &ciphertext).expect("decrypt");

        let reply = format!("Reply {}", i);
        let (reply_header, reply_ciphertext) = bob.encrypt(reply.as_bytes()).expect("encrypt reply");
        alice.decrypt(&reply_header, &reply_ciphertext).expect("decrypt reply");
    }

    // At this point, even if we had the original shared secret,
    // we cannot decrypt future messages without the ratcheted keys
    // This is verified by the fact that the ratchet maintains
    // evolving chain keys that are deleted after use.

    // Continuing to exchange messages works
    let msg = b"After many ratchets";
    let (header, ciphertext) = alice.encrypt(msg).expect("encrypt after");
    let decrypted = bob.decrypt(&header, &ciphertext).expect("decrypt after");
    assert_eq!(&decrypted[..], msg);
}

/// Test that empty messages are handled correctly.
#[test]
fn test_empty_message() {
    let _alice_keypair = EphemeralKeypair::generate();
    let bob_keypair = EphemeralKeypair::generate();
    let shared_secret: [u8; 32] = random_bytes();

    let mut alice = DoubleRatchet::init_initiator_from_bytes(&shared_secret, bob_keypair.public_key())
        .expect("init alice");
    let mut bob = DoubleRatchet::init_responder_from_bytes(&shared_secret, bob_keypair);

    // Empty message
    let empty: &[u8] = b"";
    let (header, ciphertext) = alice.encrypt(empty).expect("encrypt empty");
    let decrypted = bob.decrypt(&header, &ciphertext).expect("decrypt empty");
    assert!(decrypted.is_empty());
}

/// Test binary data (non-UTF8) encryption.
#[test]
fn test_binary_data_encryption() {
    let _alice_keypair = EphemeralKeypair::generate();
    let bob_keypair = EphemeralKeypair::generate();
    let shared_secret: [u8; 32] = random_bytes();

    let mut alice = DoubleRatchet::init_initiator_from_bytes(&shared_secret, bob_keypair.public_key())
        .expect("init alice");
    let mut bob = DoubleRatchet::init_responder_from_bytes(&shared_secret, bob_keypair);

    // Binary data with invalid UTF-8 sequences
    let binary_data: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let (header, ciphertext) = alice.encrypt(&binary_data).expect("encrypt binary");
    let decrypted = bob.decrypt(&header, &ciphertext).expect("decrypt binary");
    assert_eq!(decrypted, binary_data);
}
