//! CLI command implementations.

use anyhow::{Context, Result, bail};
use std::path::Path;
use torchat_core::{
    identity::{auto_init, generate_identity, AutoIdentity, TorIdentity},
    storage::{derive_db_key, Database, DatabaseConfig},
};

/// Get password from user with secure input (masked).
fn get_password(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt)
        .context("Failed to read password")
}

/// Validate a v3 onion address with checksum verification.
///
/// V3 onion addresses are 56 base32 characters encoding:
/// - 32 bytes: Ed25519 public key
/// - 2 bytes: checksum (truncated SHA3-256)
/// - 1 byte: version (0x03)
fn validate_onion_address(address: &str) -> Result<()> {
    // Must end with .onion
    if !address.ends_with(".onion") {
        bail!("Address must end with .onion");
    }

    // Remove .onion suffix
    let pubkey_part = &address[..address.len() - 6];

    // V3 onion addresses are 56 characters (base32 encoded)
    if pubkey_part.len() != 56 {
        bail!("V3 onion address must be 56 characters + .onion (got {} chars)", pubkey_part.len());
    }

    // Validate base32 encoding (a-z, 2-7 only)
    for c in pubkey_part.chars() {
        if !matches!(c, 'a'..='z' | '2'..='7') {
            bail!("Invalid base32 character '{}' in address (must be a-z or 2-7)", c);
        }
    }

    // Decode base32 to verify structure
    let decoded = base32_decode(pubkey_part)?;
    if decoded.len() != 35 {
        bail!("Decoded address has wrong length");
    }

    // Last byte should be version 0x03
    if decoded[34] != 0x03 {
        bail!("Invalid onion address version (expected v3)");
    }

    // Verify checksum (bytes 32-33)
    let pubkey = &decoded[0..32];
    let checksum = &decoded[32..34];
    let expected_checksum = compute_onion_checksum(pubkey);

    if checksum != &expected_checksum[..2] {
        bail!("Onion address checksum verification failed");
    }

    Ok(())
}

/// Decode base32 (RFC 4648, lowercase)
fn base32_decode(input: &str) -> Result<Vec<u8>> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

    let mut bits = 0u64;
    let mut bit_count = 0;
    let mut output = Vec::new();

    for c in input.bytes() {
        let value = ALPHABET.iter().position(|&x| x == c)
            .ok_or_else(|| anyhow::anyhow!("Invalid base32 character"))?;

        bits = (bits << 5) | (value as u64);
        bit_count += 5;

        if bit_count >= 8 {
            bit_count -= 8;
            output.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }

    Ok(output)
}

/// Compute the 2-byte checksum for a v3 onion address
fn compute_onion_checksum(pubkey: &[u8]) -> [u8; 2] {
    use sha3::{Digest, Sha3_256};

    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update(&[0x03]); // version
    let hash = hasher.finalize();

    [hash[0], hash[1]]
}

/// Derive database key from password.
fn derive_key(password: &str, data_dir: &str) -> [u8; 32] {
    // Use data_dir as salt component for uniqueness
    let salt = format!("torchat2:{}", data_dir);
    let key = derive_db_key(password.as_bytes(), salt.as_bytes());
    *key
}

/// Initialize a new identity.
pub async fn init(data_dir: &str, force: bool) -> Result<()> {
    let db_path = format!("{}/torchat.db", data_dir);

    // Check for existing identity
    if Path::new(&db_path).exists() && !force {
        bail!("Identity already exists. Use --force to overwrite.");
    }

    // Create data directory
    std::fs::create_dir_all(data_dir)
        .context("Failed to create data directory")?;

    // Get password
    let password = get_password("Enter password for new identity: ")?;
    if password.is_empty() {
        bail!("Password cannot be empty");
    }

    let confirm = get_password("Confirm password: ")?;
    if password != confirm {
        bail!("Passwords do not match");
    }

    // Generate identity
    let identity = generate_identity()
        .context("Failed to generate identity")?;

    println!("\nGenerated new identity:");
    println!("  Onion address: {}", identity.onion_address());
    println!("  Fingerprint:   {}", identity.formatted_fingerprint());

    // Open database and store identity
    let key = derive_key(&password, data_dir);
    let config = DatabaseConfig {
        path: db_path,
        in_memory: false,
    };

    let db = Database::open(&config, &key)
        .context("Failed to create database")?;

    db.store_identity(&identity)
        .context("Failed to store identity")?;

    println!("\nIdentity saved successfully.");
    println!("\nIMPORTANT: Your onion address is your identity.");
    println!("Share it with contacts who want to message you.");
    println!("If you lose your password or data directory, your identity is LOST FOREVER.");

    Ok(())
}

/// Show current identity information.
#[allow(dead_code)]
pub async fn show_identity(data_dir: &str) -> Result<()> {
    let db_path = format!("{}/torchat.db", data_dir);

    if !Path::new(&db_path).exists() {
        bail!("No identity found. Run 'torchat init' first.");
    }

    let password = get_password("Enter password: ")?;
    let key = derive_key(&password, data_dir);

    let config = DatabaseConfig {
        path: db_path,
        in_memory: false,
    };

    let db = Database::open(&config, &key)
        .context("Failed to open database (wrong password?)")?;

    let identity = db.load_identity()
        .context("Failed to load identity")?
        .context("No identity in database")?;

    println!("\nYour TorChat Identity:");
    println!("  Onion address: {}", identity.onion_address());
    println!("  Fingerprint:   {}", identity.formatted_fingerprint());

    Ok(())
}

/// Start the TorChat daemon.
#[allow(dead_code)]
pub async fn start_daemon(data_dir: &str, _socks_port: u16, control_port: u16) -> Result<()> {
    use torchat_core::tor::{OnionService, OnionServiceConfig};

    let db_path = format!("{}/torchat.db", data_dir);

    if !Path::new(&db_path).exists() {
        bail!("No identity found. Run 'torchat init' first.");
    }

    let password = get_password("Enter password: ")?;
    let key = derive_key(&password, data_dir);

    let config = DatabaseConfig {
        path: db_path,
        in_memory: false,
    };

    let db = Database::open(&config, &key)
        .context("Failed to open database (wrong password?)")?;

    let identity = db.load_identity()
        .context("Failed to load identity")?
        .context("No identity in database")?;

    println!("\nStarting TorChat daemon...");
    println!("  Onion address: {}", identity.onion_address());

    // Configure onion service
    let service_config = OnionServiceConfig {
        local_port: 9878,
        control_addr: format!("127.0.0.1:{}", control_port),
        virtual_port: 443,
        data_dir: None,
    };

    // Start the onion service
    println!("\nConnecting to Tor...");
    let onion_service = OnionService::start(identity, service_config)
        .await
        .context("Failed to start onion service")?;

    println!("\nOnion service running!");
    println!("  Address: {}", onion_service.onion_address());
    println!("  Listening on port {} (virtual port {})",
             onion_service.local_port(),
             onion_service.virtual_port());
    println!("\nReady to receive connections. Press Ctrl+C to stop.");

    // Main loop: accept incoming connections
    let accept_handle = tokio::spawn(async move {
        loop {
            match onion_service.accept().await {
                Ok(stream) => {
                    let peer_addr = stream.peer_addr().ok();
                    println!("\n[INFO] Incoming connection from {:?}", peer_addr);
                    tokio::spawn(async move {
                        handle_incoming_connection(stream).await;
                    });
                }
                Err(e) => {
                    eprintln!("[ERROR] Accept failed: {}", e);
                }
            }
        }
    });

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    println!("\n\nShutting down...");

    // Clean up
    accept_handle.abort();

    Ok(())
}

/// Handle an incoming connection (placeholder).
async fn handle_incoming_connection(mut stream: tokio::net::TcpStream) {
    use tokio::io::AsyncReadExt;

    let mut buf = [0u8; 1024];
    match stream.read(&mut buf).await {
        Ok(n) if n > 0 => {
            println!("[DEBUG] Received {} bytes from peer", n);
        }
        Ok(_) => {
            println!("[DEBUG] Peer disconnected");
        }
        Err(e) => {
            eprintln!("[ERROR] Read error: {}", e);
        }
    }
}

/// Add a contact.
#[allow(dead_code)]
pub async fn add_contact(data_dir: &str, address: &str, name: Option<&str>) -> Result<()> {
    // Validate address format with checksum verification
    validate_onion_address(address)
        .context("Invalid onion address")?;

    let db_path = format!("{}/torchat.db", data_dir);
    let password = get_password("Enter password: ")?;
    let key = derive_key(&password, data_dir);

    let config = DatabaseConfig {
        path: db_path,
        in_memory: false,
    };

    let db = Database::open(&config, &key)
        .context("Failed to open database")?;

    // Check if contact already exists
    if db.get_contact_id(address)?.is_some() {
        bail!("Contact already exists");
    }

    db.add_contact(address, name)
        .context("Failed to add contact")?;

    println!("Contact added: {}", name.unwrap_or(address));

    Ok(())
}

/// List all contacts.
pub async fn list_contacts(data_dir: &str) -> Result<()> {
    let db_path = format!("{}/torchat.db", data_dir);
    let password = get_password("Enter password: ")?;
    let key = derive_key(&password, data_dir);

    let config = DatabaseConfig {
        path: db_path,
        in_memory: false,
    };

    let _db = Database::open(&config, &key)
        .context("Failed to open database")?;

    // TODO: Implement list_contacts in Database
    println!("Contact listing not yet implemented");

    Ok(())
}

/// Send a message.
pub async fn send_message(_data_dir: &str, address: &str, message: &str) -> Result<()> {
    println!("Sending message to {}...", address);
    println!("Message: {}", message);

    // TODO: Implement actual message sending
    // - Load session or create new one
    // - Encrypt message
    // - Connect to peer
    // - Send packet

    println!("Message sending not yet implemented");

    Ok(())
}

/// Show chat history.
pub async fn show_history(_data_dir: &str, address: &str, limit: u32) -> Result<()> {
    println!("Chat history with {} (last {} messages):", address, limit);

    // TODO: Implement history display
    println!("History display not yet implemented");

    Ok(())
}

/// Export identity for backup.
pub async fn export_identity(data_dir: &str, output: &str) -> Result<()> {
    let db_path = format!("{}/torchat.db", data_dir);
    let password = get_password("Enter password: ")?;
    let key = derive_key(&password, data_dir);

    let config = DatabaseConfig {
        path: db_path,
        in_memory: false,
    };

    let db = Database::open(&config, &key)
        .context("Failed to open database")?;

    let identity = db.load_identity()
        .context("Failed to load identity")?
        .context("No identity in database")?;

    // Get export password
    let export_password = get_password("Enter password for export file: ")?;
    let confirm = get_password("Confirm export password: ")?;
    if export_password != confirm {
        bail!("Passwords do not match");
    }

    // Encrypt and save
    let secret = identity.secret_key_bytes();
    let export_key = derive_key(&export_password, "export");

    let encrypted = torchat_core::crypto::encrypt_with_random_nonce(
        &export_key,
        &secret,
        b"torchat-export-v1",
    ).context("Failed to encrypt")?;

    std::fs::write(output, &encrypted)
        .context("Failed to write export file")?;

    println!("Identity exported to: {}", output);
    println!("\nWARNING: This file contains your secret key.");
    println!("Store it securely and delete it after importing.");

    Ok(())
}

/// Import identity from backup.
pub async fn import_identity(data_dir: &str, input: &str) -> Result<()> {
    let db_path = format!("{}/torchat.db", data_dir);

    if Path::new(&db_path).exists() {
        bail!("Identity already exists. Remove data directory first.");
    }

    // Read encrypted file
    let encrypted = std::fs::read(input)
        .context("Failed to read import file")?;

    // Get import password
    let import_password = get_password("Enter password for import file: ")?;
    let import_key = derive_key(&import_password, "export");

    // Decrypt
    let decrypted = torchat_core::crypto::decrypt_with_prepended_nonce(
        &import_key,
        &encrypted,
        b"torchat-export-v1",
    ).context("Failed to decrypt (wrong password?)")?;

    // Restore identity
    let identity = TorIdentity::from_secret_bytes(&decrypted)
        .context("Invalid identity data")?;

    println!("Importing identity: {}", identity.onion_address());

    // Get new password
    let password = get_password("Enter new password for this device: ")?;
    let confirm = get_password("Confirm password: ")?;
    if password != confirm {
        bail!("Passwords do not match");
    }

    // Create database
    std::fs::create_dir_all(data_dir)?;
    let key = derive_key(&password, data_dir);

    let config = DatabaseConfig {
        path: db_path,
        in_memory: false,
    };

    let db = Database::open(&config, &key)?;
    db.store_identity(&identity)?;

    println!("Identity imported successfully.");

    Ok(())
}

// ============================================================================
// Auto-init versions (no password required - uses device key)
// ============================================================================

/// Show identity with auto-generation on first run.
pub async fn show_identity_auto(data_dir: &str) -> Result<()> {
    let auto = auto_init(data_dir)
        .context("Failed to initialize identity")?;

    let identity = auto.identity()
        .context("No identity loaded")?;

    println!("\nYour TorChat Identity:");
    println!("  Onion address: {}", identity.onion_address());
    println!("  Fingerprint:   {}", identity.formatted_fingerprint());
    println!("\nShare your onion address with contacts who want to message you.");

    Ok(())
}

/// Start daemon with auto-init.
pub async fn start_daemon_auto(data_dir: &str, _socks_port: u16, control_port: u16) -> Result<()> {
    use torchat_core::tor::{OnionService, OnionServiceConfig};

    let auto = auto_init(data_dir)
        .context("Failed to initialize identity")?;

    let identity = auto.identity()
        .context("No identity loaded")?;

    println!("\nStarting TorChat daemon...");
    println!("  Onion address: {}", identity.onion_address());

    // We need to clone the identity since OnionService takes ownership
    let identity_clone = TorIdentity::from_secret_bytes(&identity.secret_key_bytes())
        .context("Failed to clone identity")?;

    // Configure onion service
    let service_config = OnionServiceConfig {
        local_port: 9878,
        control_addr: format!("127.0.0.1:{}", control_port),
        virtual_port: 443,
        data_dir: None,
    };

    // Start the onion service
    println!("\nConnecting to Tor...");
    let onion_service = OnionService::start(identity_clone, service_config)
        .await
        .context("Failed to start onion service")?;

    println!("\nOnion service running!");
    println!("  Address: {}", onion_service.onion_address());
    println!("  Listening on port {} (virtual port {})",
             onion_service.local_port(),
             onion_service.virtual_port());
    println!("\nReady to receive connections. Press Ctrl+C to stop.");

    // Main loop: accept incoming connections
    let accept_handle = tokio::spawn(async move {
        loop {
            match onion_service.accept().await {
                Ok(stream) => {
                    let peer_addr = stream.peer_addr().ok();
                    println!("\n[INFO] Incoming connection from {:?}", peer_addr);
                    tokio::spawn(async move {
                        handle_incoming_connection(stream).await;
                    });
                }
                Err(e) => {
                    eprintln!("[ERROR] Accept failed: {}", e);
                }
            }
        }
    });

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    println!("\n\nShutting down...");

    // Clean up
    accept_handle.abort();

    Ok(())
}

/// Add contact with auto-init.
pub async fn add_contact_auto(data_dir: &str, address: &str, name: Option<&str>) -> Result<()> {
    // Validate address format with checksum verification
    validate_onion_address(address)
        .context("Invalid onion address")?;

    let auto = auto_init(data_dir)
        .context("Failed to initialize identity")?;

    let db = auto.database()
        .context("Database not available")?;

    // Check if contact already exists
    if db.get_contact_id(address)?.is_some() {
        bail!("Contact already exists");
    }

    db.add_contact(address, name)
        .context("Failed to add contact")?;

    println!("Contact added: {}", name.unwrap_or(address));

    Ok(())
}

/// Start a voice call.
pub async fn start_call(data_dir: &str, address: &str) -> Result<()> {
    use torchat_core::voice::VoiceCall;

    // Validate address with checksum verification
    validate_onion_address(address)
        .context("Invalid onion address")?;

    let auto = auto_init(data_dir)
        .context("Failed to initialize identity")?;

    let identity = auto.identity()
        .context("No identity loaded")?;

    println!("\nStarting voice call...");
    println!("  From: {}", identity.onion_address());
    println!("  To:   {}", address);

    // Create outgoing call
    let mut call = VoiceCall::new_outgoing(address.to_string());
    let _offer = call.initiate()
        .context("Failed to create call offer")?;

    println!("\nCall initiated (ID: {})", hex::encode(&call.call_id[..8]));
    println!("State: {:?}", call.state());

    // TODO: Connect to peer via Tor and send offer
    // For now, just show call info
    println!("\nVoice calling requires Tor connection to peer.");
    println!("Full implementation pending - press Ctrl+C to cancel.");

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;

    call.hangup();
    println!("\nCall ended.");

    Ok(())
}

/// Reset identity (delete and regenerate).
pub async fn reset_identity(data_dir: &str, confirm: bool) -> Result<()> {
    if !confirm {
        bail!("Reset requires --confirm flag. WARNING: This destroys your identity permanently!");
    }

    println!("WARNING: This will permanently destroy your TorChat identity!");
    println!("Your onion address will change and contacts will need to re-add you.");
    println!();

    let mut auto = AutoIdentity::new(data_dir);

    // Show old identity if exists
    if auto.exists() {
        if let Ok(()) = auto.get_or_create().map(|_| ()) {
            if let Some(id) = auto.identity() {
                println!("Current identity: {}", id.onion_address());
            }
        }
    }

    println!("\nResetting identity...");

    let identity = auto.reset()
        .context("Failed to reset identity")?;

    println!("\nNew identity generated:");
    println!("  Onion address: {}", identity.onion_address());
    println!("  Fingerprint:   {}", identity.formatted_fingerprint());

    Ok(())
}
