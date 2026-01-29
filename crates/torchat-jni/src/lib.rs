//! JNI bindings for TorChat core library.
//!
//! Provides Android/JVM access to the TorChat Rust core.

use jni::objects::{JClass, JObject, JString, JByteArray, JObjectArray};
use jni::sys::{jlong, jboolean, jint, JNI_TRUE, JNI_FALSE};
use jni::JNIEnv;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use torchat_core::identity::{auto_init, AutoIdentity};
use torchat_core::voice::{VoiceCallManager, CallState, AudioFrame, CallOffer};

/// Global state holder for the native library.
struct TorChatHandle {
    auto_identity: Option<AutoIdentity>,
    data_dir: String,
}

impl TorChatHandle {
    fn new(data_dir: String) -> Self {
        Self {
            auto_identity: None,
            data_dir,
        }
    }

    fn init(&mut self) -> Result<(), String> {
        match auto_init(&self.data_dir) {
            Ok(auto) => {
                self.auto_identity = Some(auto);
                Ok(())
            }
            Err(e) => Err(format!("Failed to initialize: {}", e)),
        }
    }

    fn get_identity(&self) -> Option<String> {
        self.auto_identity
            .as_ref()
            .and_then(|a| a.identity())
            .map(|id| id.onion_address().to_string())
    }

    fn get_fingerprint(&self) -> Option<String> {
        self.auto_identity
            .as_ref()
            .and_then(|a| a.identity())
            .map(|id| id.formatted_fingerprint())
    }
}

/// Contact JSON representation.
#[derive(Serialize, Deserialize)]
struct ContactJson {
    id: String,
    address: String,
    name: Option<String>,
    #[serde(rename = "lastMessage")]
    last_message: Option<String>,
    #[serde(rename = "lastMessageTime")]
    last_message_time: i64,
}

/// Message JSON representation.
#[derive(Serialize, Deserialize)]
struct MessageJson {
    id: i64,
    content: String,
    timestamp: i64,
    outgoing: bool,
    status: String,
}

// ============================================================================
// JNI Functions
// ============================================================================

/// Initialize the native library.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_crypto_TorChatCore_nativeInit(
    mut env: JNIEnv,
    _class: JClass,
    data_dir: JString,
) -> jlong {
    // Initialize Android logging
    #[cfg(target_os = "android")]
    {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Debug)
                .with_tag("TorChatCore"),
        );
    }

    let data_dir: String = match env.get_string(&data_dir) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };

    let mut handle = Box::new(TorChatHandle::new(data_dir));

    if handle.init().is_err() {
        return 0;
    }

    Box::into_raw(handle) as jlong
}

/// Destroy the native library handle.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_crypto_TorChatCore_nativeDestroy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        unsafe {
            let _ = Box::from_raw(handle as *mut TorChatHandle);
        }
    }
}

/// Get the current identity's onion address.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_crypto_TorChatCore_nativeGetIdentity<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    handle: jlong,
) -> JString<'a> {
    let handle = unsafe { &*(handle as *const TorChatHandle) };

    match handle.get_identity() {
        Some(address) => env.new_string(address).unwrap_or_else(|_| JObject::null().into()),
        None => JObject::null().into(),
    }
}

/// Generate a new identity.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_crypto_TorChatCore_nativeGenerateIdentity<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    handle: jlong,
) -> JString<'a> {
    let handle = unsafe { &mut *(handle as *mut TorChatHandle) };

    // Re-initialize to generate new identity
    if handle.init().is_ok() {
        if let Some(address) = handle.get_identity() {
            return env.new_string(address).unwrap_or_else(|_| JObject::null().into());
        }
    }

    JObject::null().into()
}

/// Get the identity fingerprint.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_crypto_TorChatCore_nativeGetFingerprint<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    handle: jlong,
) -> JString<'a> {
    let handle = unsafe { &*(handle as *const TorChatHandle) };

    match handle.get_fingerprint() {
        Some(fp) => env.new_string(fp).unwrap_or_else(|_| JObject::null().into()),
        None => JObject::null().into(),
    }
}

/// Add a contact.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_crypto_TorChatCore_nativeAddContact(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    address: JString,
    name: JString,
) -> jboolean {
    let handle = unsafe { &*(handle as *const TorChatHandle) };

    let address: String = match env.get_string(&address) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };

    let name: Option<String> = if name.is_null() {
        None
    } else {
        env.get_string(&name).ok().map(|s| s.into())
    };

    if let Some(auto) = &handle.auto_identity {
        if let Some(db) = auto.database() {
            if db.add_contact(&address, name.as_deref()).is_ok() {
                return JNI_TRUE;
            }
        }
    }

    JNI_FALSE
}

/// Get all contacts as JSON strings.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_crypto_TorChatCore_nativeGetContacts<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass,
    handle: jlong,
) -> JObjectArray<'a> {
    let handle = unsafe { &*(handle as *const TorChatHandle) };

    let mut contacts_json = Vec::new();

    if let Some(auto) = &handle.auto_identity {
        if let Some(db) = auto.database() {
            if let Ok(contacts) = db.list_contacts() {
                for (id, address, name) in contacts {
                    let contact = ContactJson {
                        id: id.to_string(),
                        address,
                        name,
                        last_message: None,
                        last_message_time: 0,
                    };
                    if let Ok(json) = serde_json::to_string(&contact) {
                        contacts_json.push(json);
                    }
                }
            }
        }
    }

    let string_class = env.find_class("java/lang/String").unwrap();
    let array = env
        .new_object_array(contacts_json.len() as i32, &string_class, JObject::null())
        .unwrap();

    for (i, json) in contacts_json.iter().enumerate() {
        let jstring = env.new_string(json).unwrap();
        env.set_object_array_element(&array, i as i32, jstring).unwrap();
    }

    array
}

/// Encrypt a message (placeholder - actual implementation uses Double Ratchet).
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_crypto_TorChatCore_nativeEncryptMessage<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass,
    _handle: jlong,
    _recipient: JString,
    message: JString,
) -> JByteArray<'a> {
    // For now, return the message bytes
    // Real implementation would use Double Ratchet encryption
    let message: String = match env.get_string(&message) {
        Ok(s) => s.into(),
        Err(_) => return JObject::null().into(),
    };

    match env.byte_array_from_slice(message.as_bytes()) {
        Ok(arr) => arr,
        Err(_) => JObject::null().into(),
    }
}

/// Decrypt a message (placeholder).
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_crypto_TorChatCore_nativeDecryptMessage<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    _handle: jlong,
    _sender: JString,
    ciphertext: JByteArray,
) -> JString<'a> {
    // For now, just return the bytes as string
    // Real implementation would use Double Ratchet decryption
    let bytes = match env.convert_byte_array(ciphertext) {
        Ok(b) => b,
        Err(_) => return JObject::null().into(),
    };

    match String::from_utf8(bytes) {
        Ok(s) => env.new_string(s).unwrap_or_else(|_| JObject::null().into()),
        Err(_) => JObject::null().into(),
    }
}

/// Store a message.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_crypto_TorChatCore_nativeStoreMessage(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    contact_id: JString,
    content: JString,
    outgoing: jboolean,
) -> jlong {
    let handle = unsafe { &*(handle as *const TorChatHandle) };

    let contact_id: i64 = match env.get_string(&contact_id) {
        Ok(s) => {
            let s: String = s.into();
            s.parse().unwrap_or(0)
        }
        Err(_) => return -1,
    };

    let content: String = match env.get_string(&content) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };

    let is_outgoing = outgoing == JNI_TRUE;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    if let Some(auto) = &handle.auto_identity {
        if let Some(db) = auto.database() {
            if let Ok(msg_id) = db.store_simple_message(contact_id, &content, is_outgoing, timestamp) {
                return msg_id;
            }
        }
    }

    -1
}

/// Get messages for a contact.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_crypto_TorChatCore_nativeGetMessages<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass,
    handle: jlong,
    contact_id: JString,
    limit: jint,
) -> JObjectArray<'a> {
    let handle = unsafe { &*(handle as *const TorChatHandle) };

    let contact_id: i64 = match env.get_string(&contact_id) {
        Ok(s) => {
            let s: String = s.into();
            s.parse().unwrap_or(0)
        }
        Err(_) => {
            let string_class = env.find_class("java/lang/String").unwrap();
            return env.new_object_array(0, &string_class, JObject::null()).unwrap();
        }
    };

    let mut messages_json = Vec::new();

    if let Some(auto) = &handle.auto_identity {
        if let Some(db) = auto.database() {
            if let Ok(messages) = db.load_simple_messages(contact_id, limit as u32) {
                for msg in messages {
                    let message = MessageJson {
                        id: msg.id,
                        content: msg.content,
                        timestamp: msg.timestamp,
                        outgoing: msg.is_outgoing,
                        status: "sent".to_string(),
                    };
                    if let Ok(json) = serde_json::to_string(&message) {
                        messages_json.push(json);
                    }
                }
            }
        }
    }

    let string_class = env.find_class("java/lang/String").unwrap();
    let array = env
        .new_object_array(messages_json.len() as i32, &string_class, JObject::null())
        .unwrap();

    for (i, json) in messages_json.iter().enumerate() {
        let jstring = env.new_string(json).unwrap();
        env.set_object_array_element(&array, i as i32, jstring).unwrap();
    }

    array
}

/// Delete a message.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_crypto_TorChatCore_nativeDeleteMessage(
    _env: JNIEnv,
    _class: JClass,
    _handle: jlong,
    _message_id: jlong,
) -> jboolean {
    // TODO: Implement message deletion
    JNI_TRUE
}

/// Validate an onion address.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_crypto_TorChatCore_nativeValidateOnionAddress(
    mut env: JNIEnv,
    _class: JClass,
    address: JString,
) -> jboolean {
    let address: String = match env.get_string(&address) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };

    // V3 onion address validation
    if !address.ends_with(".onion") {
        return JNI_FALSE;
    }

    let pubkey_part = &address[..address.len() - 6];
    if pubkey_part.len() != 56 {
        return JNI_FALSE;
    }

    // Validate base32 characters
    for c in pubkey_part.chars() {
        if !matches!(c, 'a'..='z' | '2'..='7') {
            return JNI_FALSE;
        }
    }

    JNI_TRUE
}

/// Get the library version.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_crypto_TorChatCore_nativeGetVersion<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
) -> JString<'a> {
    env.new_string(torchat_core::VERSION).unwrap_or_else(|_| JObject::null().into())
}

// ============================================================================
// Voice Call / Opus Codec JNI Functions
// ============================================================================

/// Global voice call manager.
static VOICE_MANAGER: Mutex<Option<VoiceCallManager>> = Mutex::new(None);

/// Initialize voice call system.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_voice_VoiceCallManager_nativeInitVoice(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    let mut manager = VOICE_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    *manager = Some(VoiceCallManager::new());
    JNI_TRUE
}

/// Start an outgoing call.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_voice_VoiceCallManager_nativeStartCall<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass,
    peer_address: JString,
) -> JByteArray<'a> {
    let peer: String = match env.get_string(&peer_address) {
        Ok(s) => s.into(),
        Err(_) => return JObject::null().into(),
    };

    let mut manager = VOICE_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mgr) = manager.as_mut() {
        match mgr.start_call(peer) {
            Ok((call_id, _offer)) => {
                return env.byte_array_from_slice(&call_id)
                    .unwrap_or_else(|_| JObject::null().into());
            }
            Err(_) => {}
        }
    }
    JObject::null().into()
}

/// Accept an incoming call.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_voice_VoiceCallManager_nativeAcceptCall(
    env: JNIEnv,
    _class: JClass,
    call_id: JByteArray,
) -> jboolean {
    let id_bytes = match env.convert_byte_array(call_id) {
        Ok(b) if b.len() == 16 => b,
        _ => return JNI_FALSE,
    };

    let mut call_id_arr = [0u8; 16];
    call_id_arr.copy_from_slice(&id_bytes);

    let mut manager = VOICE_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mgr) = manager.as_mut() {
        if let Some(call) = mgr.get_call(&call_id_arr) {
            // Create a dummy offer for acceptance (in real impl, would use received offer)
            let offer = CallOffer {
                capabilities: torchat_core::voice::AudioCapabilities::default(),
                audio_key_share: [0u8; 32],
            };
            if call.accept(&offer).is_ok() {
                return JNI_TRUE;
            }
        }
    }
    JNI_FALSE
}

/// Decline/hangup a call.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_voice_VoiceCallManager_nativeHangupCall(
    env: JNIEnv,
    _class: JClass,
    call_id: JByteArray,
) -> jboolean {
    let id_bytes = match env.convert_byte_array(call_id) {
        Ok(b) if b.len() == 16 => b,
        _ => return JNI_FALSE,
    };

    let mut call_id_arr = [0u8; 16];
    call_id_arr.copy_from_slice(&id_bytes);

    let mut manager = VOICE_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mgr) = manager.as_mut() {
        if let Some(call) = mgr.get_call(&call_id_arr) {
            call.hangup();
            return JNI_TRUE;
        }
    }
    JNI_FALSE
}

/// Get call state.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_voice_VoiceCallManager_nativeGetCallState(
    env: JNIEnv,
    _class: JClass,
    call_id: JByteArray,
) -> jint {
    let id_bytes = match env.convert_byte_array(call_id) {
        Ok(b) if b.len() == 16 => b,
        _ => return -1,
    };

    let mut call_id_arr = [0u8; 16];
    call_id_arr.copy_from_slice(&id_bytes);

    let mut manager = VOICE_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mgr) = manager.as_mut() {
        if let Some(call) = mgr.get_call(&call_id_arr) {
            return match call.state() {
                CallState::Idle => 0,
                CallState::Calling => 1,
                CallState::Ringing => 2,
                CallState::Connected => 3,
                CallState::Ending => 4,
            };
        }
    }
    -1
}

/// Opus encoder handle.
struct OpusEncoderHandle {
    encoder: audiopus::coder::Encoder,
}

/// Opus decoder handle.
struct OpusDecoderHandle {
    decoder: audiopus::coder::Decoder,
}

/// Create an Opus encoder.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_voice_OpusCodec_nativeCreateEncoder(
    _env: JNIEnv,
    _class: JClass,
    sample_rate: jint,
    channels: jint,
) -> jlong {
    let sample_rate = match sample_rate {
        8000 => audiopus::SampleRate::Hz8000,
        12000 => audiopus::SampleRate::Hz12000,
        16000 => audiopus::SampleRate::Hz16000,
        24000 => audiopus::SampleRate::Hz24000,
        48000 => audiopus::SampleRate::Hz48000,
        _ => return 0,
    };

    let channels = match channels {
        1 => audiopus::Channels::Mono,
        2 => audiopus::Channels::Stereo,
        _ => return 0,
    };

    match audiopus::coder::Encoder::new(sample_rate, channels, audiopus::Application::Voip) {
        Ok(encoder) => {
            let handle = Box::new(OpusEncoderHandle { encoder });
            Box::into_raw(handle) as jlong
        }
        Err(_) => 0,
    }
}

/// Destroy an Opus encoder.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_voice_OpusCodec_nativeDestroyEncoder(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        unsafe {
            let _ = Box::from_raw(handle as *mut OpusEncoderHandle);
        }
    }
}

/// Encode PCM audio to Opus.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_voice_OpusCodec_nativeEncode<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    handle: jlong,
    pcm_data: JByteArray,
    _frame_size: jint,
) -> JByteArray<'a> {
    if handle == 0 {
        return JObject::null().into();
    }

    let encoder = unsafe { &mut *(handle as *mut OpusEncoderHandle) };

    let pcm_bytes = match env.convert_byte_array(pcm_data) {
        Ok(b) => b,
        Err(_) => return JObject::null().into(),
    };

    // Convert bytes to i16 samples
    let samples: Vec<i16> = pcm_bytes
        .chunks_exact(2)
        .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    // Encode
    let mut output = vec![0u8; 4000]; // Max Opus frame size
    match encoder.encoder.encode(&samples, &mut output) {
        Ok(len) => {
            output.truncate(len);
            env.byte_array_from_slice(&output)
                .unwrap_or_else(|_| JObject::null().into())
        }
        Err(_) => JObject::null().into(),
    }
}

/// Create an Opus decoder.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_voice_OpusCodec_nativeCreateDecoder(
    _env: JNIEnv,
    _class: JClass,
    sample_rate: jint,
    channels: jint,
) -> jlong {
    let sample_rate = match sample_rate {
        8000 => audiopus::SampleRate::Hz8000,
        12000 => audiopus::SampleRate::Hz12000,
        16000 => audiopus::SampleRate::Hz16000,
        24000 => audiopus::SampleRate::Hz24000,
        48000 => audiopus::SampleRate::Hz48000,
        _ => return 0,
    };

    let channels = match channels {
        1 => audiopus::Channels::Mono,
        2 => audiopus::Channels::Stereo,
        _ => return 0,
    };

    match audiopus::coder::Decoder::new(sample_rate, channels) {
        Ok(decoder) => {
            let handle = Box::new(OpusDecoderHandle { decoder });
            Box::into_raw(handle) as jlong
        }
        Err(_) => 0,
    }
}

/// Destroy an Opus decoder.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_voice_OpusCodec_nativeDestroyDecoder(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        unsafe {
            let _ = Box::from_raw(handle as *mut OpusDecoderHandle);
        }
    }
}

/// Decode Opus to PCM audio.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_voice_OpusCodec_nativeDecode<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    handle: jlong,
    opus_data: JByteArray,
    frame_size: jint,
) -> JByteArray<'a> {
    if handle == 0 {
        return JObject::null().into();
    }

    let decoder = unsafe { &mut *(handle as *mut OpusDecoderHandle) };

    let opus_bytes = match env.convert_byte_array(opus_data) {
        Ok(b) => b,
        Err(_) => return JObject::null().into(),
    };

    // Decode
    let mut output = vec![0i16; frame_size as usize];
    let packet = match audiopus::packet::Packet::try_from(&opus_bytes[..]) {
        Ok(p) => p,
        Err(_) => return JObject::null().into(),
    };
    let signals = audiopus::MutSignals::try_from(&mut output[..]).unwrap();
    match decoder.decoder.decode(Some(packet), signals, false) {
        Ok(len) => {
            // Convert i16 samples to bytes
            let bytes: Vec<u8> = output[..len]
                .iter()
                .flat_map(|&s| s.to_le_bytes())
                .collect();
            env.byte_array_from_slice(&bytes)
                .unwrap_or_else(|_| JObject::null().into())
        }
        Err(_) => JObject::null().into(),
    }
}

/// Encrypt audio frame for sending.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_voice_VoiceCallManager_nativeEncryptAudio<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    call_id: JByteArray,
    opus_data: JByteArray,
) -> JByteArray<'a> {
    let id_bytes = match env.convert_byte_array(call_id) {
        Ok(b) if b.len() == 16 => b,
        _ => return JObject::null().into(),
    };

    let mut call_id_arr = [0u8; 16];
    call_id_arr.copy_from_slice(&id_bytes);

    let opus_bytes = match env.convert_byte_array(opus_data) {
        Ok(b) => b,
        Err(_) => return JObject::null().into(),
    };

    let mut manager = VOICE_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mgr) = manager.as_mut() {
        if let Some(call) = mgr.get_call(&call_id_arr) {
            if let Ok(frame) = call.encrypt_audio(&opus_bytes) {
                // Serialize frame for transmission
                if let Ok(json) = serde_json::to_vec(&frame) {
                    return env.byte_array_from_slice(&json)
                        .unwrap_or_else(|_| JObject::null().into());
                }
            }
        }
    }
    JObject::null().into()
}

/// Decrypt received audio frame.
#[no_mangle]
pub extern "system" fn Java_com_torchat_app_voice_VoiceCallManager_nativeDecryptAudio<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    call_id: JByteArray,
    encrypted_frame: JByteArray,
) -> JByteArray<'a> {
    let id_bytes = match env.convert_byte_array(call_id) {
        Ok(b) if b.len() == 16 => b,
        _ => return JObject::null().into(),
    };

    let mut call_id_arr = [0u8; 16];
    call_id_arr.copy_from_slice(&id_bytes);

    let frame_bytes = match env.convert_byte_array(encrypted_frame) {
        Ok(b) => b,
        Err(_) => return JObject::null().into(),
    };

    // Deserialize frame
    let frame: AudioFrame = match serde_json::from_slice(&frame_bytes) {
        Ok(f) => f,
        Err(_) => return JObject::null().into(),
    };

    let mut manager = VOICE_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mgr) = manager.as_mut() {
        if let Some(call) = mgr.get_call(&call_id_arr) {
            if let Ok(decrypted) = call.decrypt_audio(&frame) {
                return env.byte_array_from_slice(&decrypted)
                    .unwrap_or_else(|_| JObject::null().into());
            }
        }
    }
    JObject::null().into()
}
