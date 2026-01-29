//! Integration tests for voice call functionality.

#[cfg(feature = "voice")]
use torchat_core::voice::{
    AudioCapabilities, CallAnswer, CallOffer, CallState, VoiceCall, VoiceCallManager,
    FRAME_SIZE_SAMPLES, JITTER_BUFFER_SIZE, SAMPLE_RATE,
};

/// Test voice call state machine.
#[cfg(feature = "voice")]
#[test]
fn test_call_state_transitions() {
    // Caller initiates
    let mut caller = VoiceCall::new_outgoing("callee.onion".to_string());
    assert_eq!(caller.state(), CallState::Idle);

    let offer = caller.initiate().expect("initiate");
    assert_eq!(caller.state(), CallState::Calling);

    // Callee receives and accepts
    let mut callee = VoiceCall::new_incoming(caller.call_id, "caller.onion".to_string());
    assert_eq!(callee.state(), CallState::Ringing);

    let answer = callee.accept(&offer).expect("accept");
    assert_eq!(callee.state(), CallState::Connected);

    // Caller receives answer
    caller
        .on_answer(&answer, &offer.audio_key_share)
        .expect("on_answer");
    assert_eq!(caller.state(), CallState::Connected);

    // Call duration starts
    assert!(caller.duration().is_some());
    assert!(callee.duration().is_some());
}

/// Test call decline flow.
#[test]
fn test_call_decline() {
    let mut caller = VoiceCall::new_outgoing("callee.onion".to_string());
    let _offer = caller.initiate().expect("initiate");

    let mut callee = VoiceCall::new_incoming(caller.call_id, "caller.onion".to_string());
    assert_eq!(callee.state(), CallState::Ringing);

    callee.on_decline();
    assert_eq!(callee.state(), CallState::Idle);
}

/// Test hangup during call.
#[test]
fn test_call_hangup() {
    let mut caller = VoiceCall::new_outgoing("callee.onion".to_string());
    let offer = caller.initiate().expect("initiate");

    let mut callee = VoiceCall::new_incoming(caller.call_id, "caller.onion".to_string());
    let answer = callee.accept(&offer).expect("accept");
    caller.on_answer(&answer, &offer.audio_key_share).expect("on_answer");

    // Both sides connected
    assert_eq!(caller.state(), CallState::Connected);
    assert_eq!(callee.state(), CallState::Connected);

    // Caller hangs up
    caller.hangup();
    assert_eq!(caller.state(), CallState::Ending);

    // Callee receives hangup notification
    callee.on_hangup();
    assert_eq!(callee.state(), CallState::Idle);
}

/// Test audio encryption and decryption.
#[test]
fn test_audio_encryption() {
    let mut caller = VoiceCall::new_outgoing("callee.onion".to_string());
    let offer = caller.initiate().expect("initiate");

    let mut callee = VoiceCall::new_incoming(caller.call_id, "caller.onion".to_string());
    let answer = callee.accept(&offer).expect("accept");
    caller.on_answer(&answer, &offer.audio_key_share).expect("on_answer");

    // Simulate audio data (would be Opus-encoded in real use)
    let audio_data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    // Caller encrypts
    let frame = caller.encrypt_audio(&audio_data).expect("encrypt");

    // Verify frame has expected structure
    assert_eq!(frame.sequence, 0);
    assert!(!frame.data.is_empty());
    assert_ne!(frame.data, audio_data); // Should be encrypted

    // Callee decrypts
    let decrypted = callee.decrypt_audio(&frame).expect("decrypt");
    assert_eq!(decrypted, audio_data);

    // Verify sequence increments
    let frame2 = caller.encrypt_audio(&audio_data).expect("encrypt 2");
    assert_eq!(frame2.sequence, 1);
}

/// Test jitter buffer.
#[test]
fn test_jitter_buffer() {
    let mut caller = VoiceCall::new_outgoing("callee.onion".to_string());
    let offer = caller.initiate().expect("initiate");

    let mut callee = VoiceCall::new_incoming(caller.call_id, "caller.onion".to_string());
    let answer = callee.accept(&offer).expect("accept");
    caller.on_answer(&answer, &offer.audio_key_share).expect("on_answer");

    // Send multiple frames
    let mut frames = Vec::new();
    for i in 0..5 {
        let data = vec![i as u8; 10];
        let frame = caller.encrypt_audio(&data).expect("encrypt");
        frames.push(frame);
    }

    // Add frames out of order
    callee.buffer_frame(frames[2].clone());
    callee.buffer_frame(frames[0].clone());
    callee.buffer_frame(frames[4].clone());
    callee.buffer_frame(frames[1].clone());
    callee.buffer_frame(frames[3].clone());

    // Get frames in order
    let f0 = callee.get_buffered_frame().expect("frame 0");
    assert_eq!(f0.sequence, 0);

    let f1 = callee.get_buffered_frame().expect("frame 1");
    assert_eq!(f1.sequence, 1);

    let f2 = callee.get_buffered_frame().expect("frame 2");
    assert_eq!(f2.sequence, 2);
}

/// Test audio capabilities negotiation.
#[test]
fn test_audio_capabilities() {
    let caps = AudioCapabilities::default();

    assert!(caps.sample_rates.contains(&48000));
    assert!(caps.sample_rates.contains(&24000));
    assert!(caps.channels.contains(&1)); // Mono
    assert!(caps.channels.contains(&2)); // Stereo
    assert!(caps.max_bitrate > 0);
}

/// Test call statistics.
#[test]
fn test_call_statistics() {
    let mut caller = VoiceCall::new_outgoing("callee.onion".to_string());
    let offer = caller.initiate().expect("initiate");

    let mut callee = VoiceCall::new_incoming(caller.call_id, "caller.onion".to_string());
    let answer = callee.accept(&offer).expect("accept");
    caller.on_answer(&answer, &offer.audio_key_share).expect("on_answer");

    // Send some frames
    for _ in 0..10 {
        let frame = caller.encrypt_audio(&[1, 2, 3]).expect("encrypt");
        callee.decrypt_audio(&frame).expect("decrypt");
    }

    // Check caller stats
    let caller_stats = caller.stats();
    assert_eq!(caller_stats.packets_sent, 10);

    // Check callee stats
    let callee_stats = callee.stats();
    assert_eq!(callee_stats.packets_received, 10);
}

/// Test multiple audio frames with packet loss simulation.
#[test]
fn test_packet_loss_tracking() {
    let mut caller = VoiceCall::new_outgoing("callee.onion".to_string());
    let offer = caller.initiate().expect("initiate");

    let mut callee = VoiceCall::new_incoming(caller.call_id, "caller.onion".to_string());
    let answer = callee.accept(&offer).expect("accept");
    caller.on_answer(&answer, &offer.audio_key_share).expect("on_answer");

    // Send 10 frames but only deliver 7 (simulating 30% packet loss)
    let mut frames = Vec::new();
    for _ in 0..10 {
        let frame = caller.encrypt_audio(&[1, 2, 3]).expect("encrypt");
        frames.push(frame);
    }

    // Deliver frames 0, 1, 2, 5, 6, 7, 9 (skip 3, 4, 8)
    for i in [0, 1, 2, 5, 6, 7, 9] {
        callee.decrypt_audio(&frames[i]).expect("decrypt");
    }

    let stats = callee.stats();
    assert_eq!(stats.packets_received, 7);
    // Lost packets: jumped from 2 to 5 (lost 2), 7 to 9 (lost 1) = 3 lost
    assert!(stats.packets_lost >= 3);
}

/// Test call manager.
#[test]
fn test_call_manager() {
    let mut manager = VoiceCallManager::new();

    // Start a call
    let (call_id, _offer) = manager.start_call("peer.onion".to_string()).expect("start");

    // Verify call exists
    let call = manager.get_call(&call_id).expect("get call");
    assert_eq!(call.state(), CallState::Calling);

    // End call
    call.hangup();
    assert_eq!(call.state(), CallState::Ending);

    // Remove call
    let removed = manager.remove_call(&call_id);
    assert!(removed.is_some());
    assert!(manager.get_call(&call_id).is_none());
}

/// Test audio constants.
#[test]
fn test_audio_constants() {
    // Verify audio parameters are sensible
    assert_eq!(SAMPLE_RATE, 48000);
    assert_eq!(FRAME_SIZE_SAMPLES, 960); // 20ms at 48kHz
    assert!(JITTER_BUFFER_SIZE >= 5); // At least 100ms of buffer
}

/// Test cannot encrypt before call is connected.
#[test]
fn test_encrypt_requires_connection() {
    let mut caller = VoiceCall::new_outgoing("callee.onion".to_string());

    // Try to encrypt before initiating - should fail
    let result = caller.encrypt_audio(&[1, 2, 3]);
    assert!(result.is_err());

    // Initiate but don't complete connection
    let _offer = caller.initiate().expect("initiate");

    // Still should fail
    let result = caller.encrypt_audio(&[1, 2, 3]);
    assert!(result.is_err());
}

/// Test cannot initiate call twice.
#[test]
fn test_double_initiate_fails() {
    let mut caller = VoiceCall::new_outgoing("callee.onion".to_string());

    let _offer = caller.initiate().expect("first initiate");

    // Second initiate should fail
    let result = caller.initiate();
    assert!(result.is_err());
}

/// Test cannot accept when not ringing.
#[test]
fn test_accept_requires_ringing() {
    let mut callee = VoiceCall::new_incoming([0u8; 16], "caller.onion".to_string());

    // Decline first
    callee.on_decline();
    assert_eq!(callee.state(), CallState::Idle);

    // Now try to accept - should fail
    let offer = CallOffer {
        capabilities: AudioCapabilities::default(),
        audio_key_share: [0u8; 32],
    };

    let result = callee.accept(&offer);
    assert!(result.is_err());
}
