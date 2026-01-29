package com.torchat.app.voice

import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Voice call state.
 */
enum class CallState(val value: Int) {
    IDLE(0),
    CALLING(1),
    RINGING(2),
    CONNECTED(3),
    ENDING(4);

    companion object {
        fun fromValue(value: Int): CallState = entries.find { it.value == value } ?: IDLE
    }
}

/**
 * Voice call information.
 */
data class VoiceCallInfo(
    val callId: ByteArray,
    val peerAddress: String,
    val state: CallState,
    val isOutgoing: Boolean,
    val startTime: Long = 0,
    val duration: Long = 0
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is VoiceCallInfo) return false
        return callId.contentEquals(other.callId)
    }

    override fun hashCode(): Int = callId.contentHashCode()
}

/**
 * Manages voice calls with end-to-end encryption.
 *
 * Handles call signaling, audio encryption/decryption, and
 * coordinates with the audio capture/playback system.
 */
class VoiceCallManager private constructor() {

    companion object {
        private const val TAG = "VoiceCallManager"

        @Volatile
        private var instance: VoiceCallManager? = null

        fun getInstance(): VoiceCallManager {
            return instance ?: synchronized(this) {
                instance ?: VoiceCallManager().also { instance = it }
            }
        }

        init {
            System.loadLibrary("torchat_jni")
        }

        // Native methods
        @JvmStatic
        private external fun nativeInitVoice(): Boolean

        @JvmStatic
        private external fun nativeStartCall(peerAddress: String): ByteArray?

        @JvmStatic
        private external fun nativeAcceptCall(callId: ByteArray): Boolean

        @JvmStatic
        private external fun nativeHangupCall(callId: ByteArray): Boolean

        @JvmStatic
        private external fun nativeGetCallState(callId: ByteArray): Int

        @JvmStatic
        private external fun nativeEncryptAudio(callId: ByteArray, opusData: ByteArray): ByteArray?

        @JvmStatic
        private external fun nativeDecryptAudio(callId: ByteArray, encryptedFrame: ByteArray): ByteArray?
    }

    private val _currentCall = MutableStateFlow<VoiceCallInfo?>(null)
    val currentCall: StateFlow<VoiceCallInfo?> = _currentCall.asStateFlow()

    private val _incomingCall = MutableStateFlow<VoiceCallInfo?>(null)
    val incomingCall: StateFlow<VoiceCallInfo?> = _incomingCall.asStateFlow()

    private var audioManager: AudioStreamManager? = null
    private var opus: OpusCodec? = null
    private var isInitialized = false

    /**
     * Initialize the voice call system.
     */
    fun initialize(): Boolean {
        if (isInitialized) return true

        isInitialized = nativeInitVoice()
        if (!isInitialized) {
            Log.e(TAG, "Failed to initialize native voice system")
            return false
        }

        opus = OpusCodec.create()
        if (opus == null) {
            Log.e(TAG, "Failed to create Opus codec")
            isInitialized = false
            return false
        }

        Log.i(TAG, "Voice call manager initialized")
        return true
    }

    /**
     * Start an outgoing call.
     */
    fun startCall(peerAddress: String): Boolean {
        if (!isInitialized) {
            Log.e(TAG, "Voice system not initialized")
            return false
        }

        if (_currentCall.value != null) {
            Log.w(TAG, "Call already in progress")
            return false
        }

        val callId = nativeStartCall(peerAddress)
        if (callId == null) {
            Log.e(TAG, "Failed to start call")
            return false
        }

        _currentCall.value = VoiceCallInfo(
            callId = callId,
            peerAddress = peerAddress,
            state = CallState.CALLING,
            isOutgoing = true,
            startTime = System.currentTimeMillis()
        )

        Log.i(TAG, "Started call to $peerAddress")
        return true
    }

    /**
     * Accept an incoming call.
     */
    fun acceptCall(): Boolean {
        val incoming = _incomingCall.value ?: return false

        if (!nativeAcceptCall(incoming.callId)) {
            Log.e(TAG, "Failed to accept call")
            return false
        }

        _currentCall.value = incoming.copy(
            state = CallState.CONNECTED,
            startTime = System.currentTimeMillis()
        )
        _incomingCall.value = null

        // Start audio
        startAudio()

        Log.i(TAG, "Accepted call from ${incoming.peerAddress}")
        return true
    }

    /**
     * Decline an incoming call.
     */
    fun declineCall(): Boolean {
        val incoming = _incomingCall.value ?: return false

        nativeHangupCall(incoming.callId)
        _incomingCall.value = null

        Log.i(TAG, "Declined call from ${incoming.peerAddress}")
        return true
    }

    /**
     * End the current call.
     */
    fun hangup(): Boolean {
        val current = _currentCall.value ?: return false

        stopAudio()

        if (!nativeHangupCall(current.callId)) {
            Log.e(TAG, "Failed to hangup call")
        }

        _currentCall.value = null

        Log.i(TAG, "Ended call")
        return true
    }

    /**
     * Handle an incoming call.
     */
    fun onIncomingCall(callId: ByteArray, peerAddress: String) {
        if (_currentCall.value != null) {
            // Already in a call, auto-decline
            nativeHangupCall(callId)
            Log.w(TAG, "Auto-declined incoming call (already in call)")
            return
        }

        _incomingCall.value = VoiceCallInfo(
            callId = callId,
            peerAddress = peerAddress,
            state = CallState.RINGING,
            isOutgoing = false
        )

        Log.i(TAG, "Incoming call from $peerAddress")
    }

    /**
     * Handle call answer from peer.
     */
    fun onCallAnswered() {
        val current = _currentCall.value ?: return

        _currentCall.value = current.copy(
            state = CallState.CONNECTED,
            startTime = System.currentTimeMillis()
        )

        startAudio()

        Log.i(TAG, "Call connected")
    }

    /**
     * Handle call ended by peer.
     */
    fun onCallEnded() {
        stopAudio()
        _currentCall.value = null
        _incomingCall.value = null

        Log.i(TAG, "Call ended by peer")
    }

    /**
     * Encrypt audio data for transmission.
     */
    fun encryptAudio(opusData: ByteArray): ByteArray? {
        val current = _currentCall.value ?: return null
        return nativeEncryptAudio(current.callId, opusData)
    }

    /**
     * Decrypt received audio data.
     */
    fun decryptAudio(encryptedFrame: ByteArray): ByteArray? {
        val current = _currentCall.value ?: return null
        return nativeDecryptAudio(current.callId, encryptedFrame)
    }

    /**
     * Process and send captured audio.
     */
    fun processOutgoingAudio(pcmData: ByteArray): ByteArray? {
        val opus = this.opus ?: return null

        // Encode PCM to Opus
        val encoded = opus.encode(pcmData) ?: return null

        // Encrypt for transmission
        return encryptAudio(encoded)
    }

    /**
     * Process received audio for playback.
     */
    fun processIncomingAudio(encryptedFrame: ByteArray): ByteArray? {
        val opus = this.opus ?: return null

        // Decrypt
        val opusData = decryptAudio(encryptedFrame) ?: return null

        // Decode Opus to PCM
        return opus.decode(opusData)
    }

    private fun startAudio() {
        audioManager = AudioStreamManager(
            onAudioCaptured = { pcmData ->
                processOutgoingAudio(pcmData)?.let { encrypted ->
                    // TODO: Send encrypted audio over Tor
                }
            }
        )
        audioManager?.start()
    }

    private fun stopAudio() {
        audioManager?.stop()
        audioManager = null
    }

    /**
     * Get call duration in seconds.
     */
    fun getCallDuration(): Long {
        val current = _currentCall.value ?: return 0
        if (current.state != CallState.CONNECTED) return 0
        return (System.currentTimeMillis() - current.startTime) / 1000
    }

    /**
     * Clean up resources.
     */
    fun destroy() {
        hangup()
        opus?.close()
        opus = null
        isInitialized = false
    }
}
