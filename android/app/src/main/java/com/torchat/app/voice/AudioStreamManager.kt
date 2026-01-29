package com.torchat.app.voice

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaRecorder
import android.util.Log
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Manages audio capture and playback for voice calls.
 *
 * Captures audio from the microphone, sends to the codec/encryption pipeline,
 * and plays back received audio from peers.
 */
class AudioStreamManager(
    private val onAudioCaptured: (ByteArray) -> Unit
) {
    companion object {
        private const val TAG = "AudioStreamManager"

        // Audio settings matching Opus configuration
        const val SAMPLE_RATE = 48000
        const val CHANNEL_CONFIG_IN = AudioFormat.CHANNEL_IN_MONO
        const val CHANNEL_CONFIG_OUT = AudioFormat.CHANNEL_OUT_MONO
        const val AUDIO_FORMAT = AudioFormat.ENCODING_PCM_16BIT
        const val FRAME_SIZE_MS = 20
        const val FRAME_SIZE_SAMPLES = (SAMPLE_RATE * FRAME_SIZE_MS) / 1000  // 960 samples
        const val FRAME_SIZE_BYTES = FRAME_SIZE_SAMPLES * 2  // 16-bit = 2 bytes per sample
    }

    private var audioRecord: AudioRecord? = null
    private var audioTrack: AudioTrack? = null

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var captureJob: Job? = null
    private var playbackJob: Job? = null

    private val playbackQueue = ConcurrentLinkedQueue<ByteArray>()

    @Volatile
    private var isRunning = false

    @Volatile
    private var isMuted = false

    @Volatile
    private var isSpeakerOn = false

    /**
     * Check if audio permissions are granted.
     */
    fun hasPermission(context: Context): Boolean {
        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.RECORD_AUDIO
        ) == PackageManager.PERMISSION_GRANTED
    }

    /**
     * Start audio capture and playback.
     */
    @SuppressLint("MissingPermission")
    fun start(): Boolean {
        if (isRunning) {
            Log.w(TAG, "Audio already running")
            return true
        }

        // Initialize AudioRecord for capture
        val minBufferSize = AudioRecord.getMinBufferSize(
            SAMPLE_RATE,
            CHANNEL_CONFIG_IN,
            AUDIO_FORMAT
        )

        if (minBufferSize == AudioRecord.ERROR || minBufferSize == AudioRecord.ERROR_BAD_VALUE) {
            Log.e(TAG, "Invalid buffer size for AudioRecord")
            return false
        }

        val bufferSize = maxOf(minBufferSize, FRAME_SIZE_BYTES * 4)

        try {
            audioRecord = AudioRecord(
                MediaRecorder.AudioSource.VOICE_COMMUNICATION,
                SAMPLE_RATE,
                CHANNEL_CONFIG_IN,
                AUDIO_FORMAT,
                bufferSize
            )

            if (audioRecord?.state != AudioRecord.STATE_INITIALIZED) {
                Log.e(TAG, "Failed to initialize AudioRecord")
                audioRecord?.release()
                audioRecord = null
                return false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create AudioRecord", e)
            return false
        }

        // Initialize AudioTrack for playback
        val minPlaybackBuffer = AudioTrack.getMinBufferSize(
            SAMPLE_RATE,
            CHANNEL_CONFIG_OUT,
            AUDIO_FORMAT
        )

        val playbackBufferSize = maxOf(minPlaybackBuffer, FRAME_SIZE_BYTES * 4)

        try {
            audioTrack = AudioTrack.Builder()
                .setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                        .build()
                )
                .setAudioFormat(
                    AudioFormat.Builder()
                        .setSampleRate(SAMPLE_RATE)
                        .setChannelMask(CHANNEL_CONFIG_OUT)
                        .setEncoding(AUDIO_FORMAT)
                        .build()
                )
                .setBufferSizeInBytes(playbackBufferSize)
                .setTransferMode(AudioTrack.MODE_STREAM)
                .build()

            if (audioTrack?.state != AudioTrack.STATE_INITIALIZED) {
                Log.e(TAG, "Failed to initialize AudioTrack")
                audioRecord?.release()
                audioRecord = null
                audioTrack?.release()
                audioTrack = null
                return false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create AudioTrack", e)
            audioRecord?.release()
            audioRecord = null
            return false
        }

        isRunning = true

        // Start capture
        audioRecord?.startRecording()
        captureJob = scope.launch {
            captureLoop()
        }

        // Start playback
        audioTrack?.play()
        playbackJob = scope.launch {
            playbackLoop()
        }

        Log.i(TAG, "Audio streaming started")
        return true
    }

    /**
     * Stop audio capture and playback.
     */
    fun stop() {
        if (!isRunning) return

        isRunning = false

        captureJob?.cancel()
        playbackJob?.cancel()
        captureJob = null
        playbackJob = null

        audioRecord?.stop()
        audioRecord?.release()
        audioRecord = null

        audioTrack?.stop()
        audioTrack?.release()
        audioTrack = null

        playbackQueue.clear()

        Log.i(TAG, "Audio streaming stopped")
    }

    /**
     * Audio capture loop.
     */
    private suspend fun captureLoop() {
        val buffer = ByteArray(FRAME_SIZE_BYTES)

        while (isRunning && scope.isActive) {
            val record = audioRecord ?: break

            val bytesRead = record.read(buffer, 0, FRAME_SIZE_BYTES)

            if (bytesRead == FRAME_SIZE_BYTES) {
                if (!isMuted) {
                    // Send to processing pipeline
                    onAudioCaptured(buffer.copyOf())
                } else {
                    // Send silence when muted
                    onAudioCaptured(ByteArray(FRAME_SIZE_BYTES))
                }
            } else if (bytesRead < 0) {
                Log.e(TAG, "AudioRecord read error: $bytesRead")
                break
            }
        }
    }

    /**
     * Audio playback loop.
     */
    private suspend fun playbackLoop() {
        while (isRunning && scope.isActive) {
            val track = audioTrack ?: break

            val data = playbackQueue.poll()
            if (data != null) {
                track.write(data, 0, data.size)
            } else {
                // No data available, write silence to avoid underrun
                Thread.sleep(5)
            }
        }
    }

    /**
     * Queue audio data for playback.
     */
    fun queuePlayback(pcmData: ByteArray) {
        if (isRunning) {
            // Limit queue size to prevent memory issues
            while (playbackQueue.size > 20) {
                playbackQueue.poll()
            }
            playbackQueue.offer(pcmData)
        }
    }

    /**
     * Toggle mute state.
     */
    fun setMuted(muted: Boolean) {
        isMuted = muted
        Log.i(TAG, "Mute: $muted")
    }

    /**
     * Get mute state.
     */
    fun isMuted(): Boolean = isMuted

    /**
     * Toggle speaker output.
     */
    fun setSpeakerOn(context: Context, speakerOn: Boolean) {
        isSpeakerOn = speakerOn
        val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager
        audioManager.isSpeakerphoneOn = speakerOn
        Log.i(TAG, "Speaker: $speakerOn")
    }

    /**
     * Get speaker state.
     */
    fun isSpeakerOn(): Boolean = isSpeakerOn

    /**
     * Get current audio statistics.
     */
    fun getStats(): AudioStats {
        return AudioStats(
            captureBufferSize = audioRecord?.bufferSizeInFrames ?: 0,
            playbackBufferSize = audioTrack?.bufferSizeInFrames ?: 0,
            playbackQueueSize = playbackQueue.size,
            isRunning = isRunning
        )
    }

    /**
     * Clean up resources.
     */
    fun destroy() {
        stop()
        scope.cancel()
    }

    data class AudioStats(
        val captureBufferSize: Int,
        val playbackBufferSize: Int,
        val playbackQueueSize: Int,
        val isRunning: Boolean
    )
}
