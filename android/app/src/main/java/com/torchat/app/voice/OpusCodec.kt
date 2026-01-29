package com.torchat.app.voice

import android.util.Log

/**
 * Opus audio codec wrapper for encoding/decoding voice data.
 *
 * Uses the native Rust implementation via JNI for efficient
 * audio compression suitable for real-time voice over Tor.
 */
class OpusCodec private constructor(
    private val encoderHandle: Long,
    private val decoderHandle: Long,
    val sampleRate: Int,
    val channels: Int
) : AutoCloseable {

    companion object {
        private const val TAG = "OpusCodec"

        // Default voice settings optimized for Tor
        const val DEFAULT_SAMPLE_RATE = 48000
        const val DEFAULT_CHANNELS = 1  // Mono
        const val FRAME_SIZE_MS = 20
        const val FRAME_SIZE_SAMPLES = (DEFAULT_SAMPLE_RATE * FRAME_SIZE_MS) / 1000  // 960 samples

        init {
            System.loadLibrary("torchat_jni")
        }

        /**
         * Create a new Opus codec instance.
         */
        fun create(
            sampleRate: Int = DEFAULT_SAMPLE_RATE,
            channels: Int = DEFAULT_CHANNELS
        ): OpusCodec? {
            val encoderHandle = nativeCreateEncoder(sampleRate, channels)
            if (encoderHandle == 0L) {
                Log.e(TAG, "Failed to create Opus encoder")
                return null
            }

            val decoderHandle = nativeCreateDecoder(sampleRate, channels)
            if (decoderHandle == 0L) {
                Log.e(TAG, "Failed to create Opus decoder")
                nativeDestroyEncoder(encoderHandle)
                return null
            }

            return OpusCodec(encoderHandle, decoderHandle, sampleRate, channels)
        }

        // Native methods
        @JvmStatic
        private external fun nativeCreateEncoder(sampleRate: Int, channels: Int): Long

        @JvmStatic
        private external fun nativeDestroyEncoder(handle: Long)

        @JvmStatic
        private external fun nativeEncode(handle: Long, pcmData: ByteArray, frameSize: Int): ByteArray?

        @JvmStatic
        private external fun nativeCreateDecoder(sampleRate: Int, channels: Int): Long

        @JvmStatic
        private external fun nativeDestroyDecoder(handle: Long)

        @JvmStatic
        private external fun nativeDecode(handle: Long, opusData: ByteArray, frameSize: Int): ByteArray?
    }

    private var isClosed = false

    /**
     * Encode PCM audio data to Opus.
     *
     * @param pcmData Raw PCM audio bytes (16-bit signed LE)
     * @param frameSize Number of samples per channel
     * @return Encoded Opus data, or null on error
     */
    fun encode(pcmData: ByteArray, frameSize: Int = FRAME_SIZE_SAMPLES): ByteArray? {
        if (isClosed) {
            Log.w(TAG, "Codec is closed")
            return null
        }
        return nativeEncode(encoderHandle, pcmData, frameSize)
    }

    /**
     * Decode Opus data to PCM audio.
     *
     * @param opusData Encoded Opus data
     * @param frameSize Expected output samples per channel
     * @return Decoded PCM audio bytes (16-bit signed LE), or null on error
     */
    fun decode(opusData: ByteArray, frameSize: Int = FRAME_SIZE_SAMPLES): ByteArray? {
        if (isClosed) {
            Log.w(TAG, "Codec is closed")
            return null
        }
        return nativeDecode(decoderHandle, opusData, frameSize)
    }

    /**
     * Get the number of bytes per frame for PCM audio.
     */
    fun pcmFrameBytes(frameSize: Int = FRAME_SIZE_SAMPLES): Int {
        return frameSize * channels * 2  // 16-bit samples = 2 bytes
    }

    override fun close() {
        if (!isClosed) {
            isClosed = true
            nativeDestroyEncoder(encoderHandle)
            nativeDestroyDecoder(decoderHandle)
        }
    }
}
