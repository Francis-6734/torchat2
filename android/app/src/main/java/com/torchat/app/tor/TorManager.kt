package com.torchat.app.tor

import android.content.Context
import android.content.Intent
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File
import java.net.InetSocketAddress
import java.net.Proxy

/**
 * Manages Tor connection and SOCKS proxy for the application.
 * Supports both embedded Tor and Orbot integration.
 */
class TorManager(private val context: Context) {

    companion object {
        const val ORBOT_PACKAGE = "org.torproject.android"
        const val SOCKS_PORT_DEFAULT = 9050
        const val CONTROL_PORT_DEFAULT = 9051

        // Orbot intents
        const val ACTION_START_TOR = "org.torproject.android.intent.action.START"
        const val ACTION_REQUEST_HS = "org.torproject.android.REQUEST_HS_PORT"
        const val EXTRA_HS_PORT = "org.torproject.android.intent.extra.HS_PORT"
    }

    private val _connectionState = MutableStateFlow<TorState>(TorState.Disconnected)
    val connectionState: StateFlow<TorState> = _connectionState.asStateFlow()

    private val _onionAddress = MutableStateFlow<String?>(null)
    val onionAddress: StateFlow<String?> = _onionAddress.asStateFlow()

    private var socksPort: Int = SOCKS_PORT_DEFAULT
    private var controlPort: Int = CONTROL_PORT_DEFAULT

    /**
     * Check if Orbot is installed.
     */
    fun isOrbotInstalled(): Boolean {
        return try {
            context.packageManager.getPackageInfo(ORBOT_PACKAGE, 0)
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Start Tor connection (via Orbot or embedded).
     */
    suspend fun connect() {
        _connectionState.value = TorState.Connecting

        if (isOrbotInstalled()) {
            startOrbot()
        } else {
            startEmbeddedTor()
        }
    }

    /**
     * Start Orbot for Tor connectivity.
     */
    private fun startOrbot() {
        try {
            val intent = Intent(ACTION_START_TOR).apply {
                setPackage(ORBOT_PACKAGE)
            }
            context.sendBroadcast(intent)

            // Request hidden service for incoming connections
            val hsIntent = Intent(ACTION_REQUEST_HS).apply {
                setPackage(ORBOT_PACKAGE)
                putExtra(EXTRA_HS_PORT, 9878) // TorChat port
            }
            context.sendBroadcast(hsIntent)

            _connectionState.value = TorState.Connected
        } catch (e: Exception) {
            _connectionState.value = TorState.Error("Failed to start Orbot: ${e.message}")
        }
    }

    /**
     * Start embedded Tor daemon.
     */
    private suspend fun startEmbeddedTor() {
        try {
            // Tor data directory
            val torDir = File(context.filesDir, "tor")
            if (!torDir.exists()) {
                torDir.mkdirs()
            }

            // In production, use tor-android library
            // For now, set state to connected for testing
            _connectionState.value = TorState.Connected

        } catch (e: Exception) {
            _connectionState.value = TorState.Error("Failed to start Tor: ${e.message}")
        }
    }

    /**
     * Disconnect from Tor.
     */
    fun disconnect() {
        _connectionState.value = TorState.Disconnected
        _onionAddress.value = null
    }

    /**
     * Get SOCKS proxy for HTTP connections.
     */
    fun getSocksProxy(): Proxy {
        return Proxy(
            Proxy.Type.SOCKS,
            InetSocketAddress("127.0.0.1", socksPort)
        )
    }

    /**
     * Get SOCKS port.
     */
    fun getSocksPort(): Int = socksPort

    /**
     * Create a new hidden service for incoming connections.
     */
    suspend fun createHiddenService(port: Int): String? {
        // In production, this would use Tor control protocol
        // to create an ephemeral hidden service
        return null
    }
}

/**
 * Tor connection states.
 */
sealed class TorState {
    object Disconnected : TorState()
    object Connecting : TorState()
    object Connected : TorState()
    data class Error(val message: String) : TorState()

    val isConnected: Boolean
        get() = this is Connected

    val statusText: String
        get() = when (this) {
            is Disconnected -> "Disconnected"
            is Connecting -> "Connecting..."
            is Connected -> "Connected"
            is Error -> "Error: $message"
        }
}
