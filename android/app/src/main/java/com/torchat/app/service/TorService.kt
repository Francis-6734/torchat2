package com.torchat.app.service

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.torchat.app.R
import com.torchat.app.TorChatApplication
import com.torchat.app.tor.TorManager
import com.torchat.app.tor.TorState
import com.torchat.app.ui.MainActivity
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.collectLatest

/**
 * Foreground service that maintains the Tor connection.
 * Required for background connectivity on Android 8+.
 */
class TorService : Service() {

    companion object {
        const val NOTIFICATION_ID = 1001
        const val ACTION_CONNECT = "com.torchat.app.action.CONNECT"
        const val ACTION_DISCONNECT = "com.torchat.app.action.DISCONNECT"
    }

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private lateinit var torManager: TorManager

    override fun onCreate() {
        super.onCreate()
        torManager = TorManager(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                startForeground(NOTIFICATION_ID, createNotification(TorState.Connecting))
                serviceScope.launch {
                    torManager.connect()
                    observeTorState()
                }
            }
            ACTION_DISCONNECT -> {
                torManager.disconnect()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }

        return START_STICKY
    }

    private suspend fun observeTorState() {
        torManager.connectionState.collectLatest { state ->
            val notification = createNotification(state)
            val manager = getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager
            manager.notify(NOTIFICATION_ID, notification)
        }
    }

    private fun createNotification(state: TorState): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val disconnectIntent = PendingIntent.getService(
            this,
            0,
            Intent(this, TorService::class.java).apply {
                action = ACTION_DISCONNECT
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val (title, text, icon) = when (state) {
            is TorState.Disconnected -> Triple(
                "TorChat",
                "Disconnected from Tor",
                R.drawable.ic_tor_disconnected
            )
            is TorState.Connecting -> Triple(
                "TorChat",
                "Connecting to Tor...",
                R.drawable.ic_tor_connecting
            )
            is TorState.Connected -> Triple(
                "TorChat",
                "Connected to Tor network",
                R.drawable.ic_tor_connected
            )
            is TorState.Error -> Triple(
                "TorChat",
                "Error: ${state.message}",
                R.drawable.ic_tor_error
            )
        }

        return NotificationCompat.Builder(this, TorChatApplication.CHANNEL_TOR_SERVICE)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(icon)
            .setContentIntent(pendingIntent)
            .addAction(
                R.drawable.ic_disconnect,
                "Disconnect",
                disconnectIntent
            )
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        serviceScope.cancel()
        torManager.disconnect()
        super.onDestroy()
    }
}
