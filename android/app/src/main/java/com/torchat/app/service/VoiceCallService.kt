package com.torchat.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.torchat.app.R
import com.torchat.app.voice.CallState
import com.torchat.app.voice.VoiceCallManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Foreground service for managing voice calls.
 *
 * Maintains the call connection and audio streaming even when
 * the app is in the background.
 */
class VoiceCallService : Service() {

    companion object {
        private const val TAG = "VoiceCallService"

        const val CHANNEL_ID = "voice_call_channel"
        const val NOTIFICATION_ID = 2

        const val ACTION_START_CALL = "com.torchat.app.START_CALL"
        const val ACTION_ACCEPT_CALL = "com.torchat.app.ACCEPT_CALL"
        const val ACTION_DECLINE_CALL = "com.torchat.app.DECLINE_CALL"
        const val ACTION_HANGUP = "com.torchat.app.HANGUP"
        const val ACTION_MUTE = "com.torchat.app.MUTE"
        const val ACTION_UNMUTE = "com.torchat.app.UNMUTE"

        const val EXTRA_PEER_ADDRESS = "peer_address"

        fun startCall(context: Context, peerAddress: String) {
            val intent = Intent(context, VoiceCallService::class.java).apply {
                action = ACTION_START_CALL
                putExtra(EXTRA_PEER_ADDRESS, peerAddress)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun acceptCall(context: Context) {
            val intent = Intent(context, VoiceCallService::class.java).apply {
                action = ACTION_ACCEPT_CALL
            }
            context.startService(intent)
        }

        fun declineCall(context: Context) {
            val intent = Intent(context, VoiceCallService::class.java).apply {
                action = ACTION_DECLINE_CALL
            }
            context.startService(intent)
        }

        fun hangup(context: Context) {
            val intent = Intent(context, VoiceCallService::class.java).apply {
                action = ACTION_HANGUP
            }
            context.startService(intent)
        }
    }

    private val binder = VoiceCallBinder()
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private var durationJob: Job? = null

    private val callManager: VoiceCallManager by lazy {
        VoiceCallManager.getInstance()
    }

    inner class VoiceCallBinder : Binder() {
        fun getService(): VoiceCallService = this@VoiceCallService
        fun getCallManager(): VoiceCallManager = callManager
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        callManager.initialize()
        Log.i(TAG, "VoiceCallService created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START_CALL -> {
                val peerAddress = intent.getStringExtra(EXTRA_PEER_ADDRESS)
                if (peerAddress != null) {
                    startOutgoingCall(peerAddress)
                }
            }
            ACTION_ACCEPT_CALL -> {
                acceptIncomingCall()
            }
            ACTION_DECLINE_CALL -> {
                declineIncomingCall()
            }
            ACTION_HANGUP -> {
                endCall()
            }
            ACTION_MUTE -> {
                // Toggle handled in UI
            }
            ACTION_UNMUTE -> {
                // Toggle handled in UI
            }
        }

        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onDestroy() {
        super.onDestroy()
        durationJob?.cancel()
        scope.cancel()
        callManager.destroy()
        Log.i(TAG, "VoiceCallService destroyed")
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_calls),
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = getString(R.string.notification_channel_calls_desc)
                setSound(null, null)
                enableVibration(true)
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun startOutgoingCall(peerAddress: String) {
        if (callManager.startCall(peerAddress)) {
            startForegroundWithNotification(
                getString(R.string.call_outgoing, peerAddress),
                isOngoing = true
            )
            startDurationUpdates()
        }
    }

    private fun acceptIncomingCall() {
        if (callManager.acceptCall()) {
            val peerAddress = callManager.currentCall.value?.peerAddress ?: "Unknown"
            updateNotification(
                getString(R.string.call_connected),
                peerAddress,
                isOngoing = true
            )
            startDurationUpdates()
        }
    }

    private fun declineIncomingCall() {
        callManager.declineCall()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun endCall() {
        durationJob?.cancel()
        callManager.hangup()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun startDurationUpdates() {
        durationJob?.cancel()
        durationJob = scope.launch {
            while (isActive) {
                val call = callManager.currentCall.value
                if (call?.state == CallState.CONNECTED) {
                    val duration = callManager.getCallDuration()
                    val durationStr = formatDuration(duration)
                    updateNotification(
                        getString(R.string.call_connected),
                        "${call.peerAddress} - $durationStr",
                        isOngoing = true
                    )
                }
                delay(1000)
            }
        }
    }

    private fun formatDuration(seconds: Long): String {
        val mins = seconds / 60
        val secs = seconds % 60
        return String.format("%02d:%02d", mins, secs)
    }

    private fun startForegroundWithNotification(text: String, isOngoing: Boolean) {
        val notification = buildNotification(
            getString(R.string.app_name),
            text,
            isOngoing
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun updateNotification(title: String, text: String, isOngoing: Boolean) {
        val notification = buildNotification(title, text, isOngoing)
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NOTIFICATION_ID, notification)
    }

    private fun buildNotification(title: String, text: String, isOngoing: Boolean): Notification {
        // Intent to open app
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            packageManager.getLaunchIntentForPackage(packageName),
            PendingIntent.FLAG_IMMUTABLE
        )

        // Hangup action
        val hangupIntent = Intent(this, VoiceCallService::class.java).apply {
            action = ACTION_HANGUP
        }
        val hangupPendingIntent = PendingIntent.getService(
            this,
            1,
            hangupIntent,
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_call)
            .setContentIntent(pendingIntent)
            .setOngoing(isOngoing)
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                getString(R.string.call_hangup),
                hangupPendingIntent
            )
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
    }

    /**
     * Handle incoming call from network.
     */
    fun onIncomingCall(callId: ByteArray, peerAddress: String) {
        callManager.onIncomingCall(callId, peerAddress)

        // Show incoming call notification
        startForegroundWithNotification(
            getString(R.string.call_incoming, peerAddress),
            isOngoing = false
        )

        // Play ringtone, show full-screen UI, etc.
        // This would typically launch a full-screen incoming call activity
    }
}
