package com.torchat.app

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import com.torchat.app.crypto.TorChatCore

/**
 * TorChat Application class.
 * Initializes native library and notification channels.
 */
class TorChatApplication : Application() {

    companion object {
        const val CHANNEL_TOR_SERVICE = "tor_service"
        const val CHANNEL_MESSAGES = "messages"
        const val CHANNEL_CALLS = "calls"

        private lateinit var instance: TorChatApplication

        fun getInstance(): TorChatApplication = instance
    }

    // Native library wrapper
    lateinit var torChatCore: TorChatCore
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this

        // Initialize native library
        torChatCore = TorChatCore(this)

        // Create notification channels
        createNotificationChannels()
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

            // Tor Service Channel
            val torChannel = NotificationChannel(
                CHANNEL_TOR_SERVICE,
                "Tor Connection",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows Tor connection status"
                setShowBadge(false)
            }

            // Messages Channel
            val messagesChannel = NotificationChannel(
                CHANNEL_MESSAGES,
                "Messages",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "New message notifications"
                enableVibration(true)
            }

            // Calls Channel
            val callsChannel = NotificationChannel(
                CHANNEL_CALLS,
                "Voice Calls",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Incoming voice call notifications"
                enableVibration(true)
            }

            notificationManager.createNotificationChannels(
                listOf(torChannel, messagesChannel, callsChannel)
            )
        }
    }
}
