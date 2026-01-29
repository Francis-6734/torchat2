package com.torchat.app.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import com.torchat.app.service.TorService

/**
 * Receives boot completed broadcast to restart Tor service.
 *
 * Ensures TorChat is available immediately after device boot
 * for receiving messages.
 */
class BootReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "BootReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED ||
            intent.action == "android.intent.action.QUICKBOOT_POWERON") {

            Log.i(TAG, "Boot completed, starting Tor service")

            // Check if auto-start is enabled in preferences
            val prefs = context.getSharedPreferences("torchat_prefs", Context.MODE_PRIVATE)
            val autoStart = prefs.getBoolean("auto_start_on_boot", true)

            if (autoStart) {
                startTorService(context)
            } else {
                Log.i(TAG, "Auto-start disabled, not starting Tor service")
            }
        }
    }

    private fun startTorService(context: Context) {
        val serviceIntent = Intent(context, TorService::class.java)

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent)
            } else {
                context.startService(serviceIntent)
            }
            Log.i(TAG, "Tor service started successfully")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start Tor service", e)
        }
    }
}
