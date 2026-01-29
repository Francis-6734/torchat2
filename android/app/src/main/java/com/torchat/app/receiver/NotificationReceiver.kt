package com.torchat.app.receiver

import android.app.RemoteInput
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.torchat.app.TorChatApplication
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Handles notification actions like mark as read and quick reply.
 */
class NotificationReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "NotificationReceiver"

        const val ACTION_MARK_READ = "com.torchat.app.MARK_READ"
        const val ACTION_REPLY = "com.torchat.app.REPLY"

        const val EXTRA_CONTACT_ID = "contact_id"
        const val EXTRA_MESSAGE_ID = "message_id"
        const val KEY_TEXT_REPLY = "key_text_reply"
    }

    private val scope = CoroutineScope(Dispatchers.IO)

    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            ACTION_MARK_READ -> handleMarkRead(context, intent)
            ACTION_REPLY -> handleReply(context, intent)
        }
    }

    private fun handleMarkRead(context: Context, intent: Intent) {
        val contactId = intent.getStringExtra(EXTRA_CONTACT_ID) ?: return
        val messageId = intent.getLongExtra(EXTRA_MESSAGE_ID, -1)

        Log.i(TAG, "Marking messages as read for contact: $contactId")

        scope.launch {
            try {
                val app = context.applicationContext as TorChatApplication
                // Mark messages as read in database
                // app.torChatCore.markMessagesRead(contactId, messageId)

                // Cancel the notification
                val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE)
                        as android.app.NotificationManager
                notificationManager.cancel(contactId.hashCode())
            } catch (e: Exception) {
                Log.e(TAG, "Failed to mark messages as read", e)
            }
        }
    }

    private fun handleReply(context: Context, intent: Intent) {
        val contactId = intent.getStringExtra(EXTRA_CONTACT_ID) ?: return

        // Get the reply text from RemoteInput
        val remoteInput = RemoteInput.getResultsFromIntent(intent)
        val replyText = remoteInput?.getCharSequence(KEY_TEXT_REPLY)?.toString()

        if (replyText.isNullOrBlank()) {
            Log.w(TAG, "Empty reply text")
            return
        }

        Log.i(TAG, "Sending quick reply to contact: $contactId")

        scope.launch {
            try {
                val app = context.applicationContext as TorChatApplication
                // Send the reply
                app.torChatCore.storeMessage(contactId, replyText, true)

                // Update notification to show reply was sent
                val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE)
                        as android.app.NotificationManager

                // Create updated notification showing "Reply sent"
                val notification = android.app.Notification.Builder(
                    context,
                    "messages_channel"
                )
                    .setSmallIcon(android.R.drawable.ic_menu_send)
                    .setContentTitle("Reply sent")
                    .setContentText("Your message was sent")
                    .setAutoCancel(true)
                    .build()

                notificationManager.notify(contactId.hashCode(), notification)

            } catch (e: Exception) {
                Log.e(TAG, "Failed to send quick reply", e)
            }
        }
    }
}
