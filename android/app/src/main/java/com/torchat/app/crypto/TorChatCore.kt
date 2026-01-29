package com.torchat.app.crypto

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * JNI wrapper for the TorChat Rust core library.
 * Provides secure messaging, identity management, and cryptographic operations.
 */
class TorChatCore(private val context: Context) {

    companion object {
        init {
            System.loadLibrary("torchat_jni")
        }

        // Native method declarations
        @JvmStatic
        private external fun nativeInit(dataDir: String): Long

        @JvmStatic
        private external fun nativeDestroy(handle: Long)

        @JvmStatic
        private external fun nativeGetIdentity(handle: Long): String?

        @JvmStatic
        private external fun nativeGenerateIdentity(handle: Long): String?

        @JvmStatic
        private external fun nativeGetFingerprint(handle: Long): String?

        @JvmStatic
        private external fun nativeAddContact(handle: Long, address: String, name: String?): Boolean

        @JvmStatic
        private external fun nativeGetContacts(handle: Long): Array<String>

        @JvmStatic
        private external fun nativeEncryptMessage(handle: Long, recipient: String, message: String): ByteArray?

        @JvmStatic
        private external fun nativeDecryptMessage(handle: Long, sender: String, ciphertext: ByteArray): String?

        @JvmStatic
        private external fun nativeStoreMessage(handle: Long, contactId: String, content: String, outgoing: Boolean): Long

        @JvmStatic
        private external fun nativeGetMessages(handle: Long, contactId: String, limit: Int): Array<String>

        @JvmStatic
        private external fun nativeDeleteMessage(handle: Long, messageId: Long): Boolean

        @JvmStatic
        private external fun nativeValidateOnionAddress(address: String): Boolean

        @JvmStatic
        private external fun nativeGetVersion(): String
    }

    private var nativeHandle: Long = 0
    private val dataDir: File = File(context.filesDir, "torchat")

    init {
        // Create data directory
        if (!dataDir.exists()) {
            dataDir.mkdirs()
        }

        // Initialize native library
        nativeHandle = nativeInit(dataDir.absolutePath)
        if (nativeHandle == 0L) {
            throw RuntimeException("Failed to initialize TorChat core")
        }
    }

    /**
     * Get the current identity's onion address.
     */
    suspend fun getIdentity(): String? = withContext(Dispatchers.IO) {
        nativeGetIdentity(nativeHandle)
    }

    /**
     * Generate a new identity (first run or reset).
     */
    suspend fun generateIdentity(): String? = withContext(Dispatchers.IO) {
        nativeGenerateIdentity(nativeHandle)
    }

    /**
     * Get the identity fingerprint for verification.
     */
    suspend fun getFingerprint(): String? = withContext(Dispatchers.IO) {
        nativeGetFingerprint(nativeHandle)
    }

    /**
     * Add a new contact by onion address.
     */
    suspend fun addContact(address: String, name: String? = null): Boolean = withContext(Dispatchers.IO) {
        if (!validateOnionAddress(address)) {
            return@withContext false
        }
        nativeAddContact(nativeHandle, address, name)
    }

    /**
     * Get all contacts as JSON array.
     */
    suspend fun getContacts(): List<Contact> = withContext(Dispatchers.IO) {
        val contactsJson = nativeGetContacts(nativeHandle)
        contactsJson.map { json ->
            // Parse JSON contact
            Contact.fromJson(json)
        }
    }

    /**
     * Encrypt a message for a recipient.
     */
    suspend fun encryptMessage(recipient: String, message: String): ByteArray? = withContext(Dispatchers.IO) {
        nativeEncryptMessage(nativeHandle, recipient, message)
    }

    /**
     * Decrypt a message from a sender.
     */
    suspend fun decryptMessage(sender: String, ciphertext: ByteArray): String? = withContext(Dispatchers.IO) {
        nativeDecryptMessage(nativeHandle, sender, ciphertext)
    }

    /**
     * Store a message locally.
     */
    suspend fun storeMessage(contactId: String, content: String, outgoing: Boolean): Long = withContext(Dispatchers.IO) {
        nativeStoreMessage(nativeHandle, contactId, content, outgoing)
    }

    /**
     * Get messages for a contact.
     */
    suspend fun getMessages(contactId: String, limit: Int = 50): List<Message> = withContext(Dispatchers.IO) {
        val messagesJson = nativeGetMessages(nativeHandle, contactId, limit)
        messagesJson.map { json ->
            Message.fromJson(json)
        }
    }

    /**
     * Delete a message.
     */
    suspend fun deleteMessage(messageId: Long): Boolean = withContext(Dispatchers.IO) {
        nativeDeleteMessage(nativeHandle, messageId)
    }

    /**
     * Validate an onion address format and checksum.
     */
    fun validateOnionAddress(address: String): Boolean {
        return nativeValidateOnionAddress(address)
    }

    /**
     * Get the library version.
     */
    fun getVersion(): String {
        return nativeGetVersion()
    }

    /**
     * Clean up native resources.
     */
    fun destroy() {
        if (nativeHandle != 0L) {
            nativeDestroy(nativeHandle)
            nativeHandle = 0
        }
    }

    protected fun finalize() {
        destroy()
    }
}

/**
 * Contact data class.
 */
data class Contact(
    val id: String,
    val address: String,
    val name: String?,
    val lastMessage: String?,
    val lastMessageTime: Long
) {
    companion object {
        fun fromJson(json: String): Contact {
            // Simple JSON parsing
            val id = json.substringAfter("\"id\":\"").substringBefore("\"")
            val address = json.substringAfter("\"address\":\"").substringBefore("\"")
            val name = json.substringAfter("\"name\":").let {
                if (it.startsWith("null")) null
                else it.substringAfter("\"").substringBefore("\"")
            }
            val lastMessage = json.substringAfter("\"lastMessage\":").let {
                if (it.startsWith("null")) null
                else it.substringAfter("\"").substringBefore("\"")
            }
            val lastMessageTime = json.substringAfter("\"lastMessageTime\":").substringBefore(",").toLongOrNull() ?: 0L

            return Contact(id, address, name, lastMessage, lastMessageTime)
        }
    }
}

/**
 * Message data class.
 */
data class Message(
    val id: Long,
    val content: String,
    val timestamp: Long,
    val outgoing: Boolean,
    val status: MessageStatus
) {
    companion object {
        fun fromJson(json: String): Message {
            val id = json.substringAfter("\"id\":").substringBefore(",").toLongOrNull() ?: 0L
            val content = json.substringAfter("\"content\":\"").substringBefore("\"")
            val timestamp = json.substringAfter("\"timestamp\":").substringBefore(",").toLongOrNull() ?: 0L
            val outgoing = json.substringAfter("\"outgoing\":").substringBefore(",").toBooleanStrictOrNull() ?: false
            val statusStr = json.substringAfter("\"status\":\"").substringBefore("\"")
            val status = MessageStatus.fromString(statusStr)

            return Message(id, content, timestamp, outgoing, status)
        }
    }
}

/**
 * Message delivery status.
 */
enum class MessageStatus {
    SENDING,
    SENT,
    DELIVERED,
    READ,
    FAILED;

    companion object {
        fun fromString(value: String): MessageStatus {
            return when (value.lowercase()) {
                "sending" -> SENDING
                "sent" -> SENT
                "delivered" -> DELIVERED
                "read" -> READ
                "failed" -> FAILED
                else -> SENDING
            }
        }
    }
}
