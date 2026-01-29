package com.torchat.app.ui.viewmodels

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.torchat.app.TorChatApplication
import com.torchat.app.ui.screens.ContactUiModel
import com.torchat.app.ui.screens.MessageStatus
import com.torchat.app.ui.screens.MessageUiModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * ViewModel for HomeScreen.
 */
class HomeViewModel : ViewModel() {

    data class UiState(
        val contacts: List<ContactUiModel> = emptyList(),
        val isConnected: Boolean = false,
        val isLoading: Boolean = true
    )

    private val _uiState = MutableStateFlow(UiState())
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    private val torChatCore = TorChatApplication.getInstance().torChatCore

    init {
        loadContacts()
    }

    private fun loadContacts() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true)

            val contacts = torChatCore.getContacts().map { contact ->
                ContactUiModel(
                    id = contact.id,
                    address = contact.address,
                    name = contact.name,
                    lastMessage = contact.lastMessage,
                    lastMessageTime = contact.lastMessageTime,
                    unreadCount = 0,
                    isOnline = false
                )
            }

            _uiState.value = UiState(
                contacts = contacts,
                isConnected = true,
                isLoading = false
            )
        }
    }

    fun refresh() {
        loadContacts()
    }
}

/**
 * ViewModel for ChatScreen.
 */
class ChatViewModel : ViewModel() {

    data class UiState(
        val contactId: String = "",
        val contactName: String? = null,
        val messages: List<MessageUiModel> = emptyList(),
        val isOnline: Boolean = false,
        val isLoading: Boolean = true
    )

    private val _uiState = MutableStateFlow(UiState())
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    private val torChatCore = TorChatApplication.getInstance().torChatCore

    fun loadChat(contactId: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                contactId = contactId,
                isLoading = true
            )

            // Load messages
            val messages = torChatCore.getMessages(contactId, 50).map { msg ->
                MessageUiModel(
                    id = msg.id,
                    content = msg.content,
                    timestamp = msg.timestamp,
                    isOutgoing = msg.outgoing,
                    status = when (msg.status) {
                        com.torchat.app.crypto.MessageStatus.SENDING -> MessageStatus.SENDING
                        com.torchat.app.crypto.MessageStatus.SENT -> MessageStatus.SENT
                        com.torchat.app.crypto.MessageStatus.DELIVERED -> MessageStatus.DELIVERED
                        com.torchat.app.crypto.MessageStatus.READ -> MessageStatus.READ
                        com.torchat.app.crypto.MessageStatus.FAILED -> MessageStatus.FAILED
                    }
                )
            }

            _uiState.value = UiState(
                contactId = contactId,
                contactName = null, // TODO: Load from contacts
                messages = messages,
                isOnline = false,
                isLoading = false
            )
        }
    }

    fun sendMessage(content: String) {
        viewModelScope.launch {
            val contactId = _uiState.value.contactId

            // Store message locally
            val msgId = torChatCore.storeMessage(contactId, content, true)

            // Add to UI immediately
            val newMessage = MessageUiModel(
                id = msgId,
                content = content,
                timestamp = System.currentTimeMillis() / 1000,
                isOutgoing = true,
                status = MessageStatus.SENDING
            )

            _uiState.value = _uiState.value.copy(
                messages = _uiState.value.messages + newMessage
            )

            // TODO: Actually send via Tor
        }
    }
}

/**
 * ViewModel for SetupScreen.
 */
class SetupViewModel : ViewModel() {

    data class UiState(
        val identity: String? = null,
        val fingerprint: String? = null,
        val isGenerating: Boolean = false,
        val error: String? = null
    )

    private val _uiState = MutableStateFlow(UiState())
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    private val torChatCore = TorChatApplication.getInstance().torChatCore

    fun generateIdentity() {
        viewModelScope.launch {
            _uiState.value = UiState(isGenerating = true)

            try {
                val identity = torChatCore.generateIdentity()
                val fingerprint = torChatCore.getFingerprint()

                _uiState.value = UiState(
                    identity = identity,
                    fingerprint = fingerprint,
                    isGenerating = false
                )
            } catch (e: Exception) {
                _uiState.value = UiState(
                    isGenerating = false,
                    error = e.message ?: "Failed to generate identity"
                )
            }
        }
    }
}
