// TorChat 2.0 - Group Chat Functionality

let currentGroup = null;
let userGroups = [];

// ========================================
// Group Management
// ========================================

async function loadGroups() {
    const result = await api('/api/groups');
    const list = document.getElementById('groups-list');
    const recentGroups = document.getElementById('recent-groups');
    const groupsEmpty = document.getElementById('groups-empty');

    if (result.success && result.data && result.data.length > 0) {
        userGroups = result.data;
        const html = result.data.map(g => `
            <div class="contact-item" onclick="openGroupChat('${g.group_id}', '${escapeHtml(g.name)}')">
                <div class="contact-name">🔒 ${escapeHtml(g.name)}</div>
                <div class="contact-address">${g.member_count} member${g.member_count !== 1 ? 's' : ''} • ${g.state}</div>
                ${g.is_founder ? '<div class="contact-status">Founder</div>' : ''}
            </div>
        `).join('');
        list.innerHTML = html;

        if (recentGroups) {
            recentGroups.innerHTML = html;
            recentGroups.style.display = 'block';
        }
        if (groupsEmpty) {
            groupsEmpty.style.display = 'none';
        }
    } else {
        list.innerHTML = '<div class="empty-state"><p>No groups yet</p><p style="margin-top: 10px; font-size: 13px;">Create a group or join one with an invite</p></div>';
        if (recentGroups) recentGroups.style.display = 'none';
        if (groupsEmpty) groupsEmpty.style.display = 'block';
    }
}

async function createGroup() {
    const name = document.getElementById('group-name').value.trim();
    const blindMembership = document.getElementById('group-blind').checked;
    const maxSize = parseInt(document.getElementById('group-max-size').value) || 50;
    const statusEl = document.getElementById('create-group-status');

    if (!name) {
        statusEl.innerHTML = '<div class="status-message error">Please enter a group name</div>';
        return;
    }

    statusEl.innerHTML = '<div class="status-message info">Creating group...</div>';
    const result = await api('/api/groups', 'POST', {
        name,
        blind_membership: blindMembership,
        max_size: maxSize
    });

    if (result.success) {
        statusEl.innerHTML = '<div class="status-message success">Group created!</div>';
        setTimeout(() => {
            closeCreateGroupModal();
            loadGroups();
            showToast('Group created successfully!');
        }, 1000);
    } else {
        statusEl.innerHTML = `<div class="status-message error">${result.error || 'Failed to create group'}</div>`;
    }
}

async function joinGroup() {
    const inviteToken = document.getElementById('invite-token').value.trim();
    const statusEl = document.getElementById('join-group-status');

    if (!inviteToken) {
        statusEl.innerHTML = '<div class="status-message error">Please enter an invite code</div>';
        return;
    }

    statusEl.innerHTML = '<div class="status-message info">Joining group...</div>';
    const result = await api('/api/groups/join', 'POST', { invite_token: inviteToken });

    if (result.success) {
        statusEl.innerHTML = '<div class="status-message success">Joined group!</div>';
        setTimeout(() => {
            closeJoinGroupModal();
            loadGroups();
            showToast('Joined group successfully!');
        }, 1000);
    } else {
        statusEl.innerHTML = `<div class="status-message error">${result.error || 'Failed to join group'}</div>`;
    }
}

async function sendGroupInvite(groupId) {
    const invitee = prompt('Enter the onion address of the person to invite:');
    if (!invitee) return;

    if (!invitee.endsWith('.onion')) {
        showToast('Invalid onion address');
        return;
    }

    const result = await api(`/api/groups/${groupId}/invite`, 'POST', {
        invitee_onion: invitee
    });

    if (result.success) {
        showToast('Invite sent successfully!');
    } else {
        showToast('Failed to send invite: ' + (result.error || 'Unknown error'));
    }
}

async function leaveGroup(groupId) {
    if (!confirm('Are you sure you want to leave this group?')) return;

    const result = await api(`/api/groups/${groupId}/leave`, 'POST');

    if (result.success) {
        showToast('Left group successfully');
        closeGroupChat();
        loadGroups();
    } else {
        showToast('Failed to leave group: ' + (result.error || 'Unknown error'));
    }
}

// ========================================
// Group Chat
// ========================================

async function openGroupChat(groupId, groupName) {
    currentGroup = { id: groupId, name: groupName };
    document.getElementById('group-chat-name').textContent = groupName;
    document.getElementById('group-chat-id').textContent = 'Group • ' + groupId.substring(0, 8) + '...';
    document.getElementById('tab-nav').style.display = 'none';
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.getElementById('group-chat-panel').classList.add('active');
    await loadGroupMessages(groupId);
    startGroupMessagePolling();
}

function closeGroupChat() {
    stopGroupMessagePolling();
    currentGroup = null;
    document.getElementById('group-chat-panel').classList.remove('active');
    document.getElementById('tab-nav').style.display = 'flex';
    document.getElementById('groups-panel').classList.add('active');
}

let groupMessagePollingInterval = null;
let lastGroupMessageCount = 0;

async function loadGroupMessages(groupId, isPolling = false) {
    const container = document.getElementById('group-messages-container');
    if (!isPolling) {
        container.innerHTML = '<div class="loading"><div class="spinner"></div><p>Loading...</p></div>';
    }

    const result = await api(`/api/groups/${groupId}/messages`);
    const messages = (result.success && result.data) ? result.data : [];

    if (messages.length > 0) {
        if (!isPolling || messages.length !== lastGroupMessageCount) {
            const previousCount = lastGroupMessageCount;
            lastGroupMessageCount = messages.length;

            container.innerHTML = messages.map(msg => {
                const isOurs = msg.outgoing;
                const senderLabel = isOurs ? 'You' : (msg.sender_id.substring(0, 8) + '...');

                return `
                    <div class="message ${isOurs ? 'sent' : 'received'}">
                        <div class="message-bubble">
                            ${!isOurs ? `<div class="message-sender">${senderLabel}</div>` : ''}
                            ${escapeHtml(msg.content)}
                            <div class="message-time">${formatTime(msg.timestamp)}</div>
                        </div>
                    </div>
                `;
            }).join('');

            container.scrollTop = container.scrollHeight;

            if (isPolling && messages.length > previousCount && !messages[messages.length - 1].outgoing) {
                showToast('New group message!');
            }
        }
    } else if (!isPolling) {
        container.innerHTML = '<div class="empty-state"><h3>No messages yet</h3><p>Be the first to send a message!</p></div>';
        lastGroupMessageCount = 0;
    }
}

function startGroupMessagePolling() {
    if (groupMessagePollingInterval) clearInterval(groupMessagePollingInterval);
    groupMessagePollingInterval = setInterval(() => {
        if (currentGroup) {
            loadGroupMessages(currentGroup.id, true);
        }
    }, 3000);
}

function stopGroupMessagePolling() {
    if (groupMessagePollingInterval) {
        clearInterval(groupMessagePollingInterval);
        groupMessagePollingInterval = null;
    }
    lastGroupMessageCount = 0;
}

async function sendGroupMessage() {
    if (!currentGroup) return;
    const input = document.getElementById('group-message-input');
    const content = input.value.trim();
    if (!content) return;

    const container = document.getElementById('group-messages-container');
    const emptyState = container.querySelector('.empty-state');
    if (emptyState) emptyState.remove();

    const msgEl = document.createElement('div');
    msgEl.className = 'message sent';
    msgEl.innerHTML = `<div class="message-bubble">${escapeHtml(content)}<div class="message-time">Sending...</div></div>`;
    container.appendChild(msgEl);
    container.scrollTop = container.scrollHeight;
    input.value = '';
    input.style.height = 'auto';

    const result = await api(`/api/groups/${currentGroup.id}/messages`, 'POST', { content });
    msgEl.querySelector('.message-time').textContent = result.success ? 'Sent' : 'Failed';
    if (!result.success) {
        showToast('Failed to send: ' + (result.error || 'Unknown error'));
    }
}

// ========================================
// Modal Functions
// ========================================

function openCreateGroupModal() {
    document.getElementById('create-group-modal').classList.add('open');
}

function closeCreateGroupModal() {
    document.getElementById('create-group-modal').classList.remove('open');
    document.getElementById('group-name').value = '';
    document.getElementById('group-blind').checked = false;
    document.getElementById('group-max-size').value = '50';
    document.getElementById('create-group-status').innerHTML = '';
}

function openJoinGroupModal() {
    document.getElementById('join-group-modal').classList.add('open');
}

function closeJoinGroupModal() {
    document.getElementById('join-group-modal').classList.remove('open');
    document.getElementById('invite-token').value = '';
    document.getElementById('join-group-status').innerHTML = '';
}

function openGroupMenu() {
    if (!currentGroup) return;

    const menu = document.createElement('div');
    menu.className = 'modal open';
    menu.innerHTML = `
        <div class="modal-content group-menu-modal">
            <h2 style="color: white; text-shadow: 0 2px 4px rgba(0,0,0,0.3);">🔒 ${escapeHtml(currentGroup.name)}</h2>
            <button class="btn" onclick="sendGroupInvite('${currentGroup.id}'); this.closest('.modal').remove()">
                📤 Invite Member
            </button>
            <button class="btn btn-secondary" style="background: rgba(255,255,255,0.9); color: #333;" onclick="leaveGroup('${currentGroup.id}'); this.closest('.modal').remove()">
                🚪 Leave Group
            </button>
            <button class="btn btn-secondary" style="background: rgba(255,255,255,0.9); color: #333;" onclick="this.closest('.modal').remove()">
                ✖️ Cancel
            </button>
        </div>
    `;
    menu.addEventListener('click', (e) => {
        if (e.target.classList.contains('modal')) menu.remove();
    });
    document.body.appendChild(menu);
}

// ========================================
// Event Listeners
// ========================================

document.addEventListener('DOMContentLoaded', () => {
    // Group message input
    const groupInput = document.getElementById('group-message-input');
    if (groupInput) {
        groupInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendGroupMessage();
            }
        });

        groupInput.addEventListener('input', (e) => {
            e.target.style.height = 'auto';
            e.target.style.height = Math.min(e.target.scrollHeight, 120) + 'px';
        });
    }

    // Modal click handlers
    const createModal = document.getElementById('create-group-modal');
    if (createModal) {
        createModal.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) closeCreateGroupModal();
        });
    }

    const joinModal = document.getElementById('join-group-modal');
    if (joinModal) {
        joinModal.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) closeJoinGroupModal();
        });
    }
});
