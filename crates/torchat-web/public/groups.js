// TorChat 2.0 - Group Chat Functionality

let currentGroup = null;
let userGroups = [];
let pendingInvites = [];

// ========================================
// Pending Invites
// ========================================

async function loadPendingInvites() {
    const result = await api('/api/invites');
    const section = document.getElementById('pending-invites-section');
    const list = document.getElementById('pending-invites-list');

    if (result.success && result.data && result.data.length > 0) {
        pendingInvites = result.data;
        section.style.display = 'block';

        const html = result.data.map(inv => {
            const expiresDate = new Date(inv.expires_at * 1000);
            const now = new Date();
            const hoursLeft = Math.max(0, Math.floor((expiresDate - now) / (1000 * 60 * 60)));
            const expiresText = hoursLeft > 24
                ? `Expires in ${Math.floor(hoursLeft / 24)} days`
                : hoursLeft > 0
                    ? `Expires in ${hoursLeft} hours`
                    : 'Expires soon';

            return `
                <div class="invite-item" id="invite-${inv.id}">
                    <div class="invite-header">
                        <div class="invite-icon">📨</div>
                        <div class="invite-info">
                            <div class="invite-group-name">${escapeHtml(inv.group_name) || 'Unknown Group'}</div>
                            <div class="invite-from">From: ${inv.bootstrap_peer.substring(0, 16)}...</div>
                            <div class="invite-expires">⏰ ${expiresText}</div>
                        </div>
                    </div>
                    <div class="invite-actions">
                        <button class="invite-accept-btn" onclick="acceptInvite(${inv.id})">✓ Join Group</button>
                        <button class="invite-decline-btn" onclick="declineInvite(${inv.id})">✗ Decline</button>
                    </div>
                </div>
            `;
        }).join('');

        list.innerHTML = html;
    } else {
        pendingInvites = [];
        section.style.display = 'none';
        list.innerHTML = '';
    }
}

async function acceptInvite(inviteId) {
    const inviteEl = document.getElementById(`invite-${inviteId}`);
    if (inviteEl) {
        inviteEl.style.opacity = '0.5';
        inviteEl.style.pointerEvents = 'none';
    }

    const result = await api(`/api/invites/${inviteId}/accept`, 'POST');

    if (result.success) {
        showToast('Joined group successfully!');
        // Remove the invite from UI
        if (inviteEl) inviteEl.remove();
        // Check if any invites left
        const remaining = document.querySelectorAll('.invite-item');
        if (remaining.length === 0) {
            document.getElementById('pending-invites-section').style.display = 'none';
        }
        // Reload groups to show the new group
        await loadGroups();
    } else {
        if (inviteEl) {
            inviteEl.style.opacity = '1';
            inviteEl.style.pointerEvents = 'auto';
        }
        showToast('Failed to join: ' + (result.error || 'Unknown error'));
    }
}

async function declineInvite(inviteId) {
    if (!confirm('Decline this group invite?')) return;

    const inviteEl = document.getElementById(`invite-${inviteId}`);
    if (inviteEl) {
        inviteEl.style.opacity = '0.5';
    }

    const result = await api(`/api/invites/${inviteId}/decline`, 'POST');

    if (result.success) {
        showToast('Invite declined');
        if (inviteEl) inviteEl.remove();
        // Check if any invites left
        const remaining = document.querySelectorAll('.invite-item');
        if (remaining.length === 0) {
            document.getElementById('pending-invites-section').style.display = 'none';
        }
    } else {
        if (inviteEl) {
            inviteEl.style.opacity = '1';
        }
        showToast('Failed to decline invite');
    }
}

// ========================================
// Group Management
// ========================================

function getRoleBadge(role) {
    switch (role) {
        case 'founder':
            return '<span class="role-badge role-founder">Founder</span>';
        case 'admin':
            return '<span class="role-badge role-admin">Admin</span>';
        default:
            return '<span class="role-badge role-member">Member</span>';
    }
}

async function loadGroups() {
    // Also load pending invites
    loadPendingInvites();

    const result = await api('/api/groups');
    const list = document.getElementById('groups-list');
    const recentGroups = document.getElementById('recent-groups');
    const groupsEmpty = document.getElementById('groups-empty');

    if (result.success && result.data && result.data.length > 0) {
        userGroups = result.data;
        const html = result.data.map(g => {
            const role = g.role || (g.is_founder ? 'founder' : 'member');
            return `
            <div class="contact-item" onclick="openGroupChat('${g.group_id}', '${escapeHtml(g.name)}', '${role}')">
                <div class="contact-name">🔒 ${escapeHtml(g.name)}</div>
                <div class="contact-address">${g.member_count} member${g.member_count !== 1 ? 's' : ''} • ${g.state}</div>
                ${getRoleBadge(role)}
            </div>
        `;
        }).join('');
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

async function openGroupChat(groupId, groupName, role) {
    currentGroup = { id: groupId, name: groupName, role: role || 'member' };
    document.getElementById('group-chat-name').textContent = groupName;
    document.getElementById('group-chat-id').textContent = 'Group • ' + groupId.substring(0, 8) + '...';
    document.getElementById('tab-nav').style.display = 'none';
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.getElementById('group-chat-panel').classList.add('active');
    await loadGroupMessages(groupId);
    startGroupMessagePolling();

    // Update member count in header
    updateGroupMemberCount(groupId);
}

async function updateGroupMemberCount(groupId) {
    const members = await loadGroupMembers(groupId);
    const subtitle = document.getElementById('group-chat-id');
    if (subtitle && members.length > 0) {
        subtitle.textContent = `${members.length} member${members.length !== 1 ? 's' : ''} • tap to view`;
    }
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

                // Check if this is a file metadata message
                if (msg.content.startsWith('[FILE_META]')) {
                    try {
                        const meta = JSON.parse(msg.content.substring('[FILE_META]'.length));
                        const sizeStr = formatFileSize(meta.size);
                        const downloadBtn = !isOurs
                            ? `<button class="file-download-btn" onclick="downloadGroupFile('${groupId}', '${meta.file_id}', '${escapeHtml(meta.filename)}', this)">Download</button>`
                            : `<button class="file-download-btn" disabled>Shared</button>`;

                        return `
                            <div class="message ${isOurs ? 'sent' : 'received'}">
                                <div class="message-bubble">
                                    ${!isOurs ? `<div class="message-sender">${senderLabel}</div>` : ''}
                                    <div class="file-message">
                                        <div class="file-icon">&#128206;</div>
                                        <div class="file-info">
                                            <div class="file-name">${escapeHtml(meta.filename)}</div>
                                            <div class="file-size">${sizeStr}</div>
                                        </div>
                                        ${downloadBtn}
                                    </div>
                                    <div class="message-time">${formatTime(msg.timestamp)}</div>
                                </div>
                            </div>
                        `;
                    } catch (e) {
                        // Fall through to plain text rendering
                    }
                }

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
// Group File Sharing
// ========================================

async function handleGroupFileSelect(event) {
    const file = event.target.files[0];
    if (!file || !currentGroup) {
        showToast('Open a group chat first');
        event.target.value = '';
        return;
    }

    const MAX_SIZE = 5 * 1024 * 1024 * 1024;
    if (file.size > MAX_SIZE) {
        showToast('File size exceeds 5GB limit');
        event.target.value = '';
        return;
    }

    // Show upload progress in chat
    const container = document.getElementById('group-messages-container');
    const emptyState = container.querySelector('.empty-state');
    if (emptyState) emptyState.remove();

    const fileEl = document.createElement('div');
    fileEl.className = 'message sent';
    fileEl.innerHTML = `
        <div class="message-bubble">
            <div class="file-message">
                <div class="file-icon">&#128206;</div>
                <div class="file-info">
                    <div class="file-name">${escapeHtml(file.name)}</div>
                    <div class="file-size">${formatFileSize(file.size)}</div>
                    <div class="file-progress"><div class="file-progress-bar" style="width: 0%"></div></div>
                </div>
            </div>
            <div class="message-time">Uploading...</div>
        </div>
    `;
    container.appendChild(fileEl);
    container.scrollTop = container.scrollHeight;

    const progressBar = fileEl.querySelector('.file-progress-bar');
    const timeEl = fileEl.querySelector('.message-time');

    try {
        const formData = new FormData();
        formData.append('filename', file.name);
        formData.append('file', file);

        progressBar.style.width = '30%';

        const response = await fetch(
            `/api/groups/${currentGroup.id}/files/upload`,
            { method: 'POST', body: formData }
        );

        progressBar.style.width = '70%';
        const result = await response.json();

        if (result.success) {
            progressBar.style.width = '100%';
            timeEl.textContent = 'Shared';
            showToast(`File "${file.name}" shared with group!`);
            // Reload messages to show the file metadata message
            setTimeout(() => loadGroupMessages(currentGroup.id, true), 2000);
        } else {
            progressBar.style.width = '0%';
            progressBar.style.backgroundColor = '#ff4444';
            timeEl.textContent = 'Failed';
            showToast('Failed: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        progressBar.style.width = '0%';
        progressBar.style.backgroundColor = '#ff4444';
        timeEl.textContent = 'Error';
        showToast('Error: ' + error.message);
    }

    event.target.value = '';
}

async function downloadGroupFile(groupId, fileId, filename, btnEl) {
    if (btnEl) {
        btnEl.disabled = true;
        btnEl.textContent = 'Downloading...';
    }

    try {
        const result = await api(`/api/groups/${groupId}/files/${fileId}/download`, 'POST');

        if (result.success) {
            const responseData = result.data;
            // If already downloaded, serve it directly
            if (typeof responseData === 'string' && responseData.startsWith('already_downloaded:')) {
                // Serve the file
                window.open(`/api/groups/${groupId}/files/${fileId}/serve`, '_blank');
                if (btnEl) {
                    btnEl.textContent = 'Open';
                    btnEl.disabled = false;
                    btnEl.onclick = function() { window.open(`/api/groups/${groupId}/files/${fileId}/serve`, '_blank'); };
                }
            } else {
                showToast(`Downloading "${filename}" from sender...`);
                if (btnEl) btnEl.textContent = 'In progress...';

                // Poll for completion
                let attempts = 0;
                const pollInterval = setInterval(async () => {
                    attempts++;
                    const filesResult = await api(`/api/groups/${groupId}/files`);
                    if (filesResult.success && filesResult.data) {
                        const file = filesResult.data.find(f => f.file_id === fileId);
                        if (file && file.status === 'downloaded') {
                            clearInterval(pollInterval);
                            showToast(`"${filename}" downloaded!`);
                            window.open(`/api/groups/${groupId}/files/${fileId}/serve`, '_blank');
                            if (btnEl) {
                                btnEl.textContent = 'Open';
                                btnEl.disabled = false;
                                btnEl.onclick = function() { window.open(`/api/groups/${groupId}/files/${fileId}/serve`, '_blank'); };
                            }
                        } else if (file && file.status === 'failed') {
                            clearInterval(pollInterval);
                            showToast(`Download of "${filename}" failed`);
                            if (btnEl) {
                                btnEl.textContent = 'Retry';
                                btnEl.disabled = false;
                            }
                        }
                    }
                    if (attempts > 60) { // 5 minutes timeout
                        clearInterval(pollInterval);
                        if (btnEl) {
                            btnEl.textContent = 'Retry';
                            btnEl.disabled = false;
                        }
                    }
                }, 5000);
            }
        } else {
            showToast('Download failed: ' + (result.error || 'Unknown error'));
            if (btnEl) {
                btnEl.textContent = 'Retry';
                btnEl.disabled = false;
            }
        }
    } catch (error) {
        showToast('Error: ' + error.message);
        if (btnEl) {
            btnEl.textContent = 'Retry';
            btnEl.disabled = false;
        }
    }
}

// ========================================
// Group Member Management
// ========================================

async function loadGroupMembers(groupId) {
    const result = await api(`/api/groups/${groupId}/members`);
    if (result.success && result.data) {
        return result.data;
    }
    return [];
}

async function promoteToAdmin(groupId, memberId, memberEl) {
    if (!confirm('Promote this member to admin? Admins can invite new members.')) return;

    if (memberEl) {
        memberEl.style.opacity = '0.5';
        memberEl.style.pointerEvents = 'none';
    }

    const result = await api(`/api/groups/${groupId}/promote`, 'POST', {
        member_id: memberId
    });

    if (result.success) {
        showToast('Member promoted to admin!');
        // Refresh the member list modal
        openMembersModal(groupId);
    } else {
        if (memberEl) {
            memberEl.style.opacity = '1';
            memberEl.style.pointerEvents = 'auto';
        }
        showToast('Failed to promote: ' + (result.error || 'Unknown error'));
    }
}

async function openMembersModal(groupId) {
    const members = await loadGroupMembers(groupId);
    const isFounder = currentGroup && currentGroup.role === 'founder';

    // Remove existing modal if any
    const existing = document.getElementById('members-modal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = 'members-modal';
    modal.className = 'modal open';

    const memberListHtml = members.length > 0
        ? members.map(m => {
            const roleLabel = m.role === 'founder'
                ? '<span class="member-role-tag role-founder">Founder</span>'
                : m.role === 'admin'
                    ? '<span class="member-role-tag role-admin">Admin</span>'
                    : '<span class="member-role-tag role-member">Member</span>';

            const addr = m.onion_address
                ? m.onion_address.substring(0, 16) + '...'
                : 'Hidden';

            const promoteBtn = (isFounder && m.role === 'member')
                ? `<button class="promote-btn" onclick="promoteToAdmin('${groupId}', '${m.member_id}', this.closest('.member-item'))">Make Admin</button>`
                : '';

            return `
                <div class="member-item">
                    <div class="member-info">
                        <div class="member-addr">${addr}</div>
                        ${roleLabel}
                    </div>
                    ${promoteBtn}
                </div>
            `;
        }).join('')
        : '<div class="empty-state" style="padding: 20px;">No members found</div>';

    modal.innerHTML = `
        <div class="modal-content group-menu-modal">
            <h2 style="color: white; text-shadow: 0 2px 4px rgba(0,0,0,0.3);">Members (${members.length})</h2>
            <div class="members-list">
                ${memberListHtml}
            </div>
            <button class="btn btn-secondary" style="background: rgba(255,255,255,0.9); color: #333; margin-top: 12px;" onclick="this.closest('.modal').remove()">
                Close
            </button>
        </div>
    `;

    modal.addEventListener('click', (e) => {
        if (e.target.classList.contains('modal')) modal.remove();
    });
    document.body.appendChild(modal);
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

    const canInvite = currentGroup.role === 'founder' || currentGroup.role === 'admin';

    const menu = document.createElement('div');
    menu.className = 'modal open';
    menu.innerHTML = `
        <div class="modal-content group-menu-modal">
            <h2 style="color: white; text-shadow: 0 2px 4px rgba(0,0,0,0.3);">🔒 ${escapeHtml(currentGroup.name)}</h2>
            <div style="margin-bottom: 12px;">${getRoleBadge(currentGroup.role)}</div>
            <button class="btn" onclick="openMembersModal('${currentGroup.id}'); this.closest('.modal').remove()">
                👥 View Members
            </button>
            ${canInvite ? `
            <button class="btn" onclick="sendGroupInvite('${currentGroup.id}'); this.closest('.modal').remove()">
                📤 Invite Member
            </button>
            ` : `
            <button class="btn" disabled style="opacity: 0.5; cursor: not-allowed;">
                📤 Invite Member (Founder/Admin only)
            </button>
            `}
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
// Invite Polling
// ========================================

let invitePollingInterval = null;

function startInvitePolling() {
    if (invitePollingInterval) clearInterval(invitePollingInterval);
    invitePollingInterval = setInterval(() => {
        // Only poll when on the groups tab
        const groupsPanel = document.getElementById('groups-panel');
        if (groupsPanel && groupsPanel.classList.contains('active')) {
            loadPendingInvites();
        }
    }, 10000); // Check every 10 seconds
}

function stopInvitePolling() {
    if (invitePollingInterval) {
        clearInterval(invitePollingInterval);
        invitePollingInterval = null;
    }
}

// ========================================
// Event Listeners
// ========================================

document.addEventListener('DOMContentLoaded', () => {
    // Start polling for invites
    startInvitePolling();

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
