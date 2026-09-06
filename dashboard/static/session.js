/**
 * SSHintel session investigation view.
 * Fetches session data from the API and renders the summary, timeline,
 * and command sequence. All rendering uses textContent/escape to avoid XSS.
 */

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function eventBadge(eventType) {
    var labels = {
        connect: 'Connect',
        auth_attempt: 'Auth Attempt',
        auth_success: 'Auth Success',
        auth_failure: 'Auth Failure',
        command: 'Command',
        disconnect: 'Disconnect',
        connection_rejected: 'Rejected',
        tarpit: 'Tarpit'
    };
    var label = labels[eventType] || escapeHtml(eventType);
    return '<span class="event-badge event-' + escapeHtml(eventType) + '">' + label + '</span>';
}

function formatTimestamp(ts) {
    if (!ts) return '—';
    return ts.replace('T', ' ').replace('Z', '').slice(0, 23);
}

function formatDuration(seconds) {
    if (seconds == null) return '—';
    var s = Number(seconds);
    if (s < 60) return s.toFixed(1) + 's';
    var m = Math.floor(s / 60);
    var rem = (s % 60).toFixed(0);
    return m + 'm ' + rem + 's';
}

function eventDescription(event) {
    switch (event.event_type) {
        case 'connect':
            return escapeHtml(event.source_ip) + ' connected';
        case 'auth_attempt':
            return 'username=' + escapeHtml(event.username);
        case 'auth_success':
            return 'authenticated as ' + escapeHtml(event.username);
        case 'auth_failure':
            return 'authentication failed for ' + escapeHtml(event.username);
        case 'command':
            var cwd = event.cwd ? ' <span class="cwd">cwd=' + escapeHtml(event.cwd) + '</span>' : '';
            return escapeHtml(event.command) + cwd;
        case 'disconnect':
            var reason = event.reason ? ' (' + escapeHtml(event.reason) + ')' : '';
            return 'session closed' + reason;
        case 'connection_rejected':
            return 'connection rejected';
        case 'tarpit':
            return 'tarpit activated';
        default:
            return '';
    }
}

function renderSummary(session) {
    var el = document.getElementById('summary-content');
    var authLabel = session.status || 'unknown';
    var authClass = '';
    if (authLabel === 'success' || authLabel === 'closed') authClass = 'auth-success';
    else if (authLabel === 'failure') authClass = 'auth-failure';

    el.innerHTML =
        '<div class="summary-grid">' +
            '<div class="summary-item"><span class="summary-label">Session ID</span>' +
                '<span class="summary-value session-id-full">' + escapeHtml(session.session_id) + '</span></div>' +
            '<div class="summary-item"><span class="summary-label">Source IP</span>' +
                '<span class="summary-value">' + escapeHtml(session.source_ip) + '</span></div>' +
            '<div class="summary-item"><span class="summary-label">Username</span>' +
                '<span class="summary-value">' + escapeHtml(session.username || '—') + '</span></div>' +
            '<div class="summary-item"><span class="summary-label">Started</span>' +
                '<span class="summary-value">' + formatTimestamp(session.started_at) + '</span></div>' +
            '<div class="summary-item"><span class="summary-label">Ended</span>' +
                '<span class="summary-value">' + formatTimestamp(session.ended_at) + '</span></div>' +
            '<div class="summary-item"><span class="summary-label">Duration</span>' +
                '<span class="summary-value">' + formatDuration(session.duration) + '</span></div>' +
            '<div class="summary-item"><span class="summary-label">Authentication</span>' +
                '<span class="summary-value ' + authClass + '">' + escapeHtml(authLabel) + '</span></div>' +
            '<div class="summary-item"><span class="summary-label">Disconnect Reason</span>' +
                '<span class="summary-value">' + escapeHtml(session.disconnect_reason || '—') + '</span></div>' +
        '</div>';
}

function renderTimeline(events) {
    var el = document.getElementById('timeline');
    if (!events || events.length === 0) {
        el.innerHTML = '<div class="empty">No events recorded for this session</div>';
        return;
    }
    el.innerHTML = events.map(function(e) {
        return '<div class="timeline-row">' +
            '<div class="timeline-time">' + formatTimestamp(e.timestamp) + '</div>' +
            '<div class="timeline-content">' +
                '<div class="timeline-event">' + eventBadge(e.event_type) + '</div>' +
                '<div class="timeline-desc">' + eventDescription(e) + '</div>' +
            '</div>' +
        '</div>';
    }).join('');
}

function renderCommandSequence(events) {
    var el = document.getElementById('command-sequence');
    var commands = events.filter(function(e) { return e.event_type === 'command'; });
    if (commands.length === 0) {
        el.innerHTML = '<div class="empty">No commands executed in this session</div>';
        return;
    }
    el.innerHTML = commands.map(function(e) {
        return '<div class="cmd-line">' +
            '<span class="cmd-prompt">$</span> ' +
            '<span class="cmd-text">' + escapeHtml(e.command) + '</span>' +
        '</div>';
    }).join('');
}

async function loadSession() {
    var sessionId = window.location.pathname.split('/').pop();
    try {
        var resp = await fetch('/api/session/' + encodeURIComponent(sessionId));
        if (resp.status === 404) {
            document.getElementById('session-status').textContent = 'Session not found';
            document.getElementById('summary-content').innerHTML = '<div class="empty">Session not found</div>';
            return;
        }
        var data = await resp.json();
        renderSummary(data.session);
        renderTimeline(data.events);
        renderCommandSequence(data.events);
        document.getElementById('session-status').textContent =
            data.events.length + ' events · session ' + escapeHtml(sessionId);
    } catch (err) {
        console.error('Failed to load session:', err);
        document.getElementById('session-status').textContent = 'Error loading session';
    }
}

loadSession();