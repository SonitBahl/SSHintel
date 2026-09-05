/**
 * SSHintel dashboard frontend.
 * Fetches telemetry from the API endpoints and renders it into the page.
 * All rendering uses textContent/escape to avoid XSS from attacker-controlled data.
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

async function fetchJson(url) {
    const resp = await fetch(url);
    return resp.json();
}

function renderMetrics(data) {
    document.querySelector('#metric-sessions .card-value').textContent = data.sessions;
    document.querySelector('#metric-unique-ips .card-value').textContent = data.unique_ips;
    document.querySelector('#metric-auth-attempts .card-value').textContent = data.auth_attempts;
    document.querySelector('#metric-auth-successes .card-value').textContent = data.auth_successes;
    document.querySelector('#metric-commands .card-value').textContent = data.commands;
}

function renderRanking(elementId, items, labelKey, countKey) {
    const container = document.getElementById(elementId);
    if (!items || items.length === 0) {
        container.innerHTML = '<div class="empty">No data</div>';
        return;
    }
    container.innerHTML = items.map(function(item, i) {
        return '<div class="rank-row">' +
            '<span class="rank-num">' + (i + 1) + '</span>' +
            '<span class="rank-name">' + escapeHtml(item[labelKey]) + '</span>' +
            '<span class="rank-count">' + item[countKey] + '</span>' +
        '</div>';
    }).join('');
}

function eventBadge(eventType) {
    var labels = {
        connect: 'Connect',
        auth_attempt: 'Auth',
        auth_success: 'Success',
        auth_failure: 'Failed',
        command: 'Command',
        disconnect: 'Disconnect',
        connection_rejected: 'Rejected',
        tarpit: 'Tarpit'
    };
    var label = labels[eventType] || escapeHtml(eventType);
    return '<span class="event-badge event-' + escapeHtml(eventType) + '">' + label + '</span>';
}

function eventDetails(event) {
    if (event.command) return escapeHtml(event.command);
    if (event.reason) return escapeHtml(event.reason);
    return '';
}

function renderRecent(events) {
    var tbody = document.getElementById('recent-body');
    if (!events || events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty">No telemetry yet</td></tr>';
        return;
    }
    tbody.innerHTML = events.map(function(e) {
        return '<tr>' +
            '<td>' + escapeHtml(e.timestamp || '') + '</td>' +
            '<td>' + eventBadge(e.event_type) + '</td>' +
            '<td>' + escapeHtml(e.source_ip) + '</td>' +
            '<td>' + escapeHtml(e.username) + '</td>' +
            '<td>' + eventDetails(e) + '</td>' +
        '</tr>';
    }).join('');
}

function drawActivityChart(rows) {
    var canvas = document.getElementById('activity-chart');
    var ctx = canvas.getContext('2d');
    var dpr = window.devicePixelRatio || 1;
    var rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = 160 * dpr;
    ctx.scale(dpr, dpr);
    var w = rect.width;
    var h = 160;
    var pad = { top: 10, right: 10, bottom: 24, left: 32 };
    ctx.clearRect(0, 0, w, h);

    if (!rows || rows.length === 0) {
        ctx.fillStyle = '#8b949e';
        ctx.font = '13px -apple-system, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('No activity recorded yet', w / 2, h / 2);
        return;
    }

    var counts = rows.map(function(r) { return r.count; });
    var maxCount = Math.max.apply(null, counts.concat([1]));
    var chartW = w - pad.left - pad.right;
    var chartH = h - pad.top - pad.bottom;
    var barGap = 4;
    var barWidth = Math.max(2, (chartW - barGap * (rows.length - 1)) / rows.length);

    ctx.fillStyle = '#8b949e';
    ctx.font = '10px -apple-system, sans-serif';
    ctx.textAlign = 'right';
    for (var i = 0; i <= 4; i++) {
        var val = Math.round((maxCount / 4) * i);
        var y = pad.top + chartH - (chartH / 4) * i;
        ctx.fillText(String(val), pad.left - 6, y + 3);
        ctx.strokeStyle = 'rgba(48, 54, 61, 0.5)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(pad.left, y);
        ctx.lineTo(w - pad.right, y);
        ctx.stroke();
    }

    rows.forEach(function(row, i) {
        var x = pad.left + i * (barWidth + barGap);
        var barH = (row.count / maxCount) * chartH;
        var y = pad.top + chartH - barH;
        ctx.fillStyle = '#58a6ff';
        ctx.fillRect(x, y, barWidth, barH);
        if (rows.length <= 24) {
            ctx.fillStyle = '#8b949e';
            ctx.font = '9px -apple-system, sans-serif';
            ctx.textAlign = 'center';
            var hour = row.hour ? String(row.hour).slice(-5, -3) : '';
            ctx.fillText(hour, x + barWidth / 2, h - 6);
        }
    });
}

async function refresh() {
    try {
        var results = await Promise.all([
            fetchJson('/api/metrics'),
            fetchJson('/api/top-commands'),
            fetchJson('/api/top-usernames'),
            fetchJson('/api/top-ips'),
            fetchJson('/api/recent-events'),
            fetchJson('/api/activity')
        ]);
        renderMetrics(results[0]);
        renderRanking('top-commands', results[1], 'command', 'count');
        renderRanking('top-usernames', results[2], 'username', 'count');
        renderRanking('top-ips', results[3], 'source_ip', 'count');
        renderRecent(results[4]);
        drawActivityChart(results[5]);
        document.getElementById('last-updated').textContent = 'Last updated: ' + new Date().toLocaleTimeString();
    } catch (err) {
        console.error('Dashboard refresh failed:', err);
        document.getElementById('last-updated').textContent = 'Error loading telemetry';
    }
}

refresh();
