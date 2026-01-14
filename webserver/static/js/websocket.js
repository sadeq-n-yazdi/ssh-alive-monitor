// WebSocket client with automatic reconnection and ping/pong
class WebSocketClient {
    constructor(config = {}) {
        this.url = config.url || `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws`;
        this.reconnectDelay = 1000;
        this.maxReconnectDelay = 30000;
        this.reconnectAttempts = 0;
        this.ws = null;
        this.pingTimeout = null;
        this.expectedPingInterval = 35000; // 30s + 5s grace period
    }

    connect() {
        console.log('[WS] Connecting to', this.url);

        try {
            this.ws = new WebSocket(this.url);
        } catch (error) {
            console.error('[WS] Connection error:', error);
            this.reconnect();
            return;
        }

        this.ws.onopen = () => {
            console.log('[WS] Connected');
            this.reconnectDelay = 1000;
            this.reconnectAttempts = 0;
            this.resetPingTimeout();

            // Dispatch connected event
            window.dispatchEvent(new CustomEvent('ws-connected'));
        };

        this.ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);

                // Reset ping timeout on any message
                this.resetPingTimeout();

                // Handle ping from server - respond with pong
                if (msg.type === 'ping') {
                    this.ws.send(JSON.stringify({ type: 'pong' }));
                    console.log('[WS] Ping received, sent pong');
                    return;
                }

                // Handle other messages
                this.handleMessage(msg);
            } catch (error) {
                console.error('[WS] Failed to parse message:', error);
            }
        };

        this.ws.onclose = (event) => {
            console.log('[WS] Disconnected', event.code, event.reason);
            this.clearPingTimeout();

            // Dispatch disconnected event
            window.dispatchEvent(new CustomEvent('ws-disconnected'));

            // Reconnect
            this.reconnect();
        };

        this.ws.onerror = (error) => {
            console.error('[WS] Error:', error);
        };
    }

    resetPingTimeout() {
        this.clearPingTimeout();
        this.pingTimeout = setTimeout(() => {
            console.warn('[WS] No ping received within expected interval, connection may be stale');
            this.ws.close();
        }, this.expectedPingInterval);
    }

    clearPingTimeout() {
        if (this.pingTimeout) {
            clearTimeout(this.pingTimeout);
            this.pingTimeout = null;
        }
    }

    reconnect() {
        this.reconnectAttempts++;
        const delay = Math.min(
            this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1),
            this.maxReconnectDelay
        );

        console.log(`[WS] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);

        setTimeout(() => this.connect(), delay);
    }

    handleMessage(msg) {
        console.log('[WS] Message received:', msg.type);

        switch (msg.type) {
            case 'status_update':
                this.handleStatusUpdate(msg.payload);
                break;

            case 'full_refresh':
                console.log('[WS] Full refresh requested');
                location.reload();
                break;

            case 'host_added':
                console.log('[WS] Host added:', msg.payload.host);
                // Trigger a page refresh or dynamic update
                location.reload();
                break;

            case 'host_removed':
                console.log('[WS] Host removed:', msg.payload.host);
                // Remove row from table
                const row = document.querySelector(`tr[data-host="${msg.payload.host}"]`);
                if (row) {
                    row.remove();
                }
                break;

            default:
                console.warn('[WS] Unknown message type:', msg.type);
        }
    }

    handleStatusUpdate(payload) {
        const row = document.querySelector(`tr[data-host="${payload.host}"]`);
        if (!row) {
            console.warn('[WS] No row found for host:', payload.host);
            return;
        }

        // Update status badge
        const statusBadge = row.querySelector('.status-badge');
        if (statusBadge) {
            statusBadge.className = `badge status-badge ${this.getStatusClass(payload.status)}`;
            statusBadge.textContent = payload.status;
        }

        // Update last run time
        const lastRunCell = row.querySelector('.last-run');
        if (lastRunCell) {
            lastRunCell.textContent = payload.last_run;
        }

        // Add flash animation
        row.classList.add('htmx-settling');
        setTimeout(() => row.classList.remove('htmx-settling'), 500);
    }

    getStatusClass(status) {
        switch (status) {
            case 'SSH':
                return 'badge-success';
            case 'TIMEOUT':
                return 'badge-error';
            case 'ACTIVE_REJECT':
                return 'badge-warning';
            case 'PROTOCOL_MISMATCH':
                return 'badge-info';
            default:
                return 'badge-ghost';
        }
    }

    disconnect() {
        if (this.ws) {
            this.ws.close();
        }
        this.clearPingTimeout();
    }
}

// Auto-initialize WebSocket on page load
document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('host-table')) {
        window.wsClient = new WebSocketClient();
        window.wsClient.connect();
    }
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (window.wsClient) {
        window.wsClient.disconnect();
    }
});
