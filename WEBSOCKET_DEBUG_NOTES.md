# WebSocket Debug Session Notes

## Current Status (2026-01-14)

### What Was Done
1. Fixed form submission issues (POST/DELETE for hosts and network ranges)
2. Added WebSocket real-time update functionality
3. Created debug endpoints for testing WebSocket

### WebSocket Implementation Status
- ✅ WebSocket hub is running
- ✅ Server broadcasts status updates when hosts are checked
- ✅ Client-side JavaScript (websocket.js) handles updates
- ✅ HTML templates have correct structure (data-host, status-badge, last-run)
- ⚠️ **NOT TESTED END-TO-END YET**

### Debug Endpoints Created
```bash
# Check WebSocket client connections
curl -s -H "X-API-Key: test124" "http://localhost:8080/debug/websocket-status" | jq .

# Trigger test WebSocket broadcast (adds test host and broadcasts update)
curl -s -X POST -H "X-API-Key: test124" "http://localhost:8080/debug/test-websocket" | jq .
```

### How to Test WebSocket (Next Session)

1. **Start server:**
   ```bash
   cd webserver && ./ssh-monitor
   ```

2. **Check WebSocket status (should show 0 clients):**
   ```bash
   curl -s -H "X-API-Key: test124" "http://localhost:8080/debug/websocket-status" | jq .
   ```

3. **Open browser to:** `http://localhost:8080/`

4. **Check status again (should show 1 client):**
   ```bash
   curl -s -H "X-API-Key: test124" "http://localhost:8080/debug/websocket-status" | jq .
   ```

5. **Trigger test broadcast while browser is open:**
   ```bash
   curl -s -X POST -H "X-API-Key: test124" "http://localhost:8080/debug/test-websocket" | jq .
   ```

6. **Expected behavior:**
   - New test host appears in browser table automatically (no refresh needed)
   - Status badge updates from "TIMEOUT" to current status
   - Last run timestamp updates in real-time
   - Flash animation shows when update happens

### Files Modified

**Core WebSocket files:**
- `webserver/websocket.go` - Hub, Client, broadcast logic
- `webserver/server.go` - Added debug endpoints, WebSocket handler
- `webserver/config.go` - Added WebSocket config fields
- `webserver/monitor.go` - Calls hub.BroadcastHostUpdate() after checks

**Frontend files:**
- `webserver/static/js/websocket.js` - WebSocket client with auto-reconnect
- `webserver/templates/` - HTML templates with htmx + WebSocket support
- `webserver/templates.go` - Embedded template manager

**Config changes:**
- `webserver/config.json` - Added debug and websocket to log_components

### Known Issues
- WebSocket only works when browser tab is open (by design)
- No visual indicator in UI when WebSocket is disconnected
- Browser console needs to be checked for WebSocket connection status

### API Key
- Master key: `test124` (from config.json)

### Next Steps for Debugging
1. Verify WebSocket connects when browser opens page
2. Verify real-time updates work when hosts are checked
3. Test with multiple browser tabs
4. Add visual WebSocket connection indicator to UI
5. Clean up debug endpoints or protect them better

### Notes
- The test script `test_websocket.sh` was created but had issues with API endpoint
- Server must be restarted after config.json changes
- WebSocket errors show as 400 Bad Request when tested with curl (expected - curl can't do WebSocket upgrade)
