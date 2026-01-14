package main

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WSMessage represents a WebSocket message
type WSMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

// Hub manages WebSocket client connections and message broadcasting
type Hub struct {
	clients    map[*Client]bool
	broadcast  chan WSMessage
	register   chan *Client
	unregister chan *Client
	monitor    *Monitor
	logger     *Logger
	config     *Config
	mu         sync.RWMutex
}

// Client represents a WebSocket client connection
type Client struct {
	hub             *Hub
	conn            *websocket.Conn
	send            chan []byte
	isAuthenticated bool
	failedPings     int
	lastPong        time.Time
	mu              sync.Mutex
}

// NewHub creates a new WebSocket hub
func NewHub(monitor *Monitor, logger *Logger, config *Config) *Hub {
	hub := &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan WSMessage, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		monitor:    monitor,
		logger:     logger,
		config:     config,
	}

	// Start the hub
	go hub.run()

	return hub
}

// run manages client registration, unregistration, and broadcasting
func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			h.logger.Info("websocket", "Client connected (total: %d)", len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
				h.logger.Info("websocket", "Client disconnected (total: %d)", len(h.clients))
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				// Filter messages based on authentication
				if h.shouldSendToClient(client, message) {
					select {
					case client.send <- h.encodeMessage(message):
					default:
						// Client's send buffer is full, disconnect
						close(client.send)
						delete(h.clients, client)
					}
				}
			}
			h.mu.RUnlock()
		}
	}
}

// shouldSendToClient determines if a message should be sent to a specific client
func (h *Hub) shouldSendToClient(client *Client, message WSMessage) bool {
	// Always send ping, pong, and full_refresh messages
	if message.Type == "ping" || message.Type == "pong" || message.Type == "full_refresh" {
		return true
	}

	// If client is authenticated, send all messages
	if client.isAuthenticated {
		return true
	}

	// For unauthenticated clients, only send updates for public hosts
	if message.Type == "status_update" {
		if payload, ok := message.Payload.(map[string]interface{}); ok {
			if host, ok := payload["host"].(string); ok {
				h.monitor.mu.RLock()
				defer h.monitor.mu.RUnlock()
				if hostStatus, exists := h.monitor.Hosts[host]; exists {
					return hostStatus.Public
				}
			}
		}
	}

	return false
}

// encodeMessage encodes a WSMessage to JSON bytes
func (h *Hub) encodeMessage(message WSMessage) []byte {
	data, err := json.Marshal(message)
	if err != nil {
		h.logger.Error("websocket", "Failed to encode message: %v", err)
		return []byte("{}")
	}
	return data
}

// BroadcastHostUpdate broadcasts a host status update to all clients
func (h *Hub) BroadcastHostUpdate(result CheckResult) {
	message := WSMessage{
		Type: "status_update",
		Payload: map[string]interface{}{
			"host":     result.Host,
			"status":   result.Status,
			"time":     result.Time.Format(time.RFC3339),
			"last_run": result.Time.Format("15:04:05"),
		},
	}

	select {
	case h.broadcast <- message:
	default:
		h.logger.Warning("websocket", "Broadcast channel full, dropping message")
	}
}

// BroadcastHostAdded broadcasts when a new host is added
func (h *Hub) BroadcastHostAdded(host string) {
	message := WSMessage{
		Type: "host_added",
		Payload: map[string]interface{}{
			"host": host,
		},
	}

	select {
	case h.broadcast <- message:
	default:
	}
}

// BroadcastHostRemoved broadcasts when a host is removed
func (h *Hub) BroadcastHostRemoved(host string) {
	message := WSMessage{
		Type: "host_removed",
		Payload: map[string]interface{}{
			"host": host,
		},
	}

	select {
	case h.broadcast <- message:
	default:
	}
}

// readPump reads messages from the WebSocket connection
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	// Parse read timeout from config
	readTimeout, err := time.ParseDuration(c.hub.config.WSReadTimeout)
	if err != nil {
		readTimeout = 60 * time.Second
	}

	c.conn.SetReadDeadline(time.Now().Add(readTimeout))

	// Set pong handler
	c.conn.SetPongHandler(func(string) error {
		c.mu.Lock()
		c.failedPings = 0
		c.lastPong = time.Now()
		c.mu.Unlock()

		// Reset read deadline
		c.conn.SetReadDeadline(time.Now().Add(readTimeout))
		c.hub.logger.Debug("websocket", "Received pong from client")
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.hub.logger.Warning("websocket", "Unexpected close: %v", err)
			}
			break
		}

		// Reset read deadline on any message
		c.conn.SetReadDeadline(time.Now().Add(readTimeout))

		// Parse incoming message (could be pong response from client)
		var msg WSMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			c.hub.logger.Warning("websocket", "Failed to parse message: %v", err)
			continue
		}

		// Handle pong message type (JSON-based pong, in addition to WebSocket pong frame)
		if msg.Type == "pong" {
			c.mu.Lock()
			c.failedPings = 0
			c.lastPong = time.Now()
			c.mu.Unlock()
			c.hub.logger.Debug("websocket", "Received JSON pong from client")
		}
	}
}

// writePump writes messages to the WebSocket connection
func (c *Client) writePump() {
	// Parse ping interval from config
	pingInterval, err := time.ParseDuration(c.hub.config.WSPingInterval)
	if err != nil {
		pingInterval = 30 * time.Second
	}

	// Parse write timeout from config
	writeTimeout, err := time.ParseDuration(c.hub.config.WSWriteTimeout)
	if err != nil {
		writeTimeout = 10 * time.Second
	}

	ticker := time.NewTicker(pingInterval)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if !ok {
				// Hub closed the channel
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			// Write the message
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				c.hub.logger.Warning("websocket", "Write error: %v", err)
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))

			// Send WebSocket ping frame
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				c.mu.Lock()
				c.failedPings++
				failedCount := c.failedPings
				c.mu.Unlock()

				c.hub.logger.Warning("websocket", "Ping failed (%d/%d)", failedCount, c.hub.config.WSMaxFailures)

				if failedCount >= c.hub.config.WSMaxFailures {
					c.hub.logger.Warning("websocket", "Client exceeded max ping failures, disconnecting")
					return
				}
			} else {
				c.hub.logger.Debug("websocket", "Sent ping to client")
			}

			// Also send JSON ping message for client-side handling
			pingMsg := WSMessage{Type: "ping"}
			pingData, _ := json.Marshal(pingMsg)
			c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := c.conn.WriteMessage(websocket.TextMessage, pingData); err != nil {
				c.hub.logger.Warning("websocket", "Failed to send JSON ping: %v", err)
			}
		}
	}
}

// ServeWS handles WebSocket upgrade requests
func (c *Client) ServeWS() {
	go c.writePump()
	go c.readPump()
}
