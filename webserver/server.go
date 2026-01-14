package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	Version     = "0.1.0"
	Author      = "Sadeq <code@sadeq.uk>"
	Description = "A web server and API for monitoring SSH availability across multiple hosts."
)

var (
	sshPattern = regexp.MustCompile(`^SSH-[0-9.]+-[a-zA-Z0-9 .-]+`)
)

type Server struct {
	config      *Config
	logger      *Logger
	auth        *AuthManager
	monitor     *Monitor
	hub         *Hub
	templates   *TemplateManager
	currentHash string
}

func main() {
	cfg := GetConfig()

	logger := &Logger{
		Level:      parseLogLevel(cfg.LogLevel),
		Components: make(map[string]bool),
		UseColor:   cfg.LogFormat == "color",
		UseJSON:    cfg.LogFormat == "json",
	}
	for _, c := range cfg.LogComponents {
		logger.Components[c] = true
	}

	auth := NewAuthManager(cfg)
	monitor := NewMonitor(logger, cfg.CheckPoolSize, cfg.MaxSubnetConcurrency, cfg.HistoryLimit)

	// Initialize template manager
	templateMgr := NewTemplateManager()

	// Initialize WebSocket hub
	hub := NewHub(monitor, logger, cfg)

	// Set hub on monitor for broadcasting
	monitor.SetHub(hub)

	// Add predefined hosts from simple list
	defaultInterval, _ := time.ParseDuration(cfg.DefaultInterval)
	defaultTimeout, _ := time.ParseDuration(cfg.DefaultTimeout)
	for _, h := range cfg.PredefinedHosts {
		monitor.AddHost(normalizeTarget(h), defaultInterval, defaultTimeout, true)
	}

	// Add detailed hosts from structured list
	for _, hc := range cfg.Hosts {
		interval := defaultInterval
		if hc.Interval != "" {
			if d, err := time.ParseDuration(hc.Interval); err == nil {
				interval = d
			}
		}
		timeout := defaultTimeout
		if hc.Timeout != "" {
			if d, err := time.ParseDuration(hc.Timeout); err == nil {
				timeout = d
			}
		}
		monitor.AddHost(normalizeTarget(hc.Host), interval, timeout, hc.Public)
	}

	// Add hosts from configured network ranges
	for _, nr := range cfg.NetworkRanges {
		interval := defaultInterval
		if nr.Interval != "" {
			if d, err := time.ParseDuration(nr.Interval); err == nil {
				interval = d
			}
		}
		timeout := defaultTimeout
		if nr.Timeout != "" {
			if d, err := time.ParseDuration(nr.Timeout); err == nil {
				timeout = d
			}
		}

		ips, err := expandCIDR(nr.CIDR)
		if err == nil {
			for _, ip := range ips {
				monitor.AddHost(normalizeTarget(ip), interval, timeout, nr.Public)
			}
		} else {
			logger.Error("config", "Failed to expand network range %s: %v", nr.CIDR, err)
		}
	}

	monitor.Start()

	initialHash, _ := getFilesHash([]string{"config.json", "config-override.json"})

	s := &Server{
		config:      cfg,
		logger:      logger,
		auth:        auth,
		monitor:     monitor,
		hub:         hub,
		templates:   templateMgr,
		currentHash: initialHash,
	}

	go s.watchConfig()

	// ACME Manager
	acmeMgr := NewACMEManager(cfg, logger)
	if cfg.ACMEEnabled {
		acmeMgr.StartRenewalLoop()
	}

	mux := http.NewServeMux()

	// ACME HTTP Challenge Handler
	if cfg.ACMEEnabled && cfg.ACMEChallenge == "http" {
		mux.HandleFunc("/.well-known/acme-challenge/", acmeMgr.HTTPHandler)
	}

	// API Keys Management (Master only)
	mux.HandleFunc("/api/keys", s.auth.AuthMiddleware(s.handleKeys, KeyMaster))

	// Hosts Management (Master can do everything, Normal can add/remove/change)
	mux.HandleFunc("/api/hosts", s.auth.AuthMiddleware(s.handleHosts, KeyNormal))
	mux.HandleFunc("/api/ranges", s.auth.AuthMiddleware(s.handleRanges, KeyNormal))

	// Results (Normal and Master)
	mux.HandleFunc("/api/results", s.handleResults)

	// Debug endpoints (no auth required for diagnostics)
	mux.HandleFunc("/api/debug/hosts", s.handleDebugHosts)
	mux.HandleFunc("/api/debug/ranges", s.handleDebugRanges)
	mux.HandleFunc("/api/debug/config", s.handleDebugConfig)

	// Index page
	mux.HandleFunc("/", s.handleIndex)

	// Form interface
	mux.HandleFunc("/form/", s.auth.AuthMiddleware(s.handleForm, KeyNormal))
	mux.HandleFunc("/logout", s.handleLogout)

	// WebSocket endpoint
	mux.HandleFunc("/ws", s.handleWebSocket)

	// Debug endpoints
	mux.HandleFunc("/debug/test-websocket", s.auth.AuthMiddleware(s.handleDebugTestWebSocket, KeyMaster))
	mux.HandleFunc("/debug/websocket-status", s.auth.AuthMiddleware(s.handleDebugWebSocketStatus, KeyMaster))

	// Static file serving from embedded FS
	staticFS := http.FileServer(http.FS(GetEmbeddedFS()))
	mux.Handle("/static/", http.StripPrefix("/static/", staticFS))

	port := flag.String("port", cfg.Port, "Port to listen on")
	sslEnabled := flag.Bool("ssl-enabled", cfg.SSLEnabled, "Enable SSL/TLS")
	certPath := flag.String("cert-path", cfg.CertPath, "Path to SSL certificate")
	keyPath := flag.String("key-path", cfg.KeyPath, "Path to SSL private key")
	sslDomains := flag.String("ssl-cert-domains", "", "Comma-separated list of domains for self-signed cert")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "SSH Alive Monitor %s\n", Version)
		fmt.Fprintf(os.Stderr, "Author: %s\n", Author)
		fmt.Fprintf(os.Stderr, "%s\n\n", Description)
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "This project is licensed under the MIT License without any liability and/or obligation.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *port != "" {
		cfg.Port = *port
	}
	cfg.SSLEnabled = *sslEnabled
	if *certPath != "" {
		cfg.CertPath = *certPath
	}
	if *keyPath != "" {
		cfg.KeyPath = *keyPath
	}
	if *sslDomains != "" {
		cfg.SSLCertDomains = strings.Split(*sslDomains, ",")
		for i := range cfg.SSLCertDomains {
			cfg.SSLCertDomains[i] = strings.TrimSpace(cfg.SSLCertDomains[i])
		}
	}

	serverAddr := ":" + cfg.Port
	srv := &http.Server{
		Addr:    serverAddr,
		Handler: s.loggingMiddleware(mux),
	}

	if cfg.SSLEnabled {
		logger.Info("requests", "SSL Enabled. Checking certificates...")

		// Check ACME
		if cfg.ACMEEnabled {
			// If certs don't exist, try to obtain them
			_, certErr := os.Stat(cfg.CertPath)
			_, keyErr := os.Stat(cfg.KeyPath)
			if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
				// We need to serve HTTP for challenge if using HTTP-01
				// But we are blocking here.
				// For HTTP-01, we need to start the server in background if it's the same port/server.
				// However, ListenAndServeTLS blocks.
				// If we use HTTP-01, we must handle the challenge.
				// If we are sharing the port, we can't easily start just for challenge unless we start HTTP first?
				// Typically ACME HTTP-01 requires port 80. If our port is 8080 (forwarded), we can serve.
				// We'll start a goroutine for the server IF we need to answer challenges while obtaining?
				// No, obtaining blocks.
				// If we use the `http01.NewProviderServer` from lego, it binds a port.
				// But we are using `MyHTTPProvider` which just hooks into `acmeMgr.HTTPHandler`.
				// This implies the server MUST be running.
				// BUT we haven't started `srv.ListenAndServeTLS` yet.
				// CHICKEN AND EGG PROBLEM for HTTP-01 on the same port if we want to upgrade to TLS later.
				// Solution: Start a temporary HTTP server or start the main server in a goroutine?
				// But main server wants TLS.
				// If we are missing certs, we CANNOT start TLS.
				// So we must start as HTTP first?
				// But users expect TLS.
				// ACME HTTP-01 strictly requires answering on HTTP (plain).
				// So if we are enabled, we should probably start HTTP server first, obtain cert, then switch?
				// Or simple: Start HTTP server logic just for the challenge duration if using `MyHTTPProvider`?
				// But `srv` is configured for the app.
				// Let's assume for HTTP-01, the user has a separate setup or we temporarily listen on HTTP.

				if cfg.ACMEChallenge == "http" {
					logger.Info("requests", "Starting temporary HTTP server for ACME challenge...")
					tempSrv := &http.Server{Addr: serverAddr, Handler: mux}
					go tempSrv.ListenAndServe()
					defer tempSrv.Close() // Close after obtaining?
					// Wait a bit for server to be up
					time.Sleep(1 * time.Second)
				}

				if err := acmeMgr.ObtainCert(); err != nil {
					logger.Error("requests", "Failed to obtain ACME certificate: %v", err)
					// Fallback to self-signed?
					logger.Info("requests", "Falling back to self-signed certificate generation...")
				}
			}
		}

		// Self-signed fallback check
		_, certErr := os.Stat(cfg.CertPath)
		_, keyErr := os.Stat(cfg.KeyPath)

		if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
			logger.Info("requests", "Certificate or key not found. Generating self-signed certificate for domains: %v", cfg.SSLCertDomains)
			if err := generateSelfSignedCert(cfg.CertPath, cfg.KeyPath, cfg.SSLCertDomains); err != nil {
				logger.Error("requests", "Failed to generate self-signed certificate: %v", err)
				os.Exit(1)
			}
			logger.Info("requests", "Self-signed certificate generated at %s and %s", cfg.CertPath, cfg.KeyPath)
		}

		// Initialize CertManager for hot reloading
		certMgr := NewCertManager(cfg.CertPath, cfg.KeyPath, logger)
		certMgr.StartWatcher()

		srv.TLSConfig = &tls.Config{
			GetCertificate: certMgr.GetCertificate,
		}

		logger.Info("requests", "Server starting on %s (HTTPS)", serverAddr)
		// We use ListenAndServeTLS with empty strings because GetCertificate provides the certs
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			logger.Error("requests", "Server failed: %v", err)
		}
	} else {
		logger.Info("requests", "Server starting on %s (HTTP)", serverAddr)
		if err := srv.ListenAndServe(); err != nil {
			logger.Error("requests", "Server failed: %v", err)
		}
	}
}

func (s *Server) watchConfig() {
	configFiles := []string{"config.json", "config-override.json"}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		newHash, err := getFilesHash(configFiles)
		if err != nil {
			continue
		}

		if newHash != s.currentHash {
			s.logger.Info("requests", "Config change detected, waiting 5 seconds for stability...")
			time.Sleep(5 * time.Second)

			stableHash, err := getFilesHash(configFiles)
			if err != nil {
				continue
			}

			if stableHash == newHash {
				s.logger.Info("requests", "Config stable, reloading...")
				s.reloadConfig()
			} else {
				s.logger.Info("requests", "Config still changing, will check again...")
			}
		}
	}
}

func (s *Server) reloadConfig() {
	cfg := GetConfig()
	s.applyConfig(cfg)

	newHash, _ := getFilesHash([]string{"config.json", "config-override.json"})
	s.currentHash = newHash
}

func (s *Server) applyConfig(cfg *Config) {
	s.config = cfg

	// Update Logger
	s.logger.Level = parseLogLevel(cfg.LogLevel)
	s.logger.UseColor = cfg.LogFormat == "color"
	s.logger.UseJSON = cfg.LogFormat == "json"
	s.logger.Components = make(map[string]bool)
	for _, c := range cfg.LogComponents {
		s.logger.Components[c] = true
	}

	// Update AuthManager
	s.auth.mu.Lock()
	s.auth.Keys = make(map[string]APIKey)
	for _, k := range cfg.MasterKeys {
		s.auth.Keys[k] = APIKey{Key: k, Type: KeyMaster, Enabled: true}
	}
	for _, k := range cfg.NormalKeys {
		s.auth.Keys[k] = APIKey{Key: k, Type: KeyNormal, Enabled: true}
	}
	s.auth.mu.Unlock()

	// Update Monitor
	s.monitor.mu.Lock()
	// Clear existing hosts
	s.monitor.Hosts = make(map[string]*HostStatus)
	s.monitor.mu.Unlock()

	defaultInterval, _ := time.ParseDuration(cfg.DefaultInterval)
	defaultTimeout, _ := time.ParseDuration(cfg.DefaultTimeout)

	// Add predefined hosts
	for _, h := range cfg.PredefinedHosts {
		s.monitor.AddHost(normalizeTarget(h), defaultInterval, defaultTimeout, true)
	}

	// Add detailed hosts
	for _, hc := range cfg.Hosts {
		interval := defaultInterval
		if hc.Interval != "" {
			if d, err := time.ParseDuration(hc.Interval); err == nil {
				interval = d
			}
		}
		timeout := defaultTimeout
		if hc.Timeout != "" {
			if d, err := time.ParseDuration(hc.Timeout); err == nil {
				timeout = d
			}
		}
		s.monitor.AddHost(normalizeTarget(hc.Host), interval, timeout, hc.Public)
	}

	// Add hosts from configured network ranges
	for _, nr := range cfg.NetworkRanges {
		interval := defaultInterval
		if nr.Interval != "" {
			if d, err := time.ParseDuration(nr.Interval); err == nil {
				interval = d
			}
		}
		timeout := defaultTimeout
		if nr.Timeout != "" {
			if d, err := time.ParseDuration(nr.Timeout); err == nil {
				timeout = d
			}
		}

		ips, err := expandCIDR(nr.CIDR)
		if err == nil {
			for _, ip := range ips {
				s.monitor.AddHost(normalizeTarget(ip), interval, timeout, nr.Public)
			}
		} else {
			s.logger.Error("config", "Failed to expand network range %s: %v", nr.CIDR, err)
		}
	}

	s.logger.Info("requests", "Configuration reloaded successfully")
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Capture response status code
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		s.logger.Info("requests", "%s %s %s %d %v", r.RemoteAddr, r.Method, r.URL.Path, rw.status, duration)
		s.logger.Debug("response", "Response sent: %d", rw.status)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// --- Handlers ---

func (s *Server) saveConfig() error {
	err := s.config.Save("config.json")
	if err == nil {
		newHash, _ := getFilesHash([]string{"config.json", "config-override.json"})
		s.currentHash = newHash
	}
	return err
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.auth.ClearAuthCookie(w)
	// Force browser to clear Basic Auth credentials by sending 401 with a different realm?
	// Or just same realm but 401.
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
	http.Error(w, "Logged out", http.StatusUnauthorized)
}

func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request) {
	s.logger.Info("requests", "Admin task: %s %s", r.Method, r.URL.Path)
	switch r.Method {
	case http.MethodGet:
		s.auth.mu.RLock()
		keys := make([]APIKey, 0, len(s.auth.Keys))
		for _, k := range s.auth.Keys {
			keys = append(keys, k)
		}
		s.auth.mu.RUnlock()
		s.respond(w, r, keys)

	case http.MethodPost:
		var req struct {
			Key         string     `json:"key"`
			Type        APIKeyType `json:"type"`
			Generate    bool       `json:"generate"`
			Description string     `json:"description"`
		}

		// Handle form data from htmx
		contentType := r.Header.Get("Content-Type")
		if strings.Contains(contentType, "application/x-www-form-urlencoded") {
			r.ParseForm()
			req.Type = APIKeyType(r.FormValue("type"))
			req.Description = r.FormValue("description")
			req.Generate = true
		} else {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		if req.Generate {
			req.Key = generateRandomKey(32)
		}

		if req.Key == "" {
			http.Error(w, "Key is required", http.StatusBadRequest)
			return
		}
		if req.Type == "" {
			req.Type = KeyNormal
		}
		s.auth.AddKey(req.Key, req.Type)

		// Sync to config
		s.config.MasterKeys = s.auth.GetKeysByType(KeyMaster)
		s.config.NormalKeys = s.auth.GetKeysByType(KeyNormal)
		s.saveConfig()

		// For htmx, return HTML to display the new key
		if s.isHtmxRequest(r) {
			w.Header().Set("Content-Type", "text/html")
			keyTypeDisplay := "Normal"
			keyTypeBadge := "badge-info"
			if req.Type == KeyMaster {
				keyTypeDisplay = "Master"
				keyTypeBadge = "badge-error"
			}

			fmt.Fprintf(w, `<div class="alert alert-success">
				<svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
				</svg>
				<div>
					<h3 class="font-bold">Key Generated Successfully</h3>
					<div class="text-sm space-y-2">
						<p>Save this key - it won't be shown again!</p>
						<div class="flex items-center gap-2 mt-2">
							<code class="badge badge-lg font-mono">%s</code>
							<button class="btn btn-ghost btn-xs"
								onclick="navigator.clipboard.writeText('%s'); showToast('Copied to clipboard', 'success')">
								<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
									<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
								</svg>
								Copy
							</button>
						</div>
					</div>
				</div>
			</div>
			<tr data-key="%s" hx-swap-oob="beforeend:#api-keys-list">
				<td><code class="badge badge-lg font-mono">%s</code></td>
				<td><div class="badge %s">%s</div></td>
				<td><div class="badge badge-success">Active</div></td>
				<td><span class="text-sm text-base-content/70">%s</span></td>
				<td class="text-right">
					<button class="btn btn-ghost btn-xs"
						onclick="navigator.clipboard.writeText('%s'); showToast('Copied to clipboard', 'success')">
						<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
						</svg>
						Copy
					</button>
					<button class="btn btn-ghost btn-xs text-error"
						hx-delete="/api/keys"
						hx-vals='{"key": "%s"}'
						hx-confirm="Are you sure you want to revoke this key?"
						hx-target="closest tr"
						hx-swap="outerHTML swap:500ms">
						<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
						</svg>
						Revoke
					</button>
				</td>
			</tr>`, req.Key, req.Key, req.Key, req.Key, keyTypeBadge, keyTypeDisplay, req.Description, req.Key, req.Key)
		} else {
			s.respond(w, r, map[string]string{"message": "Key added", "key": req.Key})
		}

	case http.MethodDelete:
		var key string

		// Handle both query params and JSON body
		if r.URL.Query().Get("key") != "" {
			key = r.URL.Query().Get("key")
		} else {
			var req struct {
				Key string `json:"key"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
				key = req.Key
			}
		}

		if key == "" {
			http.Error(w, "Key is required", http.StatusBadRequest)
			return
		}
		s.auth.DeleteKey(key)

		// Sync to config
		s.config.MasterKeys = s.auth.GetKeysByType(KeyMaster)
		s.config.NormalKeys = s.auth.GetKeysByType(KeyNormal)
		s.saveConfig()

		// For htmx, return empty response (row will be swapped out)
		if s.isHtmxRequest(r) {
			w.WriteHeader(http.StatusOK)
		} else {
			s.respond(w, r, map[string]string{"message": "Key deleted"})
		}

	case http.MethodPatch:
		var req struct {
			Key     string `json:"key"`
			Enabled bool   `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.auth.SetEnabled(req.Key, req.Enabled)
		s.respond(w, r, map[string]string{"message": "Key status updated"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRanges(w http.ResponseWriter, r *http.Request) {
	s.logger.Info("requests", "Range management: %s %s", r.Method, r.URL.Path)
	switch r.Method {
	case http.MethodGet:
		s.respond(w, r, s.config.NetworkRanges)

	case http.MethodPost:
		s.logger.Info("requests", "=== POST /api/ranges called ===")
		s.logger.Info("requests", "POST ranges Content-Type: %s", r.Header.Get("Content-Type"))

		var req struct {
			CIDR     string `json:"cidr"`
			Interval string `json:"interval"`
			Timeout  string `json:"timeout"`
			Public   bool   `json:"public"`
		}

		// Read body for logging
		body, _ := io.ReadAll(r.Body)
		s.logger.Info("requests", "POST ranges body: %q", string(body))

		// Handle both form data and JSON
		contentType := r.Header.Get("Content-Type")
		if strings.Contains(contentType, "application/x-www-form-urlencoded") {
			values, err := url.ParseQuery(string(body))
			if err == nil {
				req.CIDR = values.Get("cidr")
				req.Interval = values.Get("interval")
				req.Timeout = values.Get("timeout")
				req.Public = values.Get("public") == "on"
				s.logger.Info("requests", "POST ranges from form: cidr=%q interval=%q timeout=%q public=%v", req.CIDR, req.Interval, req.Timeout, req.Public)
			} else {
				s.logger.Warning("requests", "POST ranges form parse error: %v", err)
				http.Error(w, "Invalid form data: "+err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			// Parse JSON
			if err := json.Unmarshal(body, &req); err != nil {
				s.logger.Warning("requests", "POST ranges JSON decode error: %v", err)
				http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
				return
			}
			s.logger.Info("requests", "POST ranges from JSON: cidr=%q interval=%q timeout=%q public=%v", req.CIDR, req.Interval, req.Timeout, req.Public)
		}

		if req.CIDR == "" {
			s.logger.Warning("requests", "POST ranges: CIDR is empty")
			http.Error(w, "CIDR is required", http.StatusBadRequest)
			return
		}

		// Validate CIDR
		_, ipNet, err := net.ParseCIDR(req.CIDR)
		if err != nil {
			s.logger.Warning("requests", "POST ranges: Invalid CIDR %q: %v", req.CIDR, err)
			http.Error(w, "Invalid CIDR format: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Check size limits
		ones, bits := ipNet.Mask.Size()
		if bits-ones > 16 {
			http.Error(w, "CIDR range is too large. Maximum allowed range size is /16.", http.StatusBadRequest)
			return
		}

		interval, _ := time.ParseDuration(req.Interval)
		if interval == 0 {
			interval, _ = time.ParseDuration(s.config.DefaultInterval)
		}
		timeout, _ := time.ParseDuration(req.Timeout)
		if timeout == 0 {
			timeout, _ = time.ParseDuration(s.config.DefaultTimeout)
		}

		// Expand CIDR and add hosts
		ips, err := expandCIDR(req.CIDR)
		if err != nil {
			http.Error(w, "Failed to expand CIDR: "+err.Error(), http.StatusInternalServerError)
			return
		}

		count := 0
		for _, ip := range ips {
			host := normalizeTarget(ip)
			s.monitor.AddHost(host, interval, timeout, req.Public)
			count++
		}

		// Add to config
		s.config.NetworkRanges = append(s.config.NetworkRanges, NetworkRangeConfig{
			CIDR:     req.CIDR,
			Interval: req.Interval,
			Timeout:  req.Timeout,
			Public:   req.Public,
		})
		s.saveConfig()

		// For htmx, return the range card HTML
		if s.isHtmxRequest(r) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<div class="card bg-base-200" data-cidr="%s">
				<div class="card-body">
					<div class="flex justify-between items-start">
						<div class="flex-1">
							<h3 class="font-bold text-lg">%s</h3>
							<div class="flex gap-2 mt-2 flex-wrap">
								<div class="badge badge-outline">Interval: %s</div>
								<div class="badge badge-outline">Timeout: %s</div>
								%s
							</div>
						</div>
						<button class="btn btn-ghost btn-sm text-error"
							hx-delete="/api/ranges"
							hx-vals='{"cidr": "%s"}'
							hx-confirm="Are you sure you want to remove %s?"
							hx-target="closest div[data-cidr]"
							hx-swap="outerHTML swap:500ms">Delete</button>
					</div>
				</div>
			</div>`, req.CIDR, req.CIDR, req.Interval, req.Timeout,
				func() string {
					if req.Public {
						return `<div class="badge badge-success badge-sm">Public</div>`
					}
					return `<div class="badge badge-ghost badge-sm">Private</div>`
				}(), req.CIDR, req.CIDR)
		} else {
			s.respond(w, r, map[string]interface{}{"message": fmt.Sprintf("Added %d hosts from CIDR", count), "cidr": req.CIDR, "count": count})
		}

	case http.MethodDelete:
		// Delete a range
		s.logger.Info("requests", "=== DELETE /api/ranges called ===")
		s.logger.Info("requests", "DELETE ranges Content-Type: %s", r.Header.Get("Content-Type"))
		s.logger.Info("requests", "DELETE ranges Content-Length: %d", r.ContentLength)

		var cidr string
		if r.Body != nil && r.ContentLength > 0 {
			body, _ := io.ReadAll(r.Body)
			s.logger.Info("requests", "DELETE ranges body: %q", string(body))

			// Try to parse as form data first (htmx sends this)
			if strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
				values, err := url.ParseQuery(string(body))
				if err == nil {
					cidr = values.Get("cidr")
					s.logger.Info("requests", "DELETE ranges from form data: %q", cidr)
				}
			} else if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
				// Try JSON parsing
				var req struct {
					CIDR string `json:"cidr"`
				}
				if json.Unmarshal(body, &req) == nil && req.CIDR != "" {
					cidr = req.CIDR
					s.logger.Info("requests", "DELETE ranges from JSON: %q", cidr)
				}
			}

			// Fallback to plain text
			if cidr == "" {
				cidr = strings.TrimSpace(string(body))
				if cidr != "" {
					s.logger.Info("requests", "DELETE ranges from plain body: %q", cidr)
				}
			}
		}
		if cidr == "" {
			cidr = r.URL.Query().Get("cidr")
			s.logger.Info("requests", "DELETE ranges from query param: %q", cidr)
		}

		if cidr == "" {
			s.logger.Warning("requests", "Delete range: CIDR parameter is missing or empty")
			http.Error(w, "CIDR is required", http.StatusBadRequest)
			return
		}

		s.logger.Info("requests", "Deleting network range: %s", cidr)

		// Log current config state
		s.logger.Info("requests", "Current config has %d ranges:", len(s.config.NetworkRanges))
		for i, nr := range s.config.NetworkRanges {
			s.logger.Info("requests", "  Range[%d]: %q", i, nr.CIDR)
		}

		// Find and remove from config
		found := false
		var newRanges []NetworkRangeConfig
		for _, nr := range s.config.NetworkRanges {
			s.logger.Info("requests", "Comparing config CIDR %q with target %q: match=%v", nr.CIDR, cidr, nr.CIDR == cidr)
			if nr.CIDR == cidr {
				found = true
				s.logger.Info("requests", "Found matching range, skipping it")
				continue
			}
			newRanges = append(newRanges, nr)
		}

		s.logger.Info("requests", "After search: found=%v, remaining ranges=%d", found, len(newRanges))

		if !found {
			s.logger.Warning("requests", "Range %q not found in config", cidr)
			http.Error(w, "Range not found", http.StatusNotFound)
			return
		}

		s.config.NetworkRanges = newRanges
		s.saveConfig()

		// Remove IPs from monitor
		ips, err := expandCIDR(cidr)
		removedCount := 0
		if err == nil {
			for _, ip := range ips {
				host := normalizeTarget(ip)
				s.monitor.RemoveHost(host)
				removedCount++
			}
		}

		// For htmx, return empty response
		if s.isHtmxRequest(r) {
			w.WriteHeader(http.StatusOK)
		} else {
			s.respond(w, r, map[string]interface{}{"message": "Range removed", "cidr": cidr, "hosts_removed": removedCount})
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	// For GET /api/hosts, we only show all hosts if authenticated.
	// However, AuthMiddleware is already applied to /api/hosts for KeyNormal.
	// So we don't need extra check here unless we want it to be public too.
	// The requirement says: "these host heck status should be visible without need a key"
	// "make sure the index page shows the status of all monitorin hosts based on user access (with API Key, show all of them, without API key, show only predefined ones)"
	// This implies /api/results and / are what need conditional visibility.

	switch r.Method {
	case http.MethodGet:
		s.monitor.mu.RLock()
		hosts := make([]*HostStatus, 0, len(s.monitor.Hosts))
		for _, h := range s.monitor.Hosts {
			hosts = append(hosts, h)
		}
		s.monitor.mu.RUnlock()
		s.respond(w, r, hosts)

	case http.MethodPost:
		var req struct {
			Host     string `json:"host"`
			Port     string `json:"port"`
			Interval string `json:"interval"`
			Timeout  string `json:"timeout"`
		}

		// Handle both JSON and form data
		contentType := r.Header.Get("Content-Type")
		if strings.Contains(contentType, "application/json") {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
			r.ParseForm()
			req.Host = r.FormValue("host")
			req.Port = r.FormValue("port")
			req.Interval = r.FormValue("interval")
			req.Timeout = r.FormValue("timeout")
		} else {
			// Plain text body for backward compatibility
			body, _ := io.ReadAll(r.Body)
			req.Host = strings.TrimSpace(string(body))
		}

		if req.Host == "" {
			http.Error(w, "Host is required", http.StatusBadRequest)
			return
		}

		// Combine host and port if port is provided and host doesn't already have a port
		if req.Port != "" && !strings.Contains(req.Host, ":") {
			req.Host = req.Host + ":" + req.Port
		}

		interval, _ := time.ParseDuration(req.Interval)
		if interval == 0 {
			interval, _ = time.ParseDuration(s.config.DefaultInterval)
		}
		timeout, _ := time.ParseDuration(req.Timeout)
		if timeout == 0 {
			timeout, _ = time.ParseDuration(s.config.DefaultTimeout)
		}

		// Check for CIDR
		if strings.Contains(req.Host, "/") {
			_, ipNet, err := net.ParseCIDR(req.Host)
			if err != nil {
				// Not a valid CIDR, maybe just a host with some slash? (unlikely for hostname)
				// Or invalid format.
				http.Error(w, "Invalid CIDR format: "+err.Error(), http.StatusBadRequest)
				return
			}

			// Check permissions for CIDR size
			ones, bits := ipNet.Mask.Size()

			// Enforce a maximum size for all users to prevent DoS (max /16 or 65536 hosts)
			if bits-ones > 16 {
				http.Error(w, "CIDR range is too large. Maximum allowed range size is /16.", http.StatusBadRequest)
				return
			}

			apiKey, _ := s.auth.GetAuthFromRequest(r)
			if apiKey.Type == KeyNormal {
				// For IPv4, /24 is 24 ones. Limit is range smaller than /24.
				// "smaller than /24" -> means fewer addresses? OR "range smaller than /24" usually means /25, /26...
				// Wait, "limited to range smaller than /24"
				// A /23 is LARGER range (512 IPs). A /25 is SMALLER range (128 IPs).
				// So "range smaller than /24" means prefix >= 24.
				if ones < 24 {
					http.Error(w, "Normal users are limited to CIDR ranges /24 or smaller (e.g., /24, /25)", http.StatusForbidden)
					return
				}
			}

			ips, err := expandCIDR(req.Host)
			if err != nil {
				http.Error(w, "Failed to expand CIDR: "+err.Error(), http.StatusInternalServerError)
				return
			}

			count := 0
			for _, ip := range ips {
				host := normalizeTarget(ip)
				s.monitor.AddHost(host, interval, timeout, false)
				count++
			}

			// Persistence for Network Ranges
			s.config.NetworkRanges = append(s.config.NetworkRanges, NetworkRangeConfig{
				CIDR:     req.Host,
				Interval: req.Interval,
				Timeout:  req.Timeout,
				Public:   false,
			})
			s.saveConfig()

			s.respond(w, r, map[string]interface{}{"message": fmt.Sprintf("Added %d hosts from CIDR", count), "cidr": req.Host, "count": count})

		} else {
			host := normalizeTarget(req.Host)
			s.monitor.AddHost(host, interval, timeout, false)

			// For htmx, return the new host row HTML
			if s.isHtmxRequest(r) {
				hostData := map[string]interface{}{
					"Host":            host,
					"Status":          "N/A",
					"LastRun":         "00:00:00",
					"Interval":        interval.String(),
					"Timeout":         timeout.String(),
					"Public":          false,
					"IsAuthenticated": true,
				}
				s.renderPartial(w, "host-row", hostData)
			} else {
				s.respond(w, r, map[string]string{"message": "Host added", "host": host})
			}
		}

	case http.MethodPut:
		var req struct {
			Host     string `json:"host"`
			Interval string `json:"interval"`
			Timeout  string `json:"timeout"`
			Public   bool   `json:"public"`
		}

		// Handle both JSON and form data
		contentType := r.Header.Get("Content-Type")
		if strings.Contains(contentType, "application/x-www-form-urlencoded") {
			r.ParseForm()
			req.Host = r.FormValue("host")
			req.Interval = r.FormValue("interval")
			req.Timeout = r.FormValue("timeout")
			req.Public = r.FormValue("public") == "on"
		} else {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		if req.Host == "" {
			http.Error(w, "Host is required", http.StatusBadRequest)
			return
		}

		interval, _ := time.ParseDuration(req.Interval)
		if interval == 0 {
			interval, _ = time.ParseDuration(s.config.DefaultInterval)
		}
		timeout, _ := time.ParseDuration(req.Timeout)
		if timeout == 0 {
			timeout, _ = time.ParseDuration(s.config.DefaultTimeout)
		}

		host := normalizeTarget(req.Host)
		s.monitor.mu.Lock()
		if h, ok := s.monitor.Hosts[host]; ok {
			h.Interval = interval
			h.Timeout = timeout
			h.Public = req.Public
			s.logger.Info("checks", "Updated host: %s (interval: %v, timeout: %v, public: %v)", host, interval, timeout, req.Public)
			s.monitor.mu.Unlock()

			// For htmx, return the updated host row
			if s.isHtmxRequest(r) {
				// Get latest status
				s.monitor.mu.RLock()
				results := make(map[string]CheckResult)
				for i := len(s.monitor.History) - 1; i >= 0; i-- {
					res := s.monitor.History[i]
					if _, ok := results[res.Host]; !ok {
						results[res.Host] = res
					}
				}
				s.monitor.mu.RUnlock()

				status := "N/A"
				lastRun := "00:00:00"
				if h.LastRun.Unix() > 0 {
					lastRun = h.LastRun.Format("15:04:05")
				}
				if res, ok := results[host]; ok {
					status = res.Status
					lastRun = res.Time.Format("15:04:05")
				}

				// Find and return the updated row
				hostData := map[string]interface{}{
					"Host":            host,
					"Status":          status,
					"LastRun":         lastRun,
					"Interval":        interval.String(),
					"Timeout":         timeout.String(),
					"Public":          req.Public,
					"IsAuthenticated": true,
				}
				w.WriteHeader(http.StatusOK)
				s.renderPartial(w, "host-row", hostData)
			} else {
				s.respond(w, r, map[string]string{"message": "Host updated", "host": host})
			}
		} else {
			s.monitor.mu.Unlock()
			http.Error(w, "Host not found", http.StatusNotFound)
		}

	case http.MethodDelete:
		s.logger.Info("requests", "=== DELETE /api/hosts called ===")
		body, _ := io.ReadAll(r.Body)
		s.logger.Info("requests", "DELETE hosts body: %q", string(body))
		s.logger.Info("requests", "DELETE hosts Content-Type: %s", r.Header.Get("Content-Type"))

		var host string

		// Try to parse as form data first (htmx sends this)
		if strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			values, err := url.ParseQuery(string(body))
			if err == nil {
				host = values.Get("host")
				s.logger.Info("requests", "DELETE hosts from form data: %q", host)
			}
		} else if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			// Try JSON parsing
			var req struct {
				Host string `json:"host"`
			}
			if json.Unmarshal(body, &req) == nil && req.Host != "" {
				host = req.Host
				s.logger.Info("requests", "DELETE hosts from JSON: %q", host)
			}
		}

		// Fallback to plain text body or query param
		if host == "" {
			host = strings.TrimSpace(string(body))
			if host != "" {
				s.logger.Info("requests", "DELETE hosts from plain body: %q", host)
			}
		}
		if host == "" {
			host = r.URL.Query().Get("host")
			s.logger.Info("requests", "DELETE hosts from query param: %q", host)
		}

		if host == "" {
			s.logger.Warning("requests", "DELETE hosts: no host provided")
			http.Error(w, "Host is required", http.StatusBadRequest)
			return
		}

		originalHost := host
		host = normalizeTarget(host)
		s.logger.Info("requests", "DELETE hosts: normalized %q to %q", originalHost, host)

		// Check if host exists before removal
		s.monitor.mu.RLock()
		found := false
		for _, h := range s.monitor.Hosts {
			if h.Host == host {
				found = true
				break
			}
		}
		s.monitor.mu.RUnlock()

		s.logger.Info("requests", "DELETE hosts: host %q found=%v", host, found)

		s.monitor.RemoveHost(host)
		s.logger.Info("requests", "DELETE hosts: RemoveHost called for %q", host)

		// For htmx, return empty response (row will be swapped out)
		if s.isHtmxRequest(r) {
			w.WriteHeader(http.StatusOK)
		} else {
			s.respond(w, r, map[string]string{"message": "Host removed", "host": host})
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	_, isAuthenticated := s.auth.GetAuthFromRequest(r)

	if !isAuthenticated {
		isAuthenticated = s.isWhitelisted(r.RemoteAddr)
	}

	query := r.URL.Query()
	sinceStr := query.Get("since")
	limitStr := query.Get("limit")
	hostFilter := query.Get("host")

	s.monitor.mu.RLock()
	results := make([]CheckResult, len(s.monitor.History))
	copy(results, s.monitor.History)

	var filteredHosts map[string]bool
	if !isAuthenticated {
		filteredHosts = make(map[string]bool)
		for _, h := range s.monitor.Hosts {
			if h.Public {
				filteredHosts[h.Host] = true
			}
		}
	}
	s.monitor.mu.RUnlock()

	// Filter
	filtered := make([]CheckResult, 0)
	cutoff := time.Time{}
	if sinceStr != "" {
		dur, err := time.ParseDuration(sinceStr)
		if err == nil {
			cutoff = time.Now().Add(-dur)
		}
	}

	for _, res := range results {
		if !isAuthenticated {
			if filteredHosts == nil || !filteredHosts[res.Host] {
				continue
			}
		}
		if !cutoff.IsZero() && res.Time.Before(cutoff) {
			continue
		}
		if hostFilter != "" && !strings.Contains(res.Host, hostFilter) {
			continue
		}
		filtered = append(filtered, res)
	}

	// Limit
	if limitStr != "" {
		limit, _ := strconv.Atoi(limitStr)
		if limit > 0 && limit < len(filtered) {
			filtered = filtered[len(filtered)-limit:]
		}
	}

	// Sort by time descending (latest first)
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Time.After(filtered[j].Time)
	})

	s.respond(w, r, filtered)
}

func (s *Server) isWhitelisted(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, cidr := range s.config.IPWhitelist {
		// IPv6 loopback matching
		if (cidr == "::1" || cidr == "::1/128") && (host == "::1" || host == "0:0:0:0:0:0:0:1") {
			return true
		}
		if !strings.Contains(cidr, "/") {
			// Try as plain IP
			if cidr == host {
				return true
			}
			// Also check if it's a valid IP and compare
			if net.ParseIP(cidr).Equal(ip) {
				return true
			}
			continue
		}

		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			if ipNet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	apiKey, isAuthenticated := s.auth.GetAuthFromRequest(r)

	if !isAuthenticated {
		isAuthenticated = s.isWhitelisted(r.RemoteAddr)
	}

	s.monitor.mu.RLock()
	var hosts []map[string]interface{}
	totalOnline := 0
	totalOffline := 0

	// Also get latest results for these hosts
	results := make(map[string]CheckResult)
	for i := len(s.monitor.History) - 1; i >= 0; i-- {
		res := s.monitor.History[i]
		if _, ok := results[res.Host]; !ok {
			results[res.Host] = res
		}
	}

	var hostList []*HostStatus
	for _, h := range s.monitor.Hosts {
		if isAuthenticated || h.Public {
			hostList = append(hostList, h)
		}
	}
	s.monitor.mu.RUnlock()

	sort.Slice(hostList, func(i, j int) bool {
		return hostList[i].Host < hostList[j].Host
	})

	for _, h := range hostList {
		status := "N/A"
		lastRun := "00:00:00"
		if h.LastRun.Unix() > 0 {
			lastRun = h.LastRun.Format("15:04:05")
		}
		if res, ok := results[h.Host]; ok {
			status = res.Status
			lastRun = res.Time.Format("15:04:05")
			if status == "SSH" {
				totalOnline++
			} else if status == "TIMEOUT" {
				totalOffline++
			}
		}

		hosts = append(hosts, map[string]interface{}{
			"Host":            h.Host,
			"Status":          status,
			"LastRun":         lastRun,
			"Interval":        h.Interval.String(),
			"Timeout":         h.Timeout.String(),
			"Public":          h.Public,
			"IsAuthenticated": isAuthenticated,
		})
	}

	data := map[string]interface{}{
		"Title":           "Dashboard",
		"Page":            "index",
		"IsAuthenticated": isAuthenticated,
		"KeyType":         apiKey.Type,
		"Hosts":           hosts,
		"Stats": map[string]int{
			"Total":   len(hosts),
			"Online":  totalOnline,
			"Offline": totalOffline,
		},
	}

	s.templates.Render(w, "index", data)
}

func (s *Server) handleForm(w http.ResponseWriter, r *http.Request) {
	apiKey, _ := s.auth.GetAuthFromRequest(r)

	s.monitor.mu.RLock()

	// Get latest results for each host
	results := make(map[string]CheckResult)
	for i := len(s.monitor.History) - 1; i >= 0; i-- {
		res := s.monitor.History[i]
		if _, ok := results[res.Host]; !ok {
			results[res.Host] = res
		}
	}

	var hosts []map[string]interface{}
	for _, h := range s.monitor.Hosts {
		status := "N/A"
		lastRun := "00:00:00"
		if h.LastRun.Unix() > 0 {
			lastRun = h.LastRun.Format("15:04:05")
		}
		if res, ok := results[h.Host]; ok {
			status = res.Status
			lastRun = res.Time.Format("15:04:05")
		}

		hosts = append(hosts, map[string]interface{}{
			"Host":            h.Host,
			"Status":          status,
			"LastRun":         lastRun,
			"Interval":        h.Interval.String(),
			"Timeout":         h.Timeout.String(),
			"Public":          h.Public,
			"IsAuthenticated": true,
		})
	}

	// Get network ranges
	var networkRanges []map[string]interface{}
	for _, nr := range s.config.NetworkRanges {
		interval := s.config.DefaultInterval
		if nr.Interval != "" {
			interval = nr.Interval
		}
		timeout := s.config.DefaultTimeout
		if nr.Timeout != "" {
			timeout = nr.Timeout
		}
		networkRanges = append(networkRanges, map[string]interface{}{
			"CIDR":     nr.CIDR,
			"Interval": interval,
			"Timeout":  timeout,
			"Public":   nr.Public,
		})
	}
	s.monitor.mu.RUnlock()

	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i]["Host"].(string) < hosts[j]["Host"].(string)
	})

	data := map[string]interface{}{
		"Title":           "Admin",
		"Page":            "admin",
		"IsAuthenticated": true,
		"KeyType":         apiKey.Type,
		"Hosts":           hosts,
		"NetworkRanges":   networkRanges,
		"MasterKeys":      s.config.MasterKeys,
		"NormalKeys":      s.config.NormalKeys,
	}

	// For htmx requests to partial updates, render just the requested part
	if s.isHtmxRequest(r) {
		target := r.Header.Get("HX-Target")
		if target != "" && target != "body" {
			// Handle partial renders if needed
			s.templates.Render(w, "admin", data)
			return
		}
	}

	s.templates.Render(w, "admin", data)
}

// Debug endpoints for diagnostics
func (s *Server) handleDebugHosts(w http.ResponseWriter, r *http.Request) {
	s.logger.Info("debug", "=== DEBUG: /api/debug/hosts called ===")

	s.monitor.mu.RLock()
	defer s.monitor.mu.RUnlock()

	type HostDebug struct {
		Host     string `json:"host"`
		Interval string `json:"interval"`
		Timeout  string `json:"timeout"`
		Public   bool   `json:"public"`
		LastRun  string `json:"last_run"`
	}

	hosts := make([]HostDebug, 0, len(s.monitor.Hosts))
	for _, h := range s.monitor.Hosts {
		lastRun := "never"
		if !h.LastRun.IsZero() {
			lastRun = h.LastRun.Format(time.RFC3339)
		}
		hosts = append(hosts, HostDebug{
			Host:     h.Host,
			Interval: h.Interval.String(),
			Timeout:  h.Timeout.String(),
			Public:   h.Public,
			LastRun:  lastRun,
		})
	}

	s.logger.Info("debug", "Total hosts in monitor: %d", len(hosts))
	for i, h := range hosts {
		s.logger.Info("debug", "  Host[%d]: %s (public=%v, interval=%s, timeout=%s)", i, h.Host, h.Public, h.Interval, h.Timeout)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total": len(hosts),
		"hosts": hosts,
	})
}

func (s *Server) handleDebugRanges(w http.ResponseWriter, r *http.Request) {
	s.logger.Info("debug", "=== DEBUG: /api/debug/ranges called ===")

	type RangeDebug struct {
		CIDR     string `json:"cidr"`
		Interval string `json:"interval"`
		Timeout  string `json:"timeout"`
		Public   bool   `json:"public"`
	}

	ranges := make([]RangeDebug, 0, len(s.config.NetworkRanges))
	for _, nr := range s.config.NetworkRanges {
		ranges = append(ranges, RangeDebug{
			CIDR:     nr.CIDR,
			Interval: nr.Interval,
			Timeout:  nr.Timeout,
			Public:   nr.Public,
		})
	}

	s.logger.Info("debug", "Total ranges in config: %d", len(ranges))
	for i, r := range ranges {
		s.logger.Info("debug", "  Range[%d]: %s (public=%v, interval=%s, timeout=%s)", i, r.CIDR, r.Public, r.Interval, r.Timeout)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total":  len(ranges),
		"ranges": ranges,
	})
}

func (s *Server) handleDebugConfig(w http.ResponseWriter, r *http.Request) {
	s.logger.Info("debug", "=== DEBUG: /api/debug/config called ===")

	configData := map[string]interface{}{
		"network_ranges_count": len(s.config.NetworkRanges),
		"network_ranges":       s.config.NetworkRanges,
		"master_keys_count":    len(s.config.MasterKeys),
		"normal_keys_count":    len(s.config.NormalKeys),
	}

	s.logger.Info("debug", "Config has %d network ranges", len(s.config.NetworkRanges))
	s.logger.Info("debug", "Config has %d master keys", len(s.config.MasterKeys))
	s.logger.Info("debug", "Config has %d normal keys", len(s.config.NormalKeys))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(configData)
}

func (s *Server) respond(w http.ResponseWriter, r *http.Request, data interface{}) {
	accept := r.Header.Get("Accept")
	format := r.URL.Query().Get("format")

	// If it's a simple map[string]string (like a message response),
	// default to plain text unless explicitly requested otherwise.
	if format == "json" || strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
		return
	}

	if format == "yaml" || strings.Contains(accept, "application/yaml") || strings.Contains(accept, "text/yaml") {
		w.Header().Set("Content-Type", "text/yaml")
		s.writeYAML(w, data)
		return
	}

	// Default: Plain text
	w.Header().Set("Content-Type", "text/plain")
	s.writePlainText(w, data)
}

// isHtmxRequest checks if the request is from htmx
func (s *Server) isHtmxRequest(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

// renderPartial renders a partial template for htmx responses
func (s *Server) renderPartial(w http.ResponseWriter, templateName string, data interface{}) {
	s.templates.Render(w, templateName, data)
}

// respondWithPartial sends either a partial HTML (for htmx) or JSON (for API calls)
func (s *Server) respondWithPartial(w http.ResponseWriter, r *http.Request, templateName string, jsonData interface{}, templateData interface{}) {
	if s.isHtmxRequest(r) {
		s.renderPartial(w, templateName, templateData)
	} else {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonData)
	}
}

func (s *Server) writeYAML(w io.Writer, data interface{}) {
	switch v := data.(type) {
	case []CheckResult:
		for _, res := range v {
			fmt.Fprintf(w, "- host: %s\n", res.Host)
			fmt.Fprintf(w, "  status: %s\n", res.Status)
			fmt.Fprintf(w, "  time: %s\n", res.Time.Format(time.RFC3339))
		}
	case []*HostStatus:
		for _, h := range v {
			fmt.Fprintf(w, "- host: %s\n", h.Host)
			fmt.Fprintf(w, "  interval: %v\n", h.Interval)
			fmt.Fprintf(w, "  timeout: %v\n", h.Timeout)
			fmt.Fprintf(w, "  last_run: %s\n", h.LastRun.Format(time.RFC3339))
		}
	default:
		fmt.Fprintf(w, "message: %v\n", v)
	}
}

func (s *Server) writePlainText(w io.Writer, data interface{}) {
	switch v := data.(type) {
	case []CheckResult:
		for _, res := range v {
			fmt.Fprintf(w, "[%s] %s -> %s\n", res.Time.Format("15:04:05"), res.Host, res.Status)
		}
	case []*HostStatus:
		for _, h := range v {
			fmt.Fprintf(w, "Host: %s, Interval: %v, Timeout: %v, Last: %v\n", h.Host, h.Interval, h.Timeout, h.LastRun.Format("15:04:05"))
		}
	default:
		fmt.Fprintf(w, "%v\n", v)
	}
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Check authentication
	apiKey, isAuthenticated := s.auth.GetAuthFromRequest(r)

	// Allow unauthenticated connections (they'll only see public hosts)
	if !isAuthenticated {
		isAuthenticated = s.isWhitelisted(r.RemoteAddr)
	}

	// Upgrade HTTP connection to WebSocket
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			// Allow all origins for now (consider restricting in production)
			return true
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("websocket", "Failed to upgrade connection: %v", err)
		return
	}

	// Create new client
	client := &Client{
		hub:             s.hub,
		conn:            conn,
		send:            make(chan []byte, 256),
		isAuthenticated: isAuthenticated,
		lastPong:        time.Now(),
	}

	// Register client with hub
	s.hub.register <- client

	// Start client goroutines
	client.ServeWS()

	s.logger.Info("websocket", "Client connected (authenticated: %v, type: %s)", isAuthenticated, apiKey.Type)
}

func normalizeTarget(target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return net.JoinHostPort(target, "22")
	}
	if port == "" {
		return net.JoinHostPort(host, "22")
	}
	return target
}

func generateRandomKey(length int) string {
	b := make([]byte, length/2)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func generateSelfSignedCert(certPath, keyPath string, domains []string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SSH Monitor Self-Signed"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, d := range domains {
		if ip := net.ParseIP(d); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, d)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Create temp files in the same directory as target files to ensure atomic rename
	certDir := filepath.Dir(certPath)
	certTmp, err := os.CreateTemp(certDir, "cert-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp cert file: %w", err)
	}
	certTmpName := certTmp.Name()
	defer os.Remove(certTmpName) // Clean up if not renamed successfully

	if err := pem.Encode(certTmp, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		certTmp.Close()
		return fmt.Errorf("failed to write data to cert file: %w", err)
	}
	if err := certTmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp cert file: %w", err)
	}

	keyDir := filepath.Dir(keyPath)
	keyTmp, err := os.CreateTemp(keyDir, "key-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp key file: %w", err)
	}
	keyTmpName := keyTmp.Name()
	defer os.Remove(keyTmpName) // Clean up if not renamed successfully

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		keyTmp.Close()
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	if err := pem.Encode(keyTmp, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		keyTmp.Close()
		return fmt.Errorf("failed to write data to key file: %w", err)
	}
	if err := keyTmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp key file: %w", err)
	}

	// Now rename both files
	if err := os.Rename(certTmpName, certPath); err != nil {
		return fmt.Errorf("failed to rename cert file: %w", err)
	}
	if err := os.Rename(keyTmpName, keyPath); err != nil {
		return fmt.Errorf("failed to rename key file: %w", err)
	}

	return nil
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); {
		ips = append(ips, ip.String())
		inc(ip)

		// Check for wrap-around to avoid infinite loop on /0
		isZero := true
		for _, b := range ip {
			if b != 0 {
				isZero = false
				break
			}
		}
		if isZero {
			break
		}
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// handleDebugTestWebSocket tests WebSocket by adding a test host and broadcasting an update
func (s *Server) handleDebugTestWebSocket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Add a test host
	testHost := fmt.Sprintf("test-%d.example.com:22", time.Now().Unix())
	s.monitor.AddHost(testHost, 5*time.Minute, 3*time.Second, true)
	s.logger.Info("debug", "Added test host: %s", testHost)

	// Manually trigger a status update broadcast
	result := CheckResult{
		Host:   testHost,
		Status: "SSH",
		Time:   time.Now(),
	}

	if s.hub != nil {
		s.hub.BroadcastHostUpdate(result)
		s.logger.Info("debug", "Broadcasted status update for %s", testHost)
	} else {
		s.logger.Warning("debug", "Hub is nil, cannot broadcast")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"host":    testHost,
		"message": "Test host added and WebSocket update broadcasted",
	})
}

// handleDebugWebSocketStatus shows WebSocket connection status
func (s *Server) handleDebugWebSocketStatus(w http.ResponseWriter, r *http.Request) {
	if s.hub == nil {
		http.Error(w, "WebSocket hub not initialized", http.StatusInternalServerError)
		return
	}

	s.hub.mu.RLock()
	clientCount := len(s.hub.clients)
	s.hub.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"connected_clients": clientCount,
		"hub_running":       s.hub != nil,
	})
}
