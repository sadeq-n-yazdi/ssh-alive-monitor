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
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
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
	monitor := NewMonitor(logger)

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

	monitor.Start()

	initialHash, _ := getFilesHash([]string{"config.json", "config-override.json"})

	s := &Server{
		config:      cfg,
		logger:      logger,
		auth:        auth,
		monitor:     monitor,
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

	// Results (Normal and Master)
	mux.HandleFunc("/api/results", s.handleResults)

	// Index page
	mux.HandleFunc("/", s.handleIndex)

	// Form interface
	mux.HandleFunc("/form/", s.auth.AuthMiddleware(s.handleForm, KeyNormal))
	mux.HandleFunc("/logout", s.handleLogout)

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
			Key      string     `json:"key"`
			Type     APIKeyType `json:"type"`
			Generate bool       `json:"generate"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
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

		s.respond(w, r, map[string]string{"message": "Key added", "key": req.Key})

	case http.MethodDelete:
		key := r.URL.Query().Get("key")
		if key == "" {
			http.Error(w, "Key is required", http.StatusBadRequest)
			return
		}
		s.auth.DeleteKey(key)

		// Sync to config
		s.config.MasterKeys = s.auth.GetKeysByType(KeyMaster)
		s.config.NormalKeys = s.auth.GetKeysByType(KeyNormal)
		s.saveConfig()

		s.respond(w, r, map[string]string{"message": "Key deleted"})

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
			Interval string `json:"interval"`
			Timeout  string `json:"timeout"`
		}

		// Handle both JSON and plain text body for backward compatibility or simple adds
		contentType := r.Header.Get("Content-Type")
		if strings.Contains(contentType, "application/json") {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			body, _ := io.ReadAll(r.Body)
			req.Host = strings.TrimSpace(string(body))
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
		s.monitor.AddHost(host, interval, timeout, false)
		s.respond(w, r, map[string]string{"message": "Host added", "host": host})

	case http.MethodPut:
		var req struct {
			Host     string `json:"host"`
			Interval string `json:"interval"`
			Timeout  string `json:"timeout"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
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
			s.logger.Info("checks", "Updated host: %s (interval: %v, timeout: %v)", host, interval, timeout)
			s.monitor.mu.Unlock()
			s.respond(w, r, map[string]string{"message": "Host updated", "host": host})
		} else {
			s.monitor.mu.Unlock()
			http.Error(w, "Host not found", http.StatusNotFound)
		}

	case http.MethodDelete:
		body, _ := io.ReadAll(r.Body)
		host := strings.TrimSpace(string(body))
		if host == "" {
			host = r.URL.Query().Get("host")
		}
		if host == "" {
			http.Error(w, "Host is required", http.StatusBadRequest)
			return
		}
		host = normalizeTarget(host)
		s.monitor.RemoveHost(host)
		s.respond(w, r, map[string]string{"message": "Host removed", "host": host})

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
	_, isAuthenticated := s.auth.GetAuthFromRequest(r)

	if !isAuthenticated {
		isAuthenticated = s.isWhitelisted(r.RemoteAddr)
	}

	s.monitor.mu.RLock()
	var hosts []*HostStatus
	for _, h := range s.monitor.Hosts {
		if isAuthenticated || h.Public {
			hosts = append(hosts, h)
		}
	}

	// Also get latest results for these hosts
	results := make(map[string]CheckResult)
	for i := len(s.monitor.History) - 1; i >= 0; i-- {
		res := s.monitor.History[i]
		if _, ok := results[res.Host]; !ok {
			if h, ok2 := s.monitor.Hosts[res.Host]; ok2 && (isAuthenticated || h.Public) {
				results[res.Host] = res
			}
		}
	}
	s.monitor.mu.RUnlock()

	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].Host < hosts[j].Host
	})

	// Simple HTML response
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<html><head><title>SSH Monitor</title><style>table{border-collapse:collapse;} th,td{border:1px solid #ccc;padding:8px;} .SSH{color:green;} .TIMEOUT{color:red;} .ACTIVE_REJECT{color:orange;} .PROTOCOL_MISMATCH{color:purple;}</style></head><body>")
	fmt.Fprintf(w, "<h1>SSH Monitor Status</h1>")
	if isAuthenticated {
		fmt.Fprintf(w, "<p>Authenticated access. <a href='/form/'>Manage Hosts/Keys</a></p>")
	} else {
		fmt.Fprintf(w, "<p>Public access (showing public hosts only). <a href='/form/'>Login</a></p>")
	}
	fmt.Fprintf(w, "<table><tr><th>Host</th><th>Interval</th><th>Timeout</th><th>Last Run</th><th>Status</th></tr>")
	for _, h := range hosts {
		status := "N/A"
		class := ""
		if res, ok := results[h.Host]; ok {
			status = res.Status
			class = res.Status
		}
		fmt.Fprintf(w, "<tr><td>%s</td><td>%v</td><td>%v</td><td>%s</td><td class='%s'>%s</td></tr>",
			h.Host, h.Interval, h.Timeout, h.LastRun.Format("15:04:05"), class, status)
	}
	fmt.Fprintf(w, "</table></body></html>")
}

func (s *Server) handleForm(w http.ResponseWriter, r *http.Request) {
	s.monitor.mu.RLock()
	var hosts []*HostStatus
	for _, h := range s.monitor.Hosts {
		hosts = append(hosts, h)
	}
	s.monitor.mu.RUnlock()

	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].Host < hosts[j].Host
	})

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<html><head><title>Management</title><style>table{border-collapse:collapse;} th,td{border:1px solid #ccc;padding:8px;}</style></head><body>")
	fmt.Fprintf(w, "<h1>Management Interface</h1>")
	fmt.Fprintf(w, "<p><a href='/'>Back to Status</a> | <a href='/logout'>Logout</a></p>")

	fmt.Fprintf(w, "<h2>Hosts</h2>")
	fmt.Fprintf(w, "<table><tr><th>Host</th><th>Interval</th><th>Timeout</th><th>Type</th><th>Actions</th></tr>")
	for _, h := range hosts {
		hType := "Private"
		if h.Public {
			hType = "Public"
		}
		fmt.Fprintf(w, "<tr>")
		fmt.Fprintf(w, "<td>%s</td>", h.Host)
		fmt.Fprintf(w, "<td><input type='text' id='int-%s' value='%v' size='5'></td>", h.Host, h.Interval)
		fmt.Fprintf(w, "<td><input type='text' id='tout-%s' value='%v' size='5'></td>", h.Host, h.Timeout)
		fmt.Fprintf(w, "<td>%s</td>", hType)
		fmt.Fprintf(w, "<td>")
		fmt.Fprintf(w, "<button onclick=\"updateHost('%s')\">Update</button> ", h.Host)
		fmt.Fprintf(w, "<button onclick=\"deleteHost('%s')\">Delete</button>", h.Host)
		fmt.Fprintf(w, "</td>")
		fmt.Fprintf(w, "</tr>")
	}
	fmt.Fprintf(w, "</table>")

	fmt.Fprintf(w, "<h2>Add Host</h2>")
	fmt.Fprintf(w, "<form onsubmit='return addHost(this)'>")
	fmt.Fprintf(w, "Host: <input type='text' name='host' required> ")
	fmt.Fprintf(w, "Interval: <input type='text' name='interval' placeholder='10m'> ")
	fmt.Fprintf(w, "Timeout: <input type='text' name='timeout' placeholder='5s'> ")
	fmt.Fprintf(w, "<input type='submit' value='Add'>")
	fmt.Fprintf(w, "</form>")

	fmt.Fprintf(w, "<h2>API Keys</h2>")
	fmt.Fprintf(w, "<button onclick='generateKey()'>Generate New Normal Key</button>")
	fmt.Fprintf(w, "<div id='new-key' style='margin-top:10px; font-weight:bold; color:blue;'></div>")

	fmt.Fprintf(w, "<script>")
	fmt.Fprintf(w, "function copyToClipboard(text) { navigator.clipboard.writeText(text).then(() => { alert('Key copied to clipboard'); }).catch(err => { console.error('Failed to copy: ', err); }); }")
	fmt.Fprintf(w, "function addHost(f){ fetch('/api/hosts', {method:'POST', headers:{'Content-Type':'application/json', 'Accept':'application/json'}, body:JSON.stringify({host:f.host.value, interval:f.interval.value, timeout:f.timeout.value})}).then(r=>r.json()).then(d=>{alert(d.message); location.reload();}).catch(e=>alert(e)); return false; }")
	fmt.Fprintf(w, "function updateHost(host){ var interval=document.getElementById('int-'+host).value; var timeout=document.getElementById('tout-'+host).value; fetch('/api/hosts', {method:'PUT', headers:{'Content-Type':'application/json', 'Accept':'application/json'}, body:JSON.stringify({host:host, interval:interval, timeout:timeout})}).then(r=>r.json()).then(d=>alert(d.message)).catch(e=>alert(e)); }")
	fmt.Fprintf(w, "function deleteHost(host){ if(confirm('Delete '+host+'?')){ fetch('/api/hosts', {method:'DELETE', headers:{'Accept':'application/json'}, body:host}).then(r=>r.json()).then(d=>{alert(d.message); location.reload();}).catch(e=>alert(e)); } }")
	fmt.Fprintf(w, "function generateKey(){ fetch('/api/keys', {method:'POST', headers:{'Content-Type':'application/json', 'Accept':'application/json'}, body:JSON.stringify({generate:true, type:'normal'})}).then(r=>r.json()).then(d=>{ document.getElementById('new-key').innerHTML = 'New Key: <code id=\"key-val\">' + d.key + '</code> <button onclick=\"copyToClipboard(\\''+d.key+'\\')\">Copy</button>'; alert('Key generated and saved to config.json'); }).catch(e=>alert(e)); }")
	fmt.Fprintf(w, "</script>")

	fmt.Fprintf(w, "</body></html>")
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
