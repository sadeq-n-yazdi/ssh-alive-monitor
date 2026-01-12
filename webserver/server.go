package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	sshPattern = regexp.MustCompile(`^SSH-[0-9.]+-[a-zA-Z0-9 .-]+`)
)

// Configuration
const (
	DefaultInterval = 10 * time.Minute
	HistoryCapacity = 50 // Enough for > 6 hours at 10m interval
	WorkerConcurrency = 100
)

// Data Models
type CheckResult struct {
	Host   string `json:"host" yaml:"host"`
	Status string `json:"status" yaml:"status"`
}

type RunResult struct {
	Time    time.Time     `json:"time" yaml:"time"`
	Results []CheckResult `json:"results" yaml:"results"`
}

type AppState struct {
	Hosts   []string
	History []RunResult
	mu      sync.RWMutex
}

var state = AppState{
	Hosts:   []string{},
	History: make([]RunResult, 0, HistoryCapacity),
}

func main() {
	port := flag.String("port", "8080", "Port to listen on")
	flag.Parse()

	// Start the background monitor
	go monitorLoop()

	// API Handlers
	http.HandleFunc("/api/hosts", handleHosts)
	http.HandleFunc("/api/results", handleResults)

	fmt.Printf("Server starting on port %s...\n", *port)
	log.Fatal(http.ListenAndServe(":"+*port, nil))
}

// --- Monitor Logic ---

func monitorLoop() {
	ticker := time.NewTicker(DefaultInterval)
	defer ticker.Stop()

	// Run immediately on start
	runChecks()

	for range ticker.C {
		runChecks()
	}
}

func runChecks() {
	state.mu.RLock()
	hosts := make([]string, len(state.Hosts))
	copy(hosts, state.Hosts)
	state.mu.RUnlock()

	if len(hosts) == 0 {
		return
	}

	var wg sync.WaitGroup
	results := make([]CheckResult, len(hosts))
	sem := make(chan struct{}, WorkerConcurrency)

	for i, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(index int, target string) {
			defer wg.Done()
			defer func() { <-sem }()
			
			// Normalize happens on add, but good to be safe
			normTarget := normalizeTarget(target) 
			status := checkHost(normTarget)
			results[index] = CheckResult{Host: normTarget, Status: status}
		}(i, host)
	}
	wg.Wait()

	runResult := RunResult{
		Time:    time.Now(),
		Results: results,
	}

	state.mu.Lock()
	// Append to history
	state.History = append(state.History, runResult)
	// Trim history if it exceeds capacity (keep last N)
	if len(state.History) > HistoryCapacity {
		state.History = state.History[len(state.History)-HistoryCapacity:]
	}
	state.mu.Unlock()
}

// Reuse logic from main.go
func checkHost(target string) string {
	timeout := 5 * time.Second
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		if opErr, ok := err.(*net.OpError); ok {
			if opErr.Timeout() {
				return "TIMEOUT"
			}
			if isConnectionRefused(err) {
				return "ACTIVE_REJECT"
			}
		}
		return "TIMEOUT"
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, 255)
	n, err := conn.Read(buf)
	if err != nil {
		if err == io.EOF {
			return "ACTIVE_REJECT"
		}
		return "TIMEOUT"
	}

	data := string(buf[:n])
	if sshPattern.MatchString(data) {
		return "SSH"
	}

	return "ACTIVE_REJECT"
}

func isConnectionRefused(err error) bool {
	return strings.Contains(err.Error(), "refused")
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

// --- API Handlers ---

func handleHosts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		state.mu.RLock()
		json.NewEncoder(w).Encode(state.Hosts)
		state.mu.RUnlock()
	
	case http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		host := strings.TrimSpace(string(body))
		if host == "" {
			http.Error(w, "Empty host", http.StatusBadRequest)
			return
		}
		host = normalizeTarget(host)

		state.mu.Lock()
		// Simple dedup
		exists := false
		for _, h := range state.Hosts {
			if h == host {
				exists = true
				break
			}
		}
		if !exists {
			state.Hosts = append(state.Hosts, host)
		}
		state.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Added " + host))

	case http.MethodDelete:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		host := strings.TrimSpace(string(body))
		host = normalizeTarget(host)

		state.mu.Lock()
		newHosts := make([]string, 0, len(state.Hosts))
		found := false
		for _, h := range state.Hosts {
			if h != host {
				newHosts = append(newHosts, h)
			} else {
				found = true
			}
		}
		state.Hosts = newHosts
		state.mu.Unlock()

		if found {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Removed " + host))
		} else {
			http.Error(w, "Host not found", http.StatusNotFound)
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()
	format := query.Get("format")
	sinceStr := query.Get("since")
	limitStr := query.Get("limit")

	state.mu.RLock()
	defer state.mu.RUnlock()

	// Filter Logic
	var filtered []RunResult
	cutoff := time.Time{}

	// Default: Last 6 hours
	if sinceStr == "" && limitStr == "" {
		cutoff = time.Now().Add(-6 * time.Hour)
	} else if sinceStr != "" {
		dur, err := time.ParseDuration(sinceStr)
		if err == nil {
			cutoff = time.Now().Add(-dur)
		}
	}

	for _, run := range state.History {
		if run.Time.After(cutoff) {
			filtered = append(filtered, run)
		}
	}
	
	// Apply limit if specified (takes precedence over time filter? or applies to the filtered set?)
	// "if request specified number of result ... it must respect"
	if limitStr != "" {
		var limit int
		fmt.Sscanf(limitStr, "%d", &limit)
		if limit > 0 && limit < len(filtered) {
			// Get the *last* N results
			filtered = filtered[len(filtered)-limit:]
		}
	}

	// Output Formatting
	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(filtered)
	case "yaml":
		w.Header().Set("Content-Type", "text/yaml")
		// Manual YAML marshaling to avoid external deps
		for _, run := range filtered {
			fmt.Fprintf(w, "- time: %s\n", run.Time.Format(time.RFC3339))
			fmt.Fprintf(w, "  results:\n")
			for _, res := range run.Results {
				fmt.Fprintf(w, "    - host: %s\n", res.Host)
				fmt.Fprintf(w, "      status: %s\n", res.Status)
			}
		}
	default: // Plain text
		w.Header().Set("Content-Type", "text/plain")
		for _, run := range filtered {
			fmt.Fprintf(w, "Time: %s\n", run.Time.Format(time.RFC3339))
			for _, res := range run.Results {
				fmt.Fprintf(w, "  %s -> %s\n", res.Host, res.Status)
			}
			fmt.Fprintln(w, "--------------------------------------------------")
		}
	}
}
