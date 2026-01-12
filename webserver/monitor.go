package main

import (
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type HostStatus struct {
	Host     string        `json:"host"`
	Interval time.Duration `json:"interval"`
	Timeout  time.Duration `json:"timeout"`
	LastRun  time.Time     `json:"last_run"`
	NextRun  time.Time     `json:"next_run"`
	Public   bool          `json:"public"`
}

type CheckResult struct {
	Host   string    `json:"host"`
	Status string    `json:"status"`
	Time   time.Time `json:"time"`
}

type Monitor struct {
	Hosts   map[string]*HostStatus
	History []CheckResult
	mu      sync.RWMutex
	logger  *Logger
	stop    chan struct{}
}

func NewMonitor(logger *Logger) *Monitor {
	return &Monitor{
		Hosts:   make(map[string]*HostStatus),
		History: make([]CheckResult, 0),
		logger:  logger,
		stop:    make(chan struct{}),
	}
}

func (m *Monitor) AddHost(host string, interval, timeout time.Duration, isPublic bool) {
	m.mu.Lock()
	m.Hosts[host] = &HostStatus{
		Host:     host,
		Interval: interval,
		Timeout:  timeout,
		NextRun:  time.Now(), // Run immediately
		Public:   isPublic,
	}
	m.mu.Unlock()
	m.logger.Info("checks", "Added host: %s (interval: %v, timeout: %v, public: %v)", host, interval, timeout, isPublic)
}

func (m *Monitor) RemoveHost(host string) {
	m.mu.Lock()
	delete(m.Hosts, host)
	m.mu.Unlock()
	m.logger.Info("checks", "Removed host: %s", host)
}

func (m *Monitor) Start() {
	ticker := time.NewTicker(1 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				m.checkHosts()
			case <-m.stop:
				ticker.Stop()
				return
			}
		}
	}()
}

func (m *Monitor) checkHosts() {
	now := time.Now()
	var toCheck []*HostStatus

	m.mu.RLock()
	for _, h := range m.Hosts {
		if now.After(h.NextRun) {
			toCheck = append(toCheck, h)
		}
	}
	m.mu.RUnlock()

	for _, h := range toCheck {
		go m.runCheck(h)
	}
}

func (m *Monitor) runCheck(h *HostStatus) {
	// Update next run time immediately to prevent multiple concurrent checks for same host
	m.mu.Lock()
	h.NextRun = time.Now().Add(h.Interval)
	m.mu.Unlock()

	status := checkHost(h.Host, h.Timeout)

	result := CheckResult{
		Host:   h.Host,
		Status: status,
		Time:   time.Now(),
	}

	m.mu.Lock()
	h.LastRun = result.Time
	m.History = append(m.History, result)
	// Limit history size to 1000 for now
	if len(m.History) > 1000 {
		m.History = m.History[len(m.History)-1000:]
	}
	m.mu.Unlock()

	m.logger.Info("checks", "Check result for %s: %s", h.Host, status)
}

func checkHost(target string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		if opErr, ok := err.(*net.OpError); ok {
			if opErr.Timeout() {
				return "TIMEOUT"
			}
		}
		if strings.Contains(err.Error(), "refused") {
			return "ACTIVE_REJECT"
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

	return "PROTOCOL_MISMATCH"
}
