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
	IsQueued bool          `json:"-"` // Track if host is already in pending queue
}

type CheckResult struct {
	Host   string    `json:"host"`
	Status string    `json:"status"`
	Time   time.Time `json:"time"`
}

type Monitor struct {
	Hosts           map[string]*HostStatus
	History         []CheckResult
	PendingHosts    []*HostStatus
	ActivePerSubnet map[string]int
	TotalActive     int
	PoolSize        int
	SubnetLimit     int
	mu              sync.RWMutex
	logger          *Logger
	stop            chan struct{}
}

func NewMonitor(logger *Logger, poolSize int, subnetLimit int) *Monitor {
	if poolSize <= 0 {
		poolSize = 100
	}
	if subnetLimit <= 0 {
		subnetLimit = 2
	}
	return &Monitor{
		Hosts:           make(map[string]*HostStatus),
		History:         make([]CheckResult, 0),
		PendingHosts:    make([]*HostStatus, 0),
		ActivePerSubnet: make(map[string]int),
		PoolSize:        poolSize,
		SubnetLimit:     subnetLimit,
		logger:          logger,
		stop:            make(chan struct{}),
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
	m.mu.Lock()

	// Find due hosts
	for _, h := range m.Hosts {
		if !h.IsQueued && now.After(h.NextRun) {
			h.IsQueued = true
			m.PendingHosts = append(m.PendingHosts, h)
		}
	}
	m.mu.Unlock()

	m.processPending()
}

func (m *Monitor) processPending() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// While we have capacity and pending jobs
	// We need to iterate carefully because we might skip some jobs due to subnet limits
	// but process others further down the queue?
	// The requirement says "FIFO order".
	// Strictly FIFO means if the head of the queue is blocked by subnet limit, we stop?
	// OR "pool must serve FIFO order" usually means we process in arrival order.
	// If head is blocked, strictly FIFO would block everyone.
	// But "limited for number of parallel check for ip address" suggests we should skip blocked ones
	// to allow others to run, otherwise one subnet could stall the whole system.
	// A common interpretation of "Pool with FIFO" + "Rate Limit" is:
	// Process queue in order. If item can run, run it. If not, re-queue or skip.
	// Let's implement: Iterate queue, if runnable, run and remove. If not, keep.
	// This respects FIFO for *runnable* jobs (i.e. we don't pick a later job for the SAME subnet before an earlier one).
	// But it allows other subnets to proceed.

	var remaining []*HostStatus
	processedCount := 0

	for _, h := range m.PendingHosts {
		// Global Limit
		if m.TotalActive >= m.PoolSize {
			remaining = append(remaining, h)
			continue
		}

		subnet := getSubnet(h.Host)

		// Subnet Limit
		if m.ActivePerSubnet[subnet] >= m.SubnetLimit {
			remaining = append(remaining, h)
			continue
		}

		// Can run
		m.TotalActive++
		m.ActivePerSubnet[subnet]++
		h.IsQueued = false // It's no longer in queue, it's active

		// Update NextRun immediately to push it back
		h.NextRun = time.Now().Add(h.Interval)

		go m.executeCheck(h, subnet)
		processedCount++
	}

	// Optimization: If we didn't process anything, remaining is identical to m.PendingHosts.
	// We can avoid allocation if we are careful, but for simplicity:
	m.PendingHosts = remaining
}

func (m *Monitor) executeCheck(h *HostStatus, subnet string) {
	status := checkHost(h.Host, h.Timeout)

	result := CheckResult{
		Host:   h.Host,
		Status: status,
		Time:   time.Now(),
	}

	m.mu.Lock()
	h.LastRun = result.Time
	m.History = append(m.History, result)
	if len(m.History) > 1000 {
		m.History = m.History[len(m.History)-1000:]
	}

	// Release limits
	m.TotalActive--
	m.ActivePerSubnet[subnet]--
	if m.ActivePerSubnet[subnet] == 0 {
		delete(m.ActivePerSubnet, subnet)
	}
	m.mu.Unlock()

	m.logger.Info("checks", "Check result for %s: %s", h.Host, status)

	// Trigger processing of next jobs
	m.processPending()
}

func getSubnet(host string) string {
	// Simple /24 extraction for IPv4.
	// If it's a hostname, we can't easily know the IP without resolving.
	// For now, let's try to resolve or just use the string.
	// If we resolve here, it might block or slow down.
	// Ideally, HostStatus should store the resolved IP or we group by "Target String".
	// Requirement says "same /24 block address".
	// We'll try to parse as IP.

	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host // Fallback
	}

	ip := net.ParseIP(h)
	if ip == nil {
		// Not an IP, maybe hostname. Return hostname as group key?
		// Or resolving? Resolving every time is bad.
		// Let's assume for this feature users provide IPs.
		// If hostname, we treat it as its own unique group.
		return h
	}

	ip4 := ip.To4()
	if ip4 != nil {
		// IPv4: return first 3 bytes (x.x.x)
		return ip4.Mask(net.CIDRMask(24, 32)).String()
	}

	// IPv6: /64?
	// "same /24 block" usually implies IPv4 context.
	// For IPv6 let's use /64
	return ip.Mask(net.CIDRMask(64, 128)).String()
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
