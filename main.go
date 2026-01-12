package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	timeout     time.Duration
	sshPattern  = regexp.MustCompile(`^SSH-[0-9.]+-[a-zA-Z0-9 .-]+`)
	// Regex to loosely identify things that look like hosts/IPs with optional ports
	// This captures IPv4, IPv6 (brackets), and hostnames, with optional :port
	hostPattern = regexp.MustCompile(`(?:[a-fA-F0-9:]+|[a-fA-F0-9:]+\]|[a-zA-Z0-9._-]+)(?::[0-9]+)?`)
)

func main() {
	var timeoutSec int
	var inputFile string

	flag.IntVar(&timeoutSec, "t", 5, "Timeout in seconds")
	flag.StringVar(&inputFile, "f", "", "Input file (default stdin)")
	flag.Parse()

	timeout = time.Duration(timeoutSec) * time.Second

	var scanner *bufio.Scanner
	if inputFile != "" {
		f, err := os.Open(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		scanner = bufio.NewScanner(f)
	} else {
		scanner = bufio.NewScanner(os.Stdin)
	}

	var foundSSH atomic.Bool
	var wg sync.WaitGroup

	// Use a channel to limit concurrency slightly if needed, but for this simple app, 
	// unbounded (limited by system resources) is usually fine for reasonable inputs.
	// For robustness, let's use a semaphore-like channel to limit to e.g., 100 concurrent checks.
	sem := make(chan struct{}, 100)

	for scanner.Scan() {
		line := scanner.Text()
		// Find all matches in the line
		matches := hostPattern.FindAllString(line, -1)
		for _, target := range matches {
			wg.Add(1)
			sem <- struct{}{}
			go func(t string) {
				defer wg.Done()
				defer func() { <-sem }()
				
				result := checkHost(t)
				fmt.Printf("%s %s\n", t, result)
				
				if result == "SSH" {
					foundSSH.Store(true)
				}
			}(target)
		}
	}

	wg.Wait()

	if foundSSH.Load() {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

func checkHost(target string) string {
	// If no port specified, default to 22
	if !strings.Contains(target, ":") {
		target = net.JoinHostPort(target, "22")
	} else {
		// Handle IPv6 literal with port case e.g. [::1]:22 vs [::1]
		// net.SplitHostPort helps parse, but if we already have it from regex...
		// Our regex `(?:[a-fA-F0-9:]+|\[[a-fA-F0-9:]+\]|[a-zA-Z0-9.-]+)(?::[0-9]+)?` might capture "google.com" without port.
		// If it has a colon but not inside brackets?
		// Simplest check: does it end with `:[0-9]+`?
		// Or try SplitHostPort. If it fails, add :22.
		_, _, err := net.SplitHostPort(target)
		if err != nil {
			// Likely missing port, or invalid format. 
			// If it's an IPv6 literal without brackets, SplitHostPort might fail or return too many colons.
			// Given the regex, it's safer to attempt to Add :22 if SplitHostPort fails assuming it's just a host.
			// But careful with raw IPv6.
			// Let's assume if the last colon is followed by digits, it's a port.
			if !strings.Contains(target, "]:") && strings.Count(target, ":") > 1 && !strings.HasPrefix(target, "[") {
				// Raw IPv6?
				target = net.JoinHostPort(target, "22")
			} else if !strings.Contains(target, ":") {
				target = net.JoinHostPort(target, "22")
			}
		}
	}

	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		if opErr, ok := err.(*net.OpError); ok {
			if opErr.Timeout() {
				return "TIMEOUT"
			}
			// check for connection refused
			// The error message for refused usually contains "connection refused"
			if strings.Contains(err.Error(), "refused") {
				return "ACTIVE_REJECT"
			}
			// Network unreachable, etc.
			// Treat as generic failure or timeout?
			// User asked for TIMEOUT / ACTIVEREJEVT / SSH.
			// If host is down, it's usually timeout.
		}
		// Fallback for other errors (lookup failure etc)
		return "TIMEOUT" // effectively unreachable
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	// Buffer for the server version string
	// SSH version string is usually short, e.g., "SSH-2.0-OpenSSH_8.2p1..."
	// RFC 4253: server sends identification string.
	// Max length 255 bytes including CR LF.
	buf := make([]byte, 255)
	n, err := conn.Read(buf)
	if err != nil {
		if err == io.EOF {
			return "CLOSED"
		}
		// Read timeout
		return "TIMEOUT"
	}

	data := string(buf[:n])
	// The RFC says the server may send other lines before the version string, 
	// but usually it's the first thing or very early.
	// We'll check if the *response* (first read) *starts* with the pattern, 
	// or contains it if we want to be lenient. 
	// Prompt says: "if it starts with 'SSH-[0-9.]+-[a-zA-Z0-9 .-]+'".
	// Note: The server string might have trailing \r\n. Regex handles start.
	
	// We need to match the specific regex provided.
	if sshPattern.MatchString(data) {
		return "SSH"
	}

	return "PROTOCOL_MISMATCH"
}
