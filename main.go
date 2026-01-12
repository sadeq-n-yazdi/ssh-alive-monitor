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
	timeout    time.Duration
	sshPattern = regexp.MustCompile(`^SSH-[0-9.]+-[a-zA-Z0-9 .-]+`)
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
	// Limit concurrency to avoid file descriptor exhaustion on large lists
	sem := make(chan struct{}, 100)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Split line by whitespace to handle multiple hosts per line or simple lists
		tokens := strings.Fields(line)
		for _, token := range tokens {
			wg.Add(1)
			sem <- struct{}{}
			
			go func(rawTarget string) {
				defer wg.Done()
				defer func() { <-sem }()

				target := normalizeTarget(rawTarget)
				status := checkHost(target)

				fmt.Printf("%s %s\n", target, status)

				if status == "SSH" {
					foundSSH.Store(true)
				}
			}(token)
		}
	}

	wg.Wait()

	if foundSSH.Load() {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

func normalizeTarget(target string) string {
	// Attempt to split host and port
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		// If error contains "missing port" or "too many colons" (raw IPv6),
		// assume the whole string is the host and default to port 22.
		// Note: net.SplitHostPort("::1") returns "too many colons in address".
		// net.SplitHostPort("127.0.0.1") returns "missing port in address".
		return net.JoinHostPort(target, "22")
	}
	if port == "" {
		return net.JoinHostPort(host, "22")
	}
	return target
}

func checkHost(target string) string {
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		if opErr, ok := err.(*net.OpError); ok {
			if opErr.Timeout() {
				return "TIMEOUT"
			}
			// systematic way to check for connection refused
			if isConnectionRefused(err) {
				return "ACTIVE_REJECT"
			}
		}
		// Fallback for other errors (e.g. no route to host), treat as TIMEOUT or specific error
		// For the purpose of this tool, if we can't reach it, it's effectively a timeout/unreachable.
		return "TIMEOUT"
	}
	defer conn.Close()

	// Set a deadline for reading the banner
	conn.SetReadDeadline(time.Now().Add(timeout))

	// SSH identification string must be the first line(s).
	// We will read a chunk and check the prefix.
	buf := make([]byte, 255)
	n, err := conn.Read(buf)
	if err != nil {
		// If EOF happened immediately?
		if err == io.EOF {
			return "ACTIVE_REJECT" 
		}
		return "TIMEOUT"
	}

	data := string(buf[:n])
	
	// We strictly check if the data starts with the SSH pattern provided.
	if sshPattern.MatchString(data) {
		return "SSH"
	}

	// If we connected but didn't get SSH banner
	return "ACTIVE_REJECT" // Or "PROTOCOL_MISMATCH" but prompt asks for (TIMOUT/ACTIVEREJEVT/SSH)
}

func isConnectionRefused(err error) bool {
	// Go's net package doesn't expose a direct "ConnectionRefused" error type across all platforms consistently
	// without inspecting the syscall error, but checking the string is a common pragmatic fallback.
	return strings.Contains(err.Error(), "refused")
}