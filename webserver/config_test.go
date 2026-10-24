package main

import "testing"

func TestListenAddr(t *testing.T) {
	tests := []struct {
		addr, port, want string
	}{
		{"", "9009", ":9009"},
		{"127.0.0.1", "9009", "127.0.0.1:9009"},
		{"::1", "9009", "[::1]:9009"},
	}
	for _, tt := range tests {
		c := Config{ListenAddress: tt.addr, Port: tt.port}
		if got := c.listenAddr(); got != tt.want {
			t.Errorf("listenAddr(%q, %q) = %q, want %q", tt.addr, tt.port, got, tt.want)
		}
	}
}
