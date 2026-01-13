package main

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

type CertManager struct {
	certFile string
	keyFile  string
	cert     *tls.Certificate
	mu       sync.RWMutex
	lastMod  time.Time
	logger   *Logger
}

func NewCertManager(certFile, keyFile string, logger *Logger) *CertManager {
	cm := &CertManager{
		certFile: certFile,
		keyFile:  keyFile,
		logger:   logger,
	}
	cm.loadCert() // Load initially
	return cm
}

func (cm *CertManager) loadCert() error {
	info, err := os.Stat(cm.certFile)
	if err != nil {
		return err
	}

	// If mod time hasn't changed since last successful load, skip
	if !info.ModTime().After(cm.lastMod) && cm.cert != nil {
		return nil
	}

	cm.logger.Info("requests", "Reloading SSL certificate from %s", cm.certFile)
	cert, err := tls.LoadX509KeyPair(cm.certFile, cm.keyFile)
	if err != nil {
		cm.logger.Error("requests", "Failed to load certificate: %v", err)
		return err
	}

	cm.mu.Lock()
	cm.cert = &cert
	cm.lastMod = info.ModTime()
	cm.mu.Unlock()
	return nil
}

func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Check for updates periodically or on every request (throttled)
	// For simplicity, we'll check stat every time but it's fast. 
	// To avoid too many stat calls, we could throttle.
	// But let's keep it simple: just return cached cert, and have a background routine update it.
	
	cm.mu.RLock()
	cert := cm.cert
	cm.mu.RUnlock()
	
	return cert, nil
}

func (cm *CertManager) StartWatcher() {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			cm.loadCert()
		}
	}()
}
