package main

import (
	"net/http"
	"sync"
)

type APIKeyType string

const (
	KeyMaster APIKeyType = "master"
	KeyNormal APIKeyType = "normal"
)

type APIKey struct {
	Key     string     `json:"key"`
	Type    APIKeyType `json:"type"`
	Enabled bool       `json:"enabled"`
}

type AuthManager struct {
	Keys map[string]APIKey
	mu   sync.RWMutex
}

func NewAuthManager(masterKeys []string) *AuthManager {
	am := &AuthManager{
		Keys: make(map[string]APIKey),
	}
	for _, k := range masterKeys {
		am.Keys[k] = APIKey{Key: k, Type: KeyMaster, Enabled: true}
	}
	return am
}

func (am *AuthManager) Authenticate(key string) (APIKey, bool) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	apiKey, ok := am.Keys[key]
	if !ok || !apiKey.Enabled {
		return APIKey{}, false
	}
	return apiKey, true
}

func (am *AuthManager) AddKey(key string, kType APIKeyType) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.Keys[key] = APIKey{Key: key, Type: kType, Enabled: true}
}

func (am *AuthManager) DeleteKey(key string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	delete(am.Keys, key)
}

func (am *AuthManager) SetEnabled(key string, enabled bool) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if k, ok := am.Keys[key]; ok {
		k.Enabled = enabled
		am.Keys[key] = k
	}
}

func (am *AuthManager) AuthMiddleware(next http.HandlerFunc, minType APIKeyType) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			// Try Basic Auth
			_, password, ok := r.BasicAuth()
			if ok {
				key = password
			}
		}

		if key == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Missing API Key", http.StatusUnauthorized)
			return
		}

		apiKey, ok := am.Authenticate(key)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Invalid or disabled API Key", http.StatusUnauthorized)
			return
		}

		if minType == KeyMaster && apiKey.Type != KeyMaster {
			http.Error(w, "Forbidden: Master key required", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}
