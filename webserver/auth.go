package main

import (
	"net/http"
	"sync"
	"time"
)

type APIKeyType string

const (
	KeyMaster APIKeyType = "master"
	KeyNormal APIKeyType = "normal"

	AuthCookieName = "ssh_monitor_auth"
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

func NewAuthManager(config *Config) *AuthManager {
	am := &AuthManager{
		Keys: make(map[string]APIKey),
	}
	for _, k := range config.MasterKeys {
		am.Keys[k] = APIKey{Key: k, Type: KeyMaster, Enabled: true}
	}
	for _, k := range config.NormalKeys {
		am.Keys[k] = APIKey{Key: k, Type: KeyNormal, Enabled: true}
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

func (am *AuthManager) GetAuthFromRequest(r *http.Request) (APIKey, bool) {
	// 1. Check Cookie
	if cookie, err := r.Cookie(AuthCookieName); err == nil {
		if key, ok := am.Authenticate(cookie.Value); ok {
			return key, true
		}
	}

	// 2. Check Header
	key := r.Header.Get("X-API-Key")
	if key != "" {
		if apiKey, ok := am.Authenticate(key); ok {
			return apiKey, true
		}
	}

	// 3. Check Basic Auth
	if _, password, ok := r.BasicAuth(); ok {
		if apiKey, ok := am.Authenticate(password); ok {
			return apiKey, true
		}
	}

	return APIKey{}, false
}

func (am *AuthManager) SetAuthCookie(w http.ResponseWriter, key string) {
	http.SetCookie(w, &http.Cookie{
		Name:     AuthCookieName,
		Value:    key,
		Path:     "/",
		HttpOnly: true,
		// Secure:   true, // Should be true if using SSL, but we support both
		Expires: time.Now().Add(24 * time.Hour),
	})
}

func (am *AuthManager) ClearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     AuthCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

func (am *AuthManager) AddKey(key string, kType APIKeyType) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.Keys[key] = APIKey{Key: key, Type: kType, Enabled: true}
}

func (am *AuthManager) GetKeysByType(kType APIKeyType) []string {
	am.mu.RLock()
	defer am.mu.RUnlock()
	var keys []string
	for k, v := range am.Keys {
		if v.Type == kType {
			keys = append(keys, k)
		}
	}
	return keys
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
		apiKey, ok := am.GetAuthFromRequest(r)

		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized: Invalid or missing credentials", http.StatusUnauthorized)
			return
		}

		// If authenticated via Basic Auth (or any method really, but mainly Basic for browser), ensure cookie is set
		// We can just set it every time or check if it's missing.
		// For simplicity, let's set it if missing or different.
		currentCookie, err := r.Cookie(AuthCookieName)
		if err != nil || currentCookie.Value != apiKey.Key {
			am.SetAuthCookie(w, apiKey.Key)
		}

		if minType == KeyMaster && apiKey.Type != KeyMaster {
			http.Error(w, "Forbidden: Master key required", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}
