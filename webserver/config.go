package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
)

func getFilesHash(paths []string) (string, error) {
	hasher := sha256.New()
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				hasher.Write([]byte("notfound"))
				continue
			}
			return "", err
		}
		if _, err := io.Copy(hasher, file); err != nil {
			file.Close()
			return "", err
		}
		file.Close()
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

type HostConfig struct {
	Host     string `json:"host"`
	Interval string `json:"interval,omitempty"`
	Timeout  string `json:"timeout,omitempty"`
	Public   bool   `json:"public,omitempty"`
}

type Config struct {
	Port            string       `json:"port"`
	LogLevel        string       `json:"log_level"`
	LogComponents   []string     `json:"log_components"`
	LogColor        bool         `json:"log_color"`
	LogFormat       string       `json:"log_format"` // "text", "json", "color"
	DefaultInterval string       `json:"default_interval"`
	DefaultTimeout  string       `json:"default_timeout"`
	MasterKeys      []string     `json:"master_keys"`
	NormalKeys      []string     `json:"normal_keys"`
	PredefinedHosts []string     `json:"predefined_hosts"`
	Hosts           []HostConfig `json:"hosts"`
	IPWhitelist     []string     `json:"ip_whitelist"`
	SSLEnabled      bool         `json:"ssl_enabled"`
	CertPath        string       `json:"cert_path"`
	KeyPath         string       `json:"key_path"`
	SSLCertDomains  []string     `json:"ssl_cert_domains"`
}

func loadConfig(path string, config *Config) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	return json.NewDecoder(file).Decode(config)
}

func (c *Config) Save(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	return encoder.Encode(c)
}

func GetConfig() *Config {
	cfg := &Config{
		Port:            "8080",
		LogLevel:        "info",
		LogComponents:   []string{"requests", "response", "checks"},
		LogColor:        true,
		LogFormat:       "color",
		DefaultInterval: "10m",
		DefaultTimeout:  "5s",
		MasterKeys:      []string{"master-key-123"},
		SSLEnabled:      false,
		CertPath:        "server.crt",
		KeyPath:         "server.key",
		SSLCertDomains:  []string{"localhost"},
	}

	loadConfig("config.json", cfg)
	loadConfig("config-override.json", cfg)

	return cfg
}
