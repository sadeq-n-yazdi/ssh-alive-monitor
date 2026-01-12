package main

import (
	"encoding/json"
	"os"
)

type Config struct {
	Port            string   `json:"port"`
	LogLevel        string   `json:"log_level"`
	LogComponents   []string `json:"log_components"`
	LogColor        bool     `json:"log_color"`
	LogFormat       string   `json:"log_format"` // "text", "json", "color"
	DefaultInterval string   `json:"default_interval"`
	DefaultTimeout  string   `json:"default_timeout"`
	MasterKeys      []string `json:"master_keys"`
	PredefinedHosts []string `json:"predefined_hosts"`
	IPWhitelist     []string `json:"ip_whitelist"`
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
	}

	loadConfig("config.json", cfg)
	loadConfig("override.json", cfg)

	return cfg
}
