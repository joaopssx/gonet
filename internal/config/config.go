package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration.
type Config struct {
	Mode       string `yaml:"mode" json:"mode"`
	DeviceName string `yaml:"device_name" json:"device_name"`
	DeviceIP   string `yaml:"device_ip" json:"device_ip"`
	PeerIP     string `yaml:"peer_ip" json:"peer_ip"`
	MTU        int    `yaml:"mtu" json:"mtu"`
	LogLevel   string `yaml:"log_level" json:"log_level"`
	LogPretty  bool   `yaml:"log_pretty" json:"log_pretty"`
	BufSize    int    `yaml:"buf_size" json:"buf_size"`
	Extensions struct {
		IPv6       bool `yaml:"ipv6" json:"ipv6"`
		MPTCP      bool `yaml:"mptcp" json:"mptcp"`
		ECN        bool `yaml:"ecn" json:"ecn"`
		Timestamps bool `yaml:"timestamps" json:"timestamps"`
	} `yaml:"extensions" json:"extensions"`
}

// Defaults returns a Config populated with sensible default values.
func Defaults() *Config {
	c := &Config{
		Mode:       "tun",
		DeviceName: "gonet0",
		MTU:        1500,
		LogLevel:   "info",
		LogPretty:  true,
		BufSize:    65535,
	}
	return c
}

// Load reads the configuration from a file (YAML or JSON).
func Load(path string) (*Config, error) {
	c := Defaults()
	if path == "" {
		return c, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, fmt.Errorf("config: read file: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".json" {
		if err := json.Unmarshal(data, c); err != nil {
			return nil, fmt.Errorf("config: parse JSON: %w", err)
		}
	} else if ext == ".yaml" || ext == ".yml" {
		if err := yaml.Unmarshal(data, c); err != nil {
			return nil, fmt.Errorf("config: parse YAML: %w", err)
		}
	} else {
		return nil, fmt.Errorf("config: unsupported file extension: %s", ext)
	}

	return c, nil
}

// Validate ensures that all configuration fields have valid values.
func (c *Config) Validate() error {
	if c.Mode != "tun" && c.Mode != "raw" {
		return fmt.Errorf("invalid mode: %s (must be 'tun' or 'raw')", c.Mode)
	}
	if c.MTU < 576 || c.MTU > 65535 {
		return fmt.Errorf("invalid MTU: %d (must be between 576 and 65535)", c.MTU)
	}
	if c.DeviceIP != "" && net.ParseIP(c.DeviceIP) == nil {
		return fmt.Errorf("invalid DeviceIP: %s", c.DeviceIP)
	}
	if c.PeerIP != "" && net.ParseIP(c.PeerIP) == nil {
		return fmt.Errorf("invalid PeerIP: %s", c.PeerIP)
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
		// valid
	default:
		return fmt.Errorf("invalid log level: %s", c.LogLevel)
	}
	if c.BufSize <= 0 {
		return fmt.Errorf("invalid buf_size: %d", c.BufSize)
	}

	return nil
}
