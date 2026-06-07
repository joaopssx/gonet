package config

import (
	"testing"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: &Config{
				Mode:     "tun",
				DeviceIP: "10.0.0.1",
				PeerIP:   "10.0.0.2",
				MTU:      1500,
				LogLevel: "info",
				BufSize:  65535,
			},
			wantErr: false,
		},
		{
			name: "invalid mode",
			cfg: &Config{
				Mode:     "invalid",
				MTU:      1500,
				LogLevel: "info",
				BufSize:  65535,
			},
			wantErr: true,
		},
		{
			name: "mtu too small",
			cfg: &Config{
				Mode:     "tun",
				MTU:      100,
				LogLevel: "info",
				BufSize:  65535,
			},
			wantErr: true,
		},
		{
			name: "mtu too big",
			cfg: &Config{
				Mode:     "tun",
				MTU:      100000,
				LogLevel: "info",
				BufSize:  65535,
			},
			wantErr: true,
		},
		{
			name: "invalid device ip",
			cfg: &Config{
				Mode:     "tun",
				MTU:      1500,
				DeviceIP: "not_an_ip",
				LogLevel: "info",
				BufSize:  65535,
			},
			wantErr: true,
		},
		{
			name: "invalid log level",
			cfg: &Config{
				Mode:     "tun",
				MTU:      1500,
				LogLevel: "foo",
				BufSize:  65535,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := Defaults()
	if err := cfg.Validate(); err != nil {
		t.Errorf("Defaults() validation failed: %v", err)
	}

	if cfg.Mode != "tun" {
		t.Errorf("Defaults() mode = %v, want 'tun'", cfg.Mode)
	}
	if cfg.MTU != 1500 {
		t.Errorf("Defaults() mtu = %v, want 1500", cfg.MTU)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("Defaults() loglevel = %v, want 'info'", cfg.LogLevel)
	}
}
