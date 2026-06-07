//go:build linux

package tun

import "fmt"

// Mode represents the type of PacketIO interface to create.
type Mode string

const (
	// ModeTUN represents a virtual TUN device.
	ModeTUN Mode = "tun"
	// ModeRaw represents an AF_INET IPPROTO_RAW socket fallback.
	ModeRaw Mode = "raw"
)

// Config specifies the parameters for opening a PacketIO interface.
type Config struct {
	Mode   Mode
	Name   string // Name for the TUN interface (e.g., "tun0")
	MTU    int    // MTU for the TUN interface
	BindIP string // Local IP to bind for the Raw Socket mode
}

// Open creates a new PacketIO interface (TUN or Raw Socket) based on the configuration.
func Open(cfg Config) (PacketIO, error) {
	switch cfg.Mode {
	case ModeTUN:
		return OpenTUN(cfg.Name, cfg.MTU)
	case ModeRaw:
		return OpenRaw(cfg.BindIP)
	default:
		return nil, fmt.Errorf("tun: unknown mode: %s", cfg.Mode)
	}
}
