//go:build linux

package tun

import (
	"golang.org/x/sys/unix"
)

const (
	cTUNSETIFF    = unix.TUNSETIFF
	cSIOCGIFFLAGS = unix.SIOCGIFFLAGS
	cSIOCSIFFLAGS = unix.SIOCSIFFLAGS
	cSIOCSIFMTU   = unix.SIOCSIFMTU

	cIFF_TUN     = unix.IFF_TUN
	cIFF_NO_PI   = unix.IFF_NO_PI
	cIFF_UP      = unix.IFF_UP
	cIFF_RUNNING = unix.IFF_RUNNING
)

// ifreq represents the C struct ifreq used in ioctl calls.
// It is sized to accommodate the interface name and the union data.
type ifreq struct {
	Name [unix.IFNAMSIZ]byte
	Data [24]byte
}
