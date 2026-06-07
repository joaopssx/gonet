//go:build linux

package tun

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// ErrNotSupported is returned when an operation is not supported by the underlying implementation.
var ErrNotSupported = errors.New("operation not supported")

// PacketIO defines the standard interface for reading and writing raw IP packets.
type PacketIO interface {
	Read(buf []byte) (int, error)
	Write(buf []byte) (int, error)
	Close() error
	Name() string
}

// RawSocket provides a fallback mechanism using an AF_INET RAW socket with IP_HDRINCL.
//
// Limitation: While this allows sending fully crafted IP packets directly to the network,
// receiving IP packets indiscriminately is highly restricted. Sockets bound to IPPROTO_RAW
// generally only receive packets that the kernel does not process itself, or certain ICMP/IGMP
// packets. Therefore, receiving is not supported for full TCP/IP stack replacements.
type RawSocket struct {
	fd   int
	name string
}

// OpenRaw creates a new RawSocket bound to the given local IP address.
func OpenRaw(bindIP string) (*RawSocket, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("tun/raw: open socket: %w", err)
	}

	// IP_HDRINCL tells the kernel that we provide the IP header.
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("tun/raw: setsockopt IP_HDRINCL failed: %w", err)
	}

	ip := net.ParseIP(bindIP)
	if ip == nil {
		ip = net.IPv4zero
	}
	ip = ip.To4()
	if ip == nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("tun/raw: invalid IPv4 bind address: %s", bindIP)
	}

	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], ip)

	if err := syscall.Bind(fd, &sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("tun/raw: bind failed: %w", err)
	}

	return &RawSocket{
		fd:   fd,
		name: fmt.Sprintf("raw-%s", bindIP),
	}, nil
}

// Read always returns ErrNotSupported because receiving raw IP packets
// over an IPPROTO_RAW socket is fundamentally limited and unreliable for a userspace stack.
func (s *RawSocket) Read(buf []byte) (int, error) {
	return 0, fmt.Errorf("tun/raw: receive is fundamentally restricted on IPPROTO_RAW: %w", ErrNotSupported)
}

// Write sends a fully crafted IP packet over the raw socket.
// The destination IP is extracted directly from the provided IP header.
func (s *RawSocket) Write(buf []byte) (int, error) {
	if len(buf) < 20 {
		return 0, fmt.Errorf("tun/raw: packet too short to contain IPv4 header")
	}

	var dst syscall.SockaddrInet4
	// Destination IP in an IPv4 header is at offset 16 (4 bytes)
	copy(dst.Addr[:], buf[16:20])

	err := syscall.Sendto(s.fd, buf, 0, &dst)
	if err != nil {
		return 0, fmt.Errorf("tun/raw: sendto failed: %w", err)
	}
	return len(buf), nil
}

// Close closes the underlying raw socket file descriptor.
func (s *RawSocket) Close() error {
	return syscall.Close(s.fd)
}

// Name returns the identifier name for this raw socket.
func (s *RawSocket) Name() string {
	return s.name
}
