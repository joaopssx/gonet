//go:build linux

package tun

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Interface represents a TUN device in the Linux kernel.
type Interface struct {
	fd   int
	name string
	mtu  int
}

// OpenTUN creates or opens a TUN device.
func OpenTUN(name string, mtu int) (*Interface, error) {
	// Open the TUN/TAP device file
	fd, err := syscall.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("tun: open %s: /dev/net/tun does not exist (kernel missing tun module?): %w", name, err)
		}
		if os.IsPermission(err) {
			return nil, fmt.Errorf("tun: open %s: permission denied (are you running as root or with CAP_NET_ADMIN?): %w", name, err)
		}
		return nil, fmt.Errorf("tun: open %s: %w", name, err)
	}

	var ifr ifreq
	copy(ifr.Name[:], name)

	// Set IFF_TUN (TUN device) and IFF_NO_PI (no packet info prefix, raw IP packets)
	*(*uint16)(unsafe.Pointer(&ifr.Data[0])) = cIFF_TUN | cIFF_NO_PI

	// Execute TUNSETIFF to initialize the device
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(cTUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("tun: open %s: ioctl TUNSETIFF failed: %w", name, errno)
	}

	// Retrieve the actual name assigned by the kernel (useful if we passed "")
	actualName := string(bytes.TrimRight(ifr.Name[:], "\x00"))

	// We need a standard AF_INET socket to perform interface-level ioctls like MTU and FLAGS
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("tun: open %s: failed to create datagram socket: %w", actualName, err)
	}
	defer syscall.Close(sock)

	// Configure MTU
	var ifrMtu ifreq
	copy(ifrMtu.Name[:], actualName)
	*(*int32)(unsafe.Pointer(&ifrMtu.Data[0])) = int32(mtu)

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), uintptr(cSIOCSIFMTU), uintptr(unsafe.Pointer(&ifrMtu)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("tun: open %s: ioctl SIOCSIFMTU failed: %w", actualName, errno)
	}

	// Bring the interface UP
	var ifrFlags ifreq
	copy(ifrFlags.Name[:], actualName)

	// Retrieve current flags first
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), uintptr(cSIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifrFlags)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("tun: open %s: ioctl SIOCGIFFLAGS failed: %w", actualName, errno)
	}

	// Add IFF_UP and IFF_RUNNING flags
	flags := *(*uint16)(unsafe.Pointer(&ifrFlags.Data[0]))
	flags |= cIFF_UP | cIFF_RUNNING
	*(*uint16)(unsafe.Pointer(&ifrFlags.Data[0])) = flags

	// Apply new flags
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(sock), uintptr(cSIOCSIFFLAGS), uintptr(unsafe.Pointer(&ifrFlags)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("tun: open %s: ioctl SIOCSIFFLAGS failed: %w", actualName, errno)
	}

	return &Interface{
		fd:   fd,
		name: actualName,
		mtu:  mtu,
	}, nil
}

// Read reads a raw IP packet from the TUN device.
func (i *Interface) Read(buf []byte) (int, error) {
	n, err := syscall.Read(i.fd, buf)
	if err != nil {
		return 0, fmt.Errorf("tun: read %s: %w", i.name, err)
	}
	return n, nil
}

// Write writes a raw IP packet to the TUN device.
func (i *Interface) Write(buf []byte) (int, error) {
	n, err := syscall.Write(i.fd, buf)
	if err != nil {
		return 0, fmt.Errorf("tun: write %s: %w", i.name, err)
	}
	return n, nil
}

// Close closes the file descriptor associated with the TUN device.
func (i *Interface) Close() error {
	err := syscall.Close(i.fd)
	if err != nil {
		return fmt.Errorf("tun: close %s: %w", i.name, err)
	}
	return nil
}

// Name returns the actual interface name as reported by the kernel.
func (i *Interface) Name() string {
	return i.name
}

// MTU returns the interface's configured MTU.
func (i *Interface) MTU() int {
	return i.mtu
}
