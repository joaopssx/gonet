package tcp

import (
	"encoding/binary"
	"net"

	"github.com/joaopssx/gonet/internal/ip"
)

// ChecksumCalculator helps compute and verify TCP checksums.
type ChecksumCalculator struct {
	src net.IP
	dst net.IP
}

// NewChecksumCalculator creates a new ChecksumCalculator.
func NewChecksumCalculator(src, dst net.IP) *ChecksumCalculator {
	return &ChecksumCalculator{
		src: src,
		dst: dst,
	}
}

// Compute calculates the TCP checksum including the IPv4 pseudo-header.
func (c *ChecksumCalculator) Compute(tcpSegment []byte) uint16 {
	return ip.TCPChecksum(c.src, c.dst, tcpSegment)
}

// Verify returns true if the checksum of the given TCP segment is correct.
func (c *ChecksumCalculator) Verify(tcpSegment []byte) bool {
	// If the checksum is correct, recomputing it with the checksum field
	// included in the segment will result in 0.
	return ip.TCPChecksum(c.src, c.dst, tcpSegment) == 0
}

// SetAndCompute zeroes the checksum field, calculates the new checksum,
// sets it in-place, and returns the modified segment.
func (c *ChecksumCalculator) SetAndCompute(tcpSegment []byte) []byte {
	if len(tcpSegment) < MinHeaderLen {
		return tcpSegment
	}

	// The Checksum field is at offset 16-17 in the TCP header
	tcpSegment[16] = 0
	tcpSegment[17] = 0

	chksum := c.Compute(tcpSegment)
	binary.BigEndian.PutUint16(tcpSegment[16:18], chksum)

	return tcpSegment
}
